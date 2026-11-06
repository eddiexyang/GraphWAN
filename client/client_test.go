package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/agent"
	"github.com/eWloYW8/GraphWAN/internal/control"
	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/pki"
	"github.com/eWloYW8/GraphWAN/internal/routing"
	"github.com/eWloYW8/GraphWAN/internal/store"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
	"github.com/eWloYW8/GraphWAN/internal/tunnel"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// Agents A, B and C run with user-space stacks in place of TUN interfaces.
// D is a client node attached to A and C, registered by public key: it gets
// its configuration from a real controller and reaches services on B and C.
func TestClientReachesServicesThroughTheNetwork(t *testing.T) {
	state := testutil.Topology()
	state.Agents = state.Agents[:4]
	n := &state.Networks[0]
	n.Nodes = n.Nodes[:4]
	n.Nodes[3].Client = true
	_, clientKey, _ := ed25519.GenerateKey(rand.Reader)
	state.Agents[3].PublicKey = clientKey.Public().(ed25519.PublicKey)
	state.Agents[3].Endpoints = []model.Endpoint{}
	for i := range 3 {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := uint16(listener.Addr().(*net.TCPAddr).Port)
		listener.Close()
		state.Agents[i].ListenPort = port
		state.Agents[i].Endpoints = []model.Endpoint{{ID: testutil.ID(30 + i), Transport: model.TCP, Source: model.Manual, URL: fmt.Sprintf("tcp://127.0.0.1:%d", port)}}
	}
	for i := range n.Edges {
		n.Edges[i].Transports = []model.Transport{model.TCP}
	}
	if err := state.Validate(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stacks := make([]*netstack, 3)
	for i := range 3 {
		seed := make([]byte, ed25519.SeedSize)
		seed[0] = byte(i + 1)
		runtime, err := agent.NewDataPlane(ctx, ed25519.NewKeyFromSeed(seed), agent.DataPlaneOptions{BindHost: "127.0.0.1", TunnelFactory: func(cfg tunnel.Config) (tunnel.Device, error) {
			s, err := newNetstack(cfg)
			stacks[i] = s
			return s, err
		}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { runtime.Close() })
		snapshot, err := routing.Compile(state, state.Agents[i].ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := runtime.Apply(ctx, snapshot); err != nil {
			t.Fatal(err)
		}
	}

	db, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// The controller first knows another key for D, so the client's first
	// registration fails; it must recover once the right key is registered.
	initial := state
	initial.Agents = append([]model.Agent(nil), state.Agents...)
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	initial.Agents[3].PublicKey = otherKey.Public().(ed25519.PublicKey)
	current, _ := db.Read()
	if _, err := db.Update(current.Revision, func(s *model.State) error { *s = initial; return nil }); err != nil {
		t.Fatal(err)
	}
	server, err := control.New(db, control.Options{Password: "test-password-123"})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ca, err := pki.LoadOrCreate(db)
	if err != nil {
		t.Fatal(err)
	}
	listener := httptest.NewUnstartedServer(server)
	if listener.TLS, err = ca.ServerTLS([]string{"controller.graphwan.test"}); err != nil {
		t.Fatal(err)
	}
	listener.StartTLS()
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Listener.Addr().String())

	var controls, lookups atomic.Int64
	c, err := Start(ctx, Config{
		Server:     "https://controller.graphwan.test:" + port,
		CA:         ca.PEM,
		PrivateKey: clientKey,
		Control: func(string, string, syscall.RawConn) error {
			controls.Add(1)
			return nil
		},
		Lookup: func(_ context.Context, _, host string) ([]netip.Addr, error) {
			lookups.Add(1)
			if host != "controller.graphwan.test" {
				return nil, fmt.Errorf("unexpected lookup %s", host)
			}
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	time.Sleep(500 * time.Millisecond)
	current, _ = db.Read()
	if _, err := db.Update(current.Revision, func(s *model.State) error { s.Agents[3].PublicKey = state.Agents[3].PublicKey; return nil }); err != nil {
		t.Fatal(err)
	}

	serve := func(s *netstack, port uint16) {
		l, err := gonet.ListenTCP(s.stack, fullAddress(netip.AddrPortFrom(s.address(), port)), s.protocol())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		go func() {
			for {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				go func() { defer conn.Close(); io.Copy(conn, conn) }()
			}
		}()
	}
	serve(stacks[1], 7) // B, two hops from D
	serve(stacks[2], 7) // C, a direct neighbor
	payload := bytes.Repeat([]byte("through the GraphWAN client\n"), 4096)
	for _, target := range []int{1, 2} {
		dialCtx, stop := context.WithTimeout(ctx, 20*time.Second)
		conn, err := c.DialTCP(dialCtx, netip.AddrPortFrom(n.Nodes[target].Address, 7))
		stop()
		if err != nil {
			t.Fatalf("dial node %d: %v", target, err)
		}
		conn.SetDeadline(time.Now().Add(20 * time.Second))
		go conn.Write(payload)
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("echo from node %d: %v", target, err)
		}
		conn.Close()
	}

	// UDP round trip to C.
	udp, err := gonet.DialUDP(stacks[2].stack, ptr(fullAddress(netip.AddrPortFrom(stacks[2].address(), 53))), nil, stacks[2].protocol())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			udp.WriteTo(buf[:n], from)
		}
	}()
	pc, err := c.ListenUDP(ctx, n.Nodes[2].Address)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	// UDP may be lost while Links converge; retry as a DNS client would.
	target := net.UDPAddrFromAddrPort(netip.AddrPortFrom(n.Nodes[2].Address, 53))
	buf := make([]byte, 64)
	echoed := false
	for attempt := 0; attempt < 50 && !echoed; attempt++ {
		if _, err := pc.WriteTo([]byte("ping"), target); err != nil {
			t.Fatal(err)
		}
		pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		got, _, err := pc.ReadFrom(buf)
		echoed = err == nil && string(buf[:got]) == "ping"
	}
	if !echoed {
		t.Fatal("no UDP echo through the network")
	}

	if _, err := c.DialTCP(ctx, netip.MustParseAddrPort("10.43.0.1:7")); err == nil {
		t.Fatal("dial outside the network succeeded")
	}
	if controls.Load() == 0 || lookups.Load() == 0 {
		t.Fatalf("socket hooks unused: %d controls, %d lookups", controls.Load(), lookups.Load())
	}
}

func ptr[T any](v T) *T { return &v }
