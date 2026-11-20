package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
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

	"github.com/eddiexyang/graphnet/internal/agent"
	"github.com/eddiexyang/graphnet/internal/control"
	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/pki"
	"github.com/eddiexyang/graphnet/internal/routing"
	"github.com/eddiexyang/graphnet/internal/store"
	"github.com/eddiexyang/graphnet/internal/testutil"
	"github.com/eddiexyang/graphnet/internal/tunnel"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// clientNetwork runs Agents A, B and C with user-space stacks in place of TUN
// interfaces, and a controller that knows client node D by initialKey.
type clientNetwork struct {
	state    model.State
	stacks   []*netstack
	runtimes []*agent.DataPlane
	db       *store.Store
	ca       *pki.Authority
	port     string
}

func startClientNetwork(t *testing.T, ctx context.Context, clientKey ed25519.PrivateKey, initialKey ed25519.PublicKey, carrier model.Transport) *clientNetwork {
	t.Helper()
	state := testutil.Topology()
	state.Agents = state.Agents[:4]
	n := &state.Networks[0]
	n.Nodes = n.Nodes[:4]
	n.Nodes[3].Client = true
	state.Agents[3].PublicKey = clientKey.Public().(ed25519.PublicKey)
	state.Agents[3].Endpoints = []model.Endpoint{}
	for i := range 3 {
		socket, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := uint16(socket.Addr().(*net.TCPAddr).Port)
		socket.Close()
		state.Agents[i].ListenPort = port
		state.Agents[i].Endpoints = []model.Endpoint{{ID: testutil.ID(30 + i), Transport: carrier, Source: model.Manual, URL: fmt.Sprintf("%s://127.0.0.1:%d", carrier, port)}}
	}
	for i := range n.Edges {
		n.Edges[i].Transports = []model.Transport{carrier}
	}
	if err := state.Validate(); err != nil {
		t.Fatal(err)
	}
	cn := &clientNetwork{state: state, stacks: make([]*netstack, 3)}
	for i := range 3 {
		seed := make([]byte, ed25519.SeedSize)
		seed[0] = byte(i + 1)
		runtime, err := agent.NewDataPlane(ctx, ed25519.NewKeyFromSeed(seed), agent.DataPlaneOptions{BindHost: "127.0.0.1", TunnelFactory: func(cfg tunnel.Config) (tunnel.Device, error) {
			s, err := newNetstack(cfg)
			cn.stacks[i] = s
			return s, err
		}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { runtime.Close() })
		cn.runtimes = append(cn.runtimes, runtime)
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
	t.Cleanup(func() { db.Close() })
	cn.db = db
	initial := state
	initial.Agents = append([]model.Agent(nil), state.Agents...)
	initial.Agents[3].PublicKey = initialKey
	current, _ := db.Read()
	if _, err := db.Update(current.Revision, func(s *model.State) error { *s = initial; return nil }); err != nil {
		t.Fatal(err)
	}
	server, err := control.New(db, control.Options{Password: "test-password-123"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	if cn.ca, err = pki.LoadOrCreate(db); err != nil {
		t.Fatal(err)
	}
	listener := httptest.NewUnstartedServer(server)
	if listener.TLS, err = cn.ca.ServerTLS([]string{"controller.graphnet.test"}); err != nil {
		t.Fatal(err)
	}
	listener.StartTLS()
	t.Cleanup(listener.Close)
	_, cn.port, _ = net.SplitHostPort(listener.Listener.Addr().String())
	return cn
}

// update changes the state on the controller, which the client follows, and
// on Agents A, B and C.
func (cn *clientNetwork) update(t *testing.T, ctx context.Context, change func(*model.State)) {
	t.Helper()
	change(&cn.state)
	cn.state.Revision++
	current, _ := cn.db.Read()
	if _, err := cn.db.Update(current.Revision, func(s *model.State) error { change(s); return nil }); err != nil {
		t.Fatal(err)
	}
	for i, runtime := range cn.runtimes {
		snapshot, err := routing.Compile(cn.state, cn.state.Agents[i].ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := runtime.Apply(ctx, snapshot); err != nil {
			t.Fatal(err)
		}
	}
}

func (cn *clientNetwork) serveEcho(t *testing.T, node int, port uint16) {
	t.Helper()
	s := cn.stacks[node]
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

// D is a client node attached to A and C, registered by public key: it gets
// its configuration from a real controller and reaches services on B and C.
func TestClientReachesServicesThroughTheNetwork(t *testing.T) {
	for _, carrier := range []model.Transport{model.TCP, model.UDP} {
		t.Run(string(carrier), func(t *testing.T) { testClientReachesServices(t, carrier) })
	}
}

func testClientReachesServices(t *testing.T, carrier model.Transport) {
	_, clientKey, _ := ed25519.GenerateKey(rand.Reader)
	// The controller first knows another key for D, so the client's first
	// registration fails; it must recover once the right key is registered.
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cn := startClientNetwork(t, ctx, clientKey, otherKey.Public().(ed25519.PublicKey), carrier)
	state, stacks, db, ca, port := cn.state, cn.stacks, cn.db, cn.ca, cn.port
	n := &state.Networks[0]

	var controls, lookups atomic.Int64
	c, err := Start(ctx, Config{
		Server:     "https://controller.graphnet.test:" + port,
		CA:         ca.PEM,
		PrivateKey: clientKey,
		Control: func(string, string, syscall.RawConn) error {
			controls.Add(1)
			return nil
		},
		Lookup: func(_ context.Context, _, host string) ([]netip.Addr, error) {
			lookups.Add(1)
			if host != "controller.graphnet.test" {
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
	current, _ := db.Read()
	if _, err := db.Update(current.Revision, func(s *model.State) error { s.Agents[3].PublicKey = state.Agents[3].PublicKey; return nil }); err != nil {
		t.Fatal(err)
	}

	cn.serveEcho(t, 1, 7) // B, two hops from D
	cn.serveEcho(t, 2, 7) // C, a direct neighbor
	payload := bytes.Repeat([]byte("through the GraphNet client\n"), 4096)
	for _, target := range []int{1, 2} {
		dialCtx, stop := context.WithTimeout(ctx, 20*time.Second)
		conn, err := c.DialTCP(dialCtx, netip.AddrPortFrom(n.Nodes[target].Address, 7))
		stop()
		if err != nil {
			t.Fatalf("dial node %d: %v", target, err)
		}
		if _, packetTCP := conn.(*gonet.TCPConn); packetTCP != (carrier == model.UDP) {
			t.Fatalf("dial node %d on %s returned %T", target, carrier, conn)
		}
		if err := conn.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		var timeout net.Error
		if _, err := conn.Read(make([]byte, 1)); !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("read deadline: %v", err)
		}
		conn.SetDeadline(time.Now().Add(20 * time.Second))
		done := make(chan error, 1)
		go func() {
			_, err := conn.Write(payload)
			if err == nil {
				err = conn.(interface{ CloseWrite() error }).CloseWrite()
			}
			done <- err
		}()
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("echo from node %d: %v", target, err)
		}
		if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("echo from node %d did not half-close: %v", target, err)
		}
		if err := <-done; err != nil {
			t.Fatalf("send to node %d: %v", target, err)
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

// The client's connection is a session: it follows a route change mid-transfer
// without being reset, and no TCP Link carries its TCP as packets.
func TestClientConnectionFollowsRouteChange(t *testing.T) {
	_, clientKey, _ := ed25519.GenerateKey(rand.Reader)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cn := startClientNetwork(t, ctx, clientKey, clientKey.Public().(ed25519.PublicKey), model.TCP)
	c, err := Start(ctx, Config{
		Server:     "https://controller.graphnet.test:" + cn.port,
		CA:         cn.ca.PEM,
		PrivateKey: clientKey,
		Lookup: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cn.serveEcho(t, 2, 7)
	dialCtx, stop := context.WithTimeout(ctx, 20*time.Second)
	conn, err := c.DialTCP(dialCtx, netip.AddrPortFrom(cn.state.Networks[0].Nodes[2].Address, 7))
	stop()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(60 * time.Second))
	payload := make([]byte, 16<<20) // 8 s at 2 MiB/s, so the route changes mid-transfer
	rand.Read(payload)
	go func() {
		start := time.Now()
		for sent := 0; sent < len(payload); sent += 64 << 10 {
			conn.Write(payload[sent : sent+64<<10])
			if ahead := time.Duration(sent)*time.Second/(2<<20) - time.Since(start); ahead > 0 {
				time.Sleep(ahead)
			}
		}
	}()
	got := make(chan error, 1)
	go func() {
		echo := make([]byte, len(payload))
		_, err := io.ReadFull(conn, echo)
		if err == nil && !bytes.Equal(echo, payload) {
			err = fmt.Errorf("echo changed")
		}
		got <- err
	}()
	time.Sleep(time.Second)
	// D reaches C through A and B (21) until A-D costs 100; then directly (30).
	cn.update(t, ctx, func(s *model.State) { s.Networks[0].Edges[2].Weight = 100 })
	for deadline := time.Now().Add(5 * time.Second); c.runtime.Counters()["session_rebuilds"] == 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the client's connection did not move as a session")
		}
	}
	if err := <-got; err != nil {
		t.Fatal(err)
	}
	for _, runtime := range append(cn.runtimes, c.runtime) {
		for _, l := range runtime.Report() {
			if l.TCPPackets != 0 {
				t.Fatalf("%d TCP packets on %s Link %s", l.TCPPackets, l.Transport, l.LinkID)
			}
		}
	}
}
