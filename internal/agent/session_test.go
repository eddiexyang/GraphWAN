package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/mesh"
	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/routing"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

// pacedRead reads all of r in 64-KiB steps, at most rate bytes per second, so
// a transfer lasts while the test changes the graph.
func pacedRead(r io.Reader, rate int) ([]byte, error) {
	var out bytes.Buffer
	buf := make([]byte, 64<<10)
	start := time.Now()
	for {
		n, err := r.Read(buf)
		out.Write(buf[:n])
		if err == io.EOF {
			return out.Bytes(), nil
		}
		if err != nil {
			return out.Bytes(), err
		}
		if ahead := time.Duration(out.Len())*time.Second/time.Duration(rate) - time.Since(start); ahead > 0 {
			time.Sleep(ahead)
		}
	}
}

// sessionExchange sends size bytes each way between A (device 0) and the node
// at index target, both read at rate, and calls during once they are flowing.
func sessionExchange(t *testing.T, devices []*kernelTUN, state model.State, target, size, rate int, during func()) {
	t.Helper()
	address := state.Networks[0].Nodes[target].Address
	listener, err := gonet.ListenTCP(devices[target].stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(address.As4()), Port: 8090}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	request, response := make([]byte, size), make([]byte, size)
	rand.Read(request)
	rand.Read(response)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(60 * time.Second))
		if conn.RemoteAddr().(*net.TCPAddr).AddrPort().Addr() != state.Networks[0].Nodes[0].Address {
			serverErr <- errors.New("source address changed")
			return
		}
		written := make(chan error, 1)
		go func() {
			_, err := conn.Write(response)
			if err == nil {
				err = conn.(*gonet.TCPConn).CloseWrite()
			}
			written <- err
		}()
		raw, err := pacedRead(conn, rate)
		if err == nil && !bytes.Equal(raw, request) {
			err = errors.New("request bytes changed")
		}
		serverErr <- errors.Join(err, <-written)
	}()
	conn, err := gonet.DialContextTCP(ctx, devices[0].stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(address.As4()), Port: 8090}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(60 * time.Second))
	clientErr := make(chan error, 1)
	go func() {
		_, err := conn.Write(request)
		if err == nil {
			err = conn.CloseWrite()
		}
		clientErr <- err
	}()
	got := make(chan error, 1)
	go func() {
		raw, err := pacedRead(conn, rate)
		if err == nil && !bytes.Equal(raw, response) {
			err = errors.New("response bytes changed")
		}
		got <- err
	}()
	time.Sleep(200 * time.Millisecond)
	if during != nil {
		during()
	}
	for _, c := range []chan error{clientErr, got, serverErr} {
		if err := <-c; err != nil {
			t.Fatal(err)
		}
	}
}

func applyAll(t *testing.T, agents []*DataPlane, state model.State) {
	t.Helper()
	for i, agent := range agents {
		if agent == nil {
			continue
		}
		snapshot, err := routing.Compile(state, state.Agents[i].ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := agent.Apply(context.Background(), snapshot); err != nil {
			t.Fatal(err)
		}
	}
}

func relaying(agent *DataPlane) int {
	agent.sessions.mu.Lock()
	defer agent.sessions.mu.Unlock()
	return len(agent.sessions.relays)
}

// A weight change moves an established connection to the new path while both
// directions are busy; nothing is reset or lost.
func TestTCPSessionFollowsRouteChange(t *testing.T) {
	agents, devices, state := graphAgents(t, model.TCP, streamOptions{}, 4, 4)
	sessionExchange(t, devices, state, 2, 12<<20, 4<<20, func() {
		waitFor(t, 5*time.Second, "a session through B", func() bool { return relaying(agents[1]) > 0 })
		state.Revision++
		state.Networks[0].Edges[0].Weight = 100 // A-B-C now costs 110, A-D-C 31
		applyAll(t, agents, state)
		waitFor(t, 10*time.Second, "the session to move to D", func() bool { return relaying(agents[3]) > 0 && relaying(agents[1]) == 0 })
	})
}

// A relay that fails mid-transfer loses what it buffered; the connection
// continues on the next path from the delivered offsets.
func TestTCPSessionSurvivesRelayFailure(t *testing.T) {
	agents, devices, state := graphAgents(t, model.TCP, streamOptions{}, 4, 4)
	sessionExchange(t, devices, state, 2, 24<<20, 2<<20, func() {
		waitFor(t, 5*time.Second, "a session through B", func() bool { return relaying(agents[1]) > 0 })
		agents[1].Close()
		waitFor(t, 30*time.Second, "the session to move to D", func() bool { return relaying(agents[3]) > 0 })
	})
}

// Without any path a connection waits, as IP does, instead of being reset.
// It resumes when the path returns and never uses a revoked Edge.
func TestTCPRevokedEdgeStallsAndResumes(t *testing.T) {
	agents, devices, state := streamAgents(t, model.TCP)
	target := state.Networks[0].Nodes[2].Address
	listener, err := gonet.ListenTCP(devices[2].stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(target.As4()), Port: 8082}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() { conn, _ := listener.Accept(); accepted <- conn }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, devices[0].stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(target.As4()), Port: 8082}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	server := <-accepted
	if server == nil {
		t.Fatal("target not connected")
	}
	defer server.Close()
	revoke := func(enabled bool) {
		state.Revision++
		state.Networks[0].Edges[0].Enabled = enabled
		snapshot, err := routing.Compile(state, state.Agents[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := agents[0].Apply(ctx, snapshot); err != nil {
			t.Fatal(err)
		}
	}
	revoke(false)
	if _, err := server.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("bytes crossed a revoked Edge")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("connection without a path was not kept: %v", err)
	}
	revoke(true)
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil || buf[0] != 'x' {
		t.Fatalf("connection did not resume: %q, %v", buf, err)
	}
}

// Hops toward an Agent without TCP sessions keep plain streams.
func TestTCPSessionMixedVersions(t *testing.T) {
	for name, legacy := range map[string]int{"first hop": 1, "egress": 2} {
		t.Run(name, func(t *testing.T) {
			agents, devices, state := graphAgentsLegacy(t, legacy)
			sessionExchange(t, devices, state, 2, 2<<20, 1<<20, func() {
				agents[0].sessions.mu.Lock()
				defer agents[0].sessions.mu.Unlock()
				if len(agents[0].sessions.ingress) != 0 {
					t.Error("a session crossed an Agent without sessions")
				}
			})
		})
	}
}

func graphAgentsLegacy(t *testing.T, legacy int) ([]*DataPlane, []*kernelTUN, model.State) {
	return graphAgents(t, model.TCP, streamOptions{legacy: map[int]bool{legacy: true}}, 3, 2)
}

// Edges whose Links carry no streams, such as UDP and QUIC, carry sessions on
// carriers; transit TCP never reaches a TUN.
func TestTCPSessionsOnCarriers(t *testing.T) {
	for _, transport := range []model.Transport{model.UDP, model.QUIC} {
		t.Run(string(transport), func(t *testing.T) {
			agents, devices, state := graphAgents(t, transport, streamOptions{}, 3, 2)
			sessionExchange(t, devices, state, 2, 4<<20, 8<<20, func() {
				if relaying(agents[1]) == 0 {
					t.Error("no session crossed the carrier Edges")
				}
			})
			if devices[1].writes.Load() != 0 {
				t.Fatal("transit TCP reached a TUN")
			}
		})
	}
}

// A session moves between a TCP Link's streams and a UDP Link's carrier on the
// same Edge as Links come and go.
func TestTCPSessionMovesBetweenStreamsAndCarrier(t *testing.T) {
	agents, devices, state := graphAgents(t, model.TCP, streamOptions{}, 3, 2, func(s *model.State) {
		for i := range s.Agents {
			endpoint := s.Agents[i].Endpoints[0]
			endpoint.ID, endpoint.Transport = testutil.ID(60+i), model.UDP
			endpoint.URL = strings.Replace(endpoint.URL, "tcp://", "udp://", 1)
			s.Agents[i].Endpoints = append(s.Agents[i].Endpoints, endpoint)
		}
		for i := range s.Networks[0].Edges {
			s.Networks[0].Edges[i].Transports = []model.Transport{model.TCP, model.UDP}
		}
	})
	sessionExchange(t, devices, state, 2, 12<<20, 4<<20, func() {
		waitFor(t, 5*time.Second, "a session through B", func() bool { return relaying(agents[1]) > 0 })
		state.Revision++
		for i := range state.Networks[0].Edges {
			state.Networks[0].Edges[i].Transports = []model.Transport{model.UDP}
		}
		applyAll(t, agents, state)
		waitFor(t, 15*time.Second, "the session on a carrier", func() bool {
			agents[0].sessions.mu.Lock()
			defer agents[0].sessions.mu.Unlock()
			for s := range agents[0].sessions.ingress {
				if _, hop, ok := s.session.Next(); ok && mesh.IsCarrier(hop) {
					return true
				}
			}
			return false
		})
	})
}
