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

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/routing"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

func ingressCount(agent *DataPlane) int {
	agent.sessions.mu.Lock()
	defer agent.sessions.mu.Unlock()
	return len(agent.sessions.ingress)
}

func relaying(agent *DataPlane) int {
	agent.sessions.mu.Lock()
	defer agent.sessions.mu.Unlock()
	return len(agent.sessions.relays)
}

// pacedWrite and pacedRead move p in 64-KiB steps at most rate bytes per
// second, so a transfer lasts while the test changes the graph.
func pacedWrite(w io.Writer, p []byte, rate int) error {
	start := time.Now()
	for sent := 0; sent < len(p); {
		n := min(64<<10, len(p)-sent)
		if _, err := w.Write(p[sent : sent+n]); err != nil {
			return err
		}
		sent += n
		if ahead := time.Duration(sent)*time.Second/time.Duration(rate) - time.Since(start); ahead > 0 {
			time.Sleep(ahead)
		}
	}
	return nil
}

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
// at index target at rate, and calls during once they are flowing.
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
		written := make(chan error, 1)
		go func() {
			err := pacedWrite(conn, response, rate)
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
		err := pacedWrite(conn, request, rate)
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

// A connection over TCP Links between current Agents is a session.
func TestTCPConnectionIsSession(t *testing.T) {
	agents, devices, state := graphAgents(t, model.TCP, streamOptions{}, 3, 2)
	sessionExchange(t, devices, state, 2, 1<<20, 4<<20, func() {
		if ingressCount(agents[0]) != 1 || relaying(agents[1]) != 1 {
			t.Errorf("ingress sessions %d, relayed chains %d", ingressCount(agents[0]), relaying(agents[1]))
		}
	})
	assertNoTCPOverTCP(t, agents)
}

// A weight change moves an established connection to the new path while both
// directions are busy; nothing is reset or lost.
func TestTCPSessionFollowsRouteChange(t *testing.T) {
	agents, devices, state := graphAgents(t, model.TCP, streamOptions{}, 4, 4)
	sessionExchange(t, devices, state, 2, 12<<20, 4<<20, func() {
		waitFor(t, 5*time.Second, "a chain through B", func() bool { return relaying(agents[1]) > 0 })
		state.Revision++
		state.Networks[0].Edges[0].Weight = 100 // A-B-C now costs 110, A-D-C 31
		applyAll(t, agents, state)
		waitFor(t, 10*time.Second, "the chain to move to D", func() bool { return relaying(agents[3]) > 0 && relaying(agents[1]) == 0 })
	})
	assertNoTCPOverTCP(t, agents)
	if agents[0].Counters()["session_rebuilds"] == 0 {
		t.Fatal("no rebuild counted")
	}
	waitFor(t, 5*time.Second, "ended sessions to release what they kept", func() bool {
		for _, agent := range agents {
			if agent.Counters()["session_retained_bytes"] != 0 {
				return false
			}
		}
		return true
	})
}

// A relay that fails mid-transfer loses what it buffered; the ingress
// rebuilds on the next path from what the egress delivered.
func TestTCPSessionSurvivesRelayFailure(t *testing.T) {
	agents, devices, state := graphAgents(t, model.TCP, streamOptions{}, 4, 4)
	sessionExchange(t, devices, state, 2, 24<<20, 2<<20, func() {
		waitFor(t, 5*time.Second, "a chain through B", func() bool { return relaying(agents[1]) > 0 })
		agents[1].Close()
		waitFor(t, 30*time.Second, "the chain to move to D", func() bool { return relaying(agents[3]) > 0 })
	})
	assertNoTCPOverTCP(t, []*DataPlane{agents[0], agents[2], agents[3]})
}

// The only path's Links fail and come back while the connection is busy; it
// waits and continues on the new Links.
func TestTCPSessionSurvivesLinkFlap(t *testing.T) {
	agents, devices, state := graphAgents(t, model.TCP, streamOptions{}, 3, 2)
	sessionExchange(t, devices, state, 2, 8<<20, 2<<20, func() {
		waitFor(t, 5*time.Second, "a chain through B", func() bool { return relaying(agents[1]) > 0 })
		for _, enabled := range []bool{false, true} {
			state.Revision++
			state.Networks[0].Edges[0].Enabled = enabled
			applyAll(t, agents, state)
			time.Sleep(500 * time.Millisecond)
		}
		waitFor(t, 20*time.Second, "the chain back through B", func() bool { return relaying(agents[1]) > 0 })
	})
	assertNoTCPOverTCP(t, agents)
}

// Toward an Agent without sessions, as the first hop or the egress, the
// connection uses a plain stream.
func TestTCPSessionMixedVersions(t *testing.T) {
	for name, legacy := range map[string]int{"first hop": 1, "egress": 2} {
		t.Run(name, func(t *testing.T) {
			agents, devices, state := graphAgents(t, model.TCP, streamOptions{legacy: map[int]bool{legacy: true}}, 3, 2)
			sessionExchange(t, devices, state, 2, 2<<20, 4<<20, func() {
				if ingressCount(agents[0]) != 0 {
					t.Error("a session crossed an Agent without sessions")
				}
			})
			assertNoTCPOverTCP(t, agents)
		})
	}
}

// A FIN or reset that arrives while the session moves to a new path still
// reaches the other end exactly as sent.
func TestTCPSessionEndsDuringReroute(t *testing.T) {
	agents, devices, state := graphAgents(t, model.TCP, streamOptions{}, 4, 4)
	address := state.Networks[0].Nodes[2].Address
	listener, err := gonet.ListenTCP(devices[2].stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(address.As4()), Port: 8091}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ends := make(chan error, 16)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				// Unread, the greeting makes the client's close a reset.
				_, err := conn.Write([]byte("hi"))
				var raw []byte
				if err == nil {
					raw, err = io.ReadAll(conn)
				}
				if err == nil {
					_, err = conn.Write(raw)
				}
				ends <- err
			}()
		}
	}()
	weight := uint32(100)
	for i := range 6 {
		abort := i%2 == 1
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		conn, err := gonet.DialContextTCP(ctx, devices[0].stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(address.As4()), Port: 8091}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		payload := make([]byte, 256<<10)
		rand.Read(payload)
		if _, err := conn.Write(payload); err != nil {
			t.Fatal(err)
		}
		// The end and the route change race.
		if abort {
			time.Sleep(20 * time.Millisecond) // the greeting arrives unread
			go conn.Close()
		} else {
			go conn.CloseWrite()
		}
		state.Revision++
		state.Networks[0].Edges[0].Weight, weight = weight, 110-weight
		applyAll(t, agents, state)
		if abort {
			if err := <-ends; err == nil {
				t.Fatal("server saw a clean end after a reset")
			}
		} else {
			conn.SetReadDeadline(time.Now().Add(15 * time.Second))
			echo, err := io.ReadAll(conn)
			if err != nil || !bytes.Equal(echo, append([]byte("hi"), payload...)) {
				t.Fatalf("connection %d: %d bytes back, %v", i, len(echo), err)
			}
			if err := <-ends; err != nil {
				t.Fatal(err)
			}
			conn.Close()
		}
		cancel()
		time.Sleep(300 * time.Millisecond)
	}
	assertNoTCPOverTCP(t, agents)
}

// When the routes move a session onto a path whose Edge carries only
// packets, the connection is reset: TCP never crosses a TCP Link as packets.
func TestTCPSessionResetsOnPacketPath(t *testing.T) {
	agents, devices, state := graphAgents(t, model.TCP, streamOptions{}, 4, 4, func(s *model.State) {
		for i := range s.Agents {
			endpoint := s.Agents[i].Endpoints[0]
			endpoint.ID, endpoint.Transport = testutil.ID(60+i), model.UDP
			endpoint.URL = strings.Replace(endpoint.URL, "tcp://", "udp://", 1)
			s.Agents[i].Endpoints = append(s.Agents[i].Endpoints, endpoint)
		}
		s.Networks[0].Edges[2].Transports = []model.Transport{model.UDP} // A-D
	})
	address := state.Networks[0].Nodes[2].Address
	listener, err := gonet.ListenTCP(devices[2].stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(address.As4()), Port: 8092}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() { conn, _ := listener.Accept(); accepted <- conn }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, devices[0].stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(address.As4()), Port: 8092}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	server := <-accepted
	defer server.Close()
	if ingressCount(agents[0]) != 1 {
		t.Fatal("no session over the TCP path")
	}
	state.Revision++
	state.Networks[0].Edges[0].Weight = 100 // now A-D (UDP) -D-C
	applyAll(t, agents, state)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil || err == io.EOF {
		t.Fatalf("connection on a packet path was not reset: %v", err)
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("connection on a packet path was kept waiting")
	}
	assertNoTCPOverTCP(t, agents)
}

// A connection opened as packets on a UDP path ends with a reset when its
// route moves to TCP Links, which carry TCP only as streams: never TCP over
// TCP.
func TestTCPPacketFlowResetsOnTCPPath(t *testing.T) {
	agents, devices, state := graphAgents(t, model.TCP, streamOptions{}, 4, 4, func(s *model.State) {
		for i := range s.Agents {
			endpoint := s.Agents[i].Endpoints[0]
			endpoint.ID, endpoint.Transport = testutil.ID(60+i), model.UDP
			endpoint.URL = strings.Replace(endpoint.URL, "tcp://", "udp://", 1)
			s.Agents[i].Endpoints = append(s.Agents[i].Endpoints, endpoint)
		}
		s.Networks[0].Edges[2].Transports = []model.Transport{model.UDP} // A-D
		s.Networks[0].Edges[3].Transports = []model.Transport{model.UDP} // D-C
		s.Networks[0].Edges[0].Weight = 100                              // A-D-C first
	})
	address := state.Networks[0].Nodes[2].Address
	listener, err := gonet.ListenTCP(devices[2].stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(address.As4()), Port: 8093}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() { conn, _ := listener.Accept(); accepted <- conn }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, devices[0].stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(address.As4()), Port: 8093}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	server := <-accepted
	defer server.Close()
	go io.Copy(io.Discard, server)
	if ingressCount(agents[0]) != 0 {
		t.Fatal("a session on a UDP path")
	}
	state.Revision++
	state.Networks[0].Edges[0].Weight = 10
	state.Networks[0].Edges[2].Weight = 100 // now A-B-C, all TCP
	applyAll(t, agents, state)
	waitFor(t, 5*time.Second, "the route through B", func() bool { return nextHopToC(agents[0], state) == state.Networks[0].Nodes[1].ID })
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	var writeErr error
	for i := 0; i < 1024 && writeErr == nil; i++ {
		_, writeErr = conn.Write(make([]byte, 16384))
		time.Sleep(time.Millisecond)
	}
	if writeErr == nil {
		_, writeErr = conn.Read(make([]byte, 1))
	}
	if timeout, ok := writeErr.(net.Error); writeErr == nil || ok && timeout.Timeout() {
		t.Fatalf("connection on the TCP path was not reset: %v", writeErr)
	}
	assertNoTCPOverTCP(t, agents)
}

// Connections whose receivers stopped reading keep what they have in flight,
// and no more than that, without holding back another connection of the
// same Agents.
func TestTCPSessionStalledConnectionsDoNotBlockOthers(t *testing.T) {
	agents, devices, state := graphAgents(t, model.TCP, streamOptions{}, 3, 2)
	address := state.Networks[0].Nodes[2].Address
	listen := func(port uint16) *gonet.TCPListener {
		listener, err := gonet.ListenTCP(devices[2].stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(address.As4()), Port: port}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		return listener
	}
	dial := func(port uint16) net.Conn {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := gonet.DialContextTCP(ctx, devices[0].stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(address.As4()), Port: port}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	}

	// Receivers that accept and never read.
	stalled := listen(8091)
	go func() {
		for {
			conn, err := stalled.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { conn.Close() })
		}
	}()
	payload := make([]byte, 96<<20)
	for range 2 {
		conn := dial(8091)
		conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
		go conn.Write(payload)
	}
	// Together they keep more than the 64 MiB an Agent's ends could keep
	// before.
	waitFor(t, 30*time.Second, "the stalled connections to fill what is in flight", func() bool {
		return agents[0].Counters()["session_retained_bytes"] > 64<<20
	})

	active := listen(8092)
	request := make([]byte, 4<<20)
	rand.Read(request)
	served := make(chan error, 1)
	go func() {
		conn, err := active.Accept()
		if err != nil {
			served <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(20 * time.Second))
		got, err := io.ReadAll(conn)
		if err == nil && !bytes.Equal(got, request) {
			err = errors.New("request bytes changed")
		}
		if err == nil {
			_, err = conn.Write([]byte("done"))
		}
		served <- err
	}()
	conn := dial(8092)
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := conn.Write(request); err != nil {
		t.Fatal("the active connection could not send:", err)
	}
	if err := conn.(*gonet.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(conn)
	if err != nil || string(reply) != "done" {
		t.Fatal("the active connection got no reply:", err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
}
