package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/packet"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// B (cost 10 + metric 0) and D (1 + 20) both advertise 192.168.0.0/24. When
// D becomes the cheaper exit, a connection through B ends with a reset after
// a correct prefix of its byte stream; it never continues at D. A new
// connection exits at D.
func TestTCPConnectionResetsOnExitChange(t *testing.T) {
	prefix := netip.MustParsePrefix("192.168.0.0/24")
	agents, devices, state := graphAgents(t, model.TCP, streamOptions{}, 4, 4, func(s *model.State) {
		s.Networks[0].Nodes[1].AdvertisedSubnets = []model.AdvertisedSubnet{{Prefix: prefix, GatewayMode: model.GatewayOff}}
		s.Networks[0].Nodes[3].AdvertisedSubnets = []model.AdvertisedSubnet{{Prefix: prefix, GatewayMode: model.GatewayOff, Metric: 20}}
	})
	network, nodes := state.Networks[0].ID, state.Networks[0].Nodes
	waitFor(t, 10*time.Second, "end-to-end sessions toward both exits", func() bool {
		return outgoingE2E(agents[0], network, nodes[1].ID) != nil && outgoingE2E(agents[0], network, nodes[3].ID) != nil
	})
	toB, toD := outgoingE2E(agents[0], network, nodes[1].ID), outgoingE2E(agents[0], network, nodes[3].ID)
	server := tcpip.AddrFrom4(netip.MustParseAddr("192.168.0.7").As4())
	accepted := make(chan int, 4)
	for _, exit := range []int{1, 3} {
		if err := devices[exit].stack.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: server, PrefixLen: 32}}, stack.AddressProperties{}); err != nil {
			t.Fatal(err)
		}
		listener, err := gonet.ListenTCP(devices[exit].stack, tcpip.FullAddress{NIC: 1, Addr: server, Port: 9000}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				accepted <- exit
				go func() { defer conn.Close(); io.Copy(conn, conn) }()
			}
		}()
	}
	dial := func() (net.Conn, int) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := gonet.DialContextTCP(ctx, devices[0].stack, tcpip.FullAddress{NIC: 1, Addr: server, Port: 9000}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		select {
		case exit := <-accepted:
			return conn, exit
		case <-time.After(10 * time.Second):
			t.Fatal("no exit accepted the connection")
		}
		return nil, 0
	}
	echo := func(conn net.Conn) {
		t.Helper()
		payload := make([]byte, 1<<20)
		rand.Read(payload)
		conn.SetDeadline(time.Now().Add(20 * time.Second))
		go conn.Write(payload)
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("echo: %v", err)
		}
	}
	conn, exit := dial()
	defer conn.Close()
	if exit != 1 {
		t.Fatalf("first connection exits at node %d, want B", exit)
	}
	// Stream random bytes and compare the echo with what was sent, before and
	// after the exit changes.
	sent := make([]byte, 64<<20)
	rand.Read(sent)
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	writeErr := make(chan error, 1)
	go func() {
		for offset := 0; offset < len(sent); offset += 16 << 10 {
			if _, err := conn.Write(sent[offset : offset+16<<10]); err != nil {
				writeErr <- err
				return
			}
			time.Sleep(time.Millisecond)
		}
		writeErr <- nil
	}()
	received := make([]byte, 0, len(sent))
	buf := make([]byte, 64<<10)
	changed := false
	var readErr error
	for readErr == nil {
		var n int
		n, readErr = conn.Read(buf)
		received = append(received, buf[:n]...)
		if !bytes.Equal(received, sent[:len(received)]) {
			t.Fatalf("echo differs from the sent stream within %d bytes", len(received))
		}
		if !changed && len(received) >= 1<<20 {
			changed = true
			state.Revision++
			state.Networks[0].Nodes[1].AdvertisedSubnets[0].Metric = 50 // B: 60, D: 21
			applyAll(t, agents, state)
		}
	}
	if !changed {
		t.Fatalf("connection ended before the exit changed: %v", readErr)
	}
	// The stack reports a reset to one call; the other then sees the closed
	// connection.
	var written error
	select {
	case written = <-writeErr:
	case <-time.After(5 * time.Second):
	}
	reset := func(err error) bool { return err != nil && strings.Contains(err.Error(), "connection reset by peer") }
	if !reset(readErr) && !reset(written) {
		t.Fatalf("connection through the old exit was not reset: read %v, write %v", readErr, written)
	}
	t.Logf("reset after %d correct bytes: read %v, write %v", len(received), readErr, written)
	select {
	case other := <-accepted:
		t.Fatalf("the connection continued at node %d", other)
	default:
	}
	if agents[0].Counters()["session_exit_resets"] == 0 {
		t.Fatal("no exit reset counted")
	}
	second, exit := dial()
	defer second.Close()
	if exit != 3 {
		t.Fatalf("new connection exits at node %d, want D", exit)
	}
	echo(second)
	assertNoTCPOverTCP(t, agents)
	// Both connections were sealed with the sessions A prepared toward each
	// exit before it needed them: none was replaced on the way.
	if outgoingE2E(agents[0], network, nodes[1].ID) != toB || outgoingE2E(agents[0], network, nodes[3].ID) != toD {
		t.Fatal("the ingress replaced a prepared session")
	}
	if agents[1].e2eAccepted(network, nodes[0].ID, toB.id) == nil || agents[3].e2eAccepted(network, nodes[0].ID, toD.id) == nil {
		t.Fatal("an exit did not open the connection with A's prepared session")
	}
}

// exitServer is the address B and D's prefix holds in the exit tests.
var exitServer = netip.MustParseAddr("192.168.0.7")

// exitAgents has B (cost 10 + metric 0) and D (1 + dMetric) advertise
// 192.168.0.0/24 and capture the UDP datagrams written to their devices.
func exitAgents(t *testing.T, carrier model.Transport, dMetric uint32, paths model.EqualCostPaths) ([]*DataPlane, []*kernelTUN, model.State) {
	t.Helper()
	prefix := netip.MustParsePrefix("192.168.0.0/24")
	agents, devices, state := graphAgents(t, carrier, streamOptions{}, 4, 4, func(s *model.State) {
		s.Networks[0].EqualCostPaths = paths
		s.Networks[0].Nodes[1].AdvertisedSubnets = []model.AdvertisedSubnet{{Prefix: prefix, GatewayMode: model.GatewayOff}}
		s.Networks[0].Nodes[3].AdvertisedSubnets = []model.AdvertisedSubnet{{Prefix: prefix, GatewayMode: model.GatewayOff, Metric: dMetric}}
	})
	for _, exit := range []int{1, 3} {
		devices[exit].udp = make(chan []byte, 4096)
	}
	network, nodes := state.Networks[0].ID, state.Networks[0].Nodes
	waitFor(t, 10*time.Second, "end-to-end sessions toward both exits", func() bool {
		return outgoingE2E(agents[0], network, nodes[1].ID) != nil && outgoingE2E(agents[0], network, nodes[3].ID) != nil
	})
	return agents, devices, state
}

// datagramExit sends one datagram from port from at A to the exit server and
// reports which exit's device received it, unchanged.
func datagramExit(t *testing.T, devices []*kernelTUN, state model.State, from uint16) int {
	t.Helper()
	source := netip.AddrPortFrom(state.Networks[0].Nodes[0].Address, from)
	destination := netip.AddrPortFrom(exitServer, 5001)
	message := []byte(fmt.Sprintf("datagram from %d", from))
	raw := packet.UDP(source, destination, message)
	for attempt := 0; attempt < 50; attempt++ {
		devices[0].packets <- kernelPacket{raw: bytes.Clone(raw)}
		select {
		case got := <-devices[1].udp:
			return checkDatagram(t, got, source, destination, message, 1)
		case got := <-devices[3].udp:
			return checkDatagram(t, got, source, destination, message, 3)
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatal("no exit received the datagram")
	return 0
}

func checkDatagram(t *testing.T, got []byte, source, destination netip.AddrPort, message []byte, exit int) int {
	t.Helper()
	if s, d, payload, ok := packet.UDPDatagram(got); !ok || s != source || d != destination || !bytes.Equal(payload, message) {
		t.Fatalf("exit %d received a changed datagram", exit)
	}
	return exit
}

// Sealed datagrams move to the cheaper exit with the next packet, sealed with
// the session the ingress prepared toward it: no handshake on the way.
func TestSealedPacketsFollowExitChange(t *testing.T) {
	agents, devices, state := exitAgents(t, model.UDP, 20, model.EqualCostLowestID)
	network, nodes := state.Networks[0].ID, state.Networks[0].Nodes
	toB, toD := outgoingE2E(agents[0], network, nodes[1].ID), outgoingE2E(agents[0], network, nodes[3].ID)
	if exit := datagramExit(t, devices, state, 6000); exit != 1 {
		t.Fatalf("datagram exits at node %d, want B", exit)
	}
	state.Revision++
	state.Networks[0].Nodes[1].AdvertisedSubnets[0].Metric = 50 // B: 60, D: 21
	applyAll(t, agents, state)
	for port := uint16(6001); port < 6021; port++ {
		if exit := datagramExit(t, devices, state, port); exit != 3 {
			t.Fatalf("datagram %d after the change exits at node %d, want D", port, exit)
		}
	}
	if outgoingE2E(agents[0], network, nodes[1].ID) != toB || outgoingE2E(agents[0], network, nodes[3].ID) != toD {
		t.Fatal("the ingress replaced a prepared session")
	}
	if agents[3].e2eAccepted(network, nodes[0].ID, toD.id) == nil {
		t.Fatal("D did not open the datagrams with A's prepared session")
	}
}

// With ECMP between two exits of equal cost, each flow keeps one exit and
// both exits carry flows; when one exit becomes dearer every flow moves to
// the other at once.
func TestSealedECMPKeepsEachFlowOnOneExit(t *testing.T) {
	agents, devices, state := exitAgents(t, model.UDP, 9, model.EqualCostECMP) // B: 10, D: 10
	exits := map[uint16]int{}
	used := map[int]int{}
	for port := uint16(7000); port < 7064; port++ {
		exit := datagramExit(t, devices, state, port)
		exits[port] = exit
		used[exit]++
	}
	if used[1] == 0 || used[3] == 0 {
		t.Fatalf("flows per exit %v, want both", used)
	}
	for port, exit := range exits {
		for range 3 {
			if again := datagramExit(t, devices, state, port); again != exit {
				t.Fatalf("flow %d moved from node %d to %d", port, exit, again)
			}
		}
	}
	state.Revision++
	state.Networks[0].Nodes[1].AdvertisedSubnets[0].Metric = 10 // B: 20, D: 10
	applyAll(t, agents, state)
	for port := range exits {
		if exit := datagramExit(t, devices, state, port); exit != 3 {
			t.Fatalf("flow %d exits at node %d after B became dearer", port, exit)
		}
	}
}

// With ECMP between two exits of equal cost, TCP connections spread over both
// exits, each sealed with the session A prepared toward its exit.
func TestSealedECMPSpreadsConnections(t *testing.T) {
	agents, devices, state := exitAgents(t, model.TCP, 9, model.EqualCostECMP) // B: 10, D: 10
	network, nodes := state.Networks[0].ID, state.Networks[0].Nodes
	toB, toD := outgoingE2E(agents[0], network, nodes[1].ID), outgoingE2E(agents[0], network, nodes[3].ID)
	server := tcpip.AddrFrom4(exitServer.As4())
	accepted := make(chan int, 64)
	for _, exit := range []int{1, 3} {
		if err := devices[exit].stack.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: server, PrefixLen: 32}}, stack.AddressProperties{}); err != nil {
			t.Fatal(err)
		}
		listener, err := gonet.ListenTCP(devices[exit].stack, tcpip.FullAddress{NIC: 1, Addr: server, Port: 9000}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				accepted <- exit
				go func() { defer conn.Close(); io.Copy(conn, conn) }()
			}
		}()
	}
	used := map[int]int{}
	for i := range 64 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		conn, err := gonet.DialContextTCP(ctx, devices[0].stack, tcpip.FullAddress{NIC: 1, Addr: server, Port: 9000}, ipv4.ProtocolNumber)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		message := []byte(fmt.Sprintf("connection %d", i))
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		got := make([]byte, len(message))
		if _, err := conn.Write(message); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, message) {
			t.Fatalf("connection %d: %v", i, err)
		}
		conn.Close()
		select {
		case exit := <-accepted:
			used[exit]++
		case <-time.After(5 * time.Second):
			t.Fatalf("no exit accepted connection %d", i)
		}
	}
	if used[1] == 0 || used[3] == 0 || used[1]+used[3] != 64 {
		t.Fatalf("connections per exit %v, want both", used)
	}
	if outgoingE2E(agents[0], network, nodes[1].ID) != toB || outgoingE2E(agents[0], network, nodes[3].ID) != toD {
		t.Fatal("the ingress replaced a prepared session")
	}
	assertNoTCPOverTCP(t, agents)
}
