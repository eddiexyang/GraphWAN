package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
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
}
