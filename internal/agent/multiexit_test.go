package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// B (cost 10 + metric 0) and D (1 + 20) both advertise 192.168.0.0/24. A
// connection keeps its exit when the other exit becomes cheaper; new
// connections use the cheaper one.
func TestTCPConnectionKeepsExit(t *testing.T) {
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
	echo(conn)
	state.Revision++
	state.Networks[0].Nodes[1].AdvertisedSubnets[0].Metric = 50 // B: 60, D: 21
	applyAll(t, agents, state)
	echo(conn)
	select {
	case other := <-accepted:
		t.Fatalf("the connection was reopened at node %d", other)
	default:
	}
	second, exit := dial()
	defer second.Close()
	if exit != 3 {
		t.Fatalf("new connection exits at node %d, want D", exit)
	}
	echo(second)
	echo(conn)
	assertNoTCPOverTCP(t, agents)
}
