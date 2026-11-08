package agent

import (
	"context"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/routing"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

// A connection whose path is missing for now is not reset: its SYN is
// dropped as a packet with no route would be, and the client's retransmitted
// SYN connects once the path exists. Here the ingress routes through a relay
// that has no route yet, as while routes converge.
func TestTCPConnectsOnceItsPathExists(t *testing.T) {
	agents, devices, state := graphAgents(t, model.TCP, streamOptions{withoutLinkState: true}, 3, 2)
	address := state.Networks[0].Nodes[2].Address
	listener, err := gonet.ListenTCP(devices[2].stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(address.As4()), Port: 8083}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		if conn, err := listener.Accept(); err == nil {
			conn.Write([]byte("ok"))
			conn.Close()
		}
	}()
	apply := func(agent int, s model.State) {
		t.Helper()
		snapshot, err := routing.Compile(s, s.Agents[agent].ID)
		if err != nil {
			t.Fatal(err)
		}
		for n := range snapshot.Networks {
			snapshot.Networks[n].Topology = nil
		}
		if err := agents[agent].Apply(context.Background(), snapshot); err != nil {
			t.Fatal(err)
		}
	}
	missing := state.Clone()
	missing.Revision++
	missing.Networks[0].Edges[1].Enabled = false // B-C, at B only
	apply(1, missing)
	dialed := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		conn, err := gonet.DialContextTCP(ctx, devices[0].stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(address.As4()), Port: 8083}, ipv4.ProtocolNumber)
		if err == nil {
			buf := make([]byte, 2)
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, err = conn.Read(buf)
			conn.Close()
		}
		dialed <- err
	}()
	select {
	case err := <-dialed:
		t.Fatalf("connection ended while its path was missing: %v", err)
	case <-time.After(1500 * time.Millisecond):
	}
	state.Revision = missing.Revision + 1
	apply(1, state)
	if err := <-dialed; err != nil {
		t.Fatal(err)
	}
}
