package agent

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

func ingressCount(agent *DataPlane) int {
	agent.sessions.mu.Lock()
	defer agent.sessions.mu.Unlock()
	return len(agent.sessions.ingress)
}

// A connection over TCP Links between current Agents is a session.
func TestTCPConnectionIsSession(t *testing.T) {
	agents, devices, state := streamAgents(t, model.TCP)
	target := state.Networks[0].Nodes[2].Address
	listener, err := gonet.ListenTCP(devices[2].stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(target.As4()), Port: 8090}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() { conn, _ := listener.Accept(); accepted <- conn }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, devices[0].stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(target.As4()), Port: 8090}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	server := <-accepted
	defer server.Close()
	if ingressCount(agents[0]) != 1 {
		t.Fatalf("ingress sessions: %d", ingressCount(agents[0]))
	}
	server.Write([]byte("x"))
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
}
