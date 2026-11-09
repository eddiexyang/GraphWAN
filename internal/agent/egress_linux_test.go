package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

// A session's egress reaches a destination on its own host with a kernel
// socket: the server sees the client's own address, and the bytes arrive
// unchanged both ways. It needs CAP_NET_ADMIN, nft and ip, as in a network
// namespace of its own.
func TestTCPEgressThroughKernelSocket(t *testing.T) {
	if os.Getenv("GRAPHWAN_KERNEL_EGRESS_TEST") == "" {
		t.Skip("needs a network namespace of its own: set GRAPHWAN_KERNEL_EGRESS_TEST")
	}
	agents, devices, state := graphAgents(t, model.TCP, streamOptions{kernelEgress: true}, 3, 2)
	for i, agent := range agents {
		if !agent.kernelEgress {
			t.Fatalf("Agent %d could not install the kernel egress", i)
		}
	}
	nodes := state.Networks[0].Nodes
	// The egress's overlay address is on this host, as its TUN's would be.
	server := nodes[2].Address
	if out, err := exec.Command("ip", "addr", "add", server.String()+"/32", "dev", "lo").CombinedOutput(); err != nil {
		t.Fatal(string(out), err)
	}
	t.Cleanup(func() { exec.Command("ip", "addr", "del", server.String()+"/32", "dev", "lo").Run() })
	listener, err := net.Listen("tcp", netip.AddrPortFrom(server, 9100).String())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	payload := make([]byte, 8<<20)
	rand.Read(payload)
	type result struct {
		remote net.Addr
		got    []byte
		err    error
	}
	served := make(chan result, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			served <- result{nil, nil, err}
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		go conn.Write(payload)
		got, err := io.ReadAll(conn)
		served <- result{conn.RemoteAddr(), got, err}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, devices[0].stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(server.As4()), Port: 9100}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	go func() {
		conn.Write(payload)
		conn.CloseWrite()
	}()
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, echo); err != nil || !bytes.Equal(echo, payload) {
		t.Fatal("the server's bytes changed", err)
	}
	r := <-served
	if r.err != nil || !bytes.Equal(r.got, payload) {
		t.Fatal("the client's bytes changed", r.err)
	}
	if from := r.remote.(*net.TCPAddr).AddrPort().Addr(); from != nodes[0].Address {
		t.Fatalf("the server saw %s, not the client %s", from, nodes[0].Address)
	}
	assertNoTCPOverTCP(t, agents)
}
