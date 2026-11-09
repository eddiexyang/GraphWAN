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
	// The egress's overlay address and the network's route are on this host,
	// as its TUN's would be.
	server := nodes[2].Address
	for _, args := range [][]string{
		{"link", "add", "gwegress", "type", "dummy"},
		{"link", "set", "gwegress", "up"},
		{"addr", "add", netip.PrefixFrom(server, state.Networks[0].CIDR.Bits()).String(), "dev", "gwegress"},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatal(string(out), err)
		}
	}
	t.Cleanup(func() { exec.Command("ip", "link", "del", "gwegress").Run() })
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
		wrote := make(chan struct{})
		go func() {
			conn.Write(payload)
			close(wrote)
		}()
		got, err := io.ReadAll(conn)
		<-wrote
		served <- result{conn.RemoteAddr(), got, err}
	}()
	if echo := exchange(t, devices[0], netip.AddrPortFrom(server, 9100), payload); !bytes.Equal(echo, payload) {
		t.Fatal("the server's bytes changed")
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

// A session's egress reaches a destination in a subnet its node is a gateway
// for with a kernel socket too: a routed gateway keeps the client's address,
// and a SNAT gateway sends from one of the host's own. The server runs in
// another network namespace, TestKernelEgressServer, that routes the
// network's addresses to this one.
func TestTCPEgressToGatewaySubnet(t *testing.T) {
	remote := os.Getenv("GRAPHWAN_KERNEL_EGRESS_REMOTE")
	if remote == "" {
		t.Skip("needs a server in another network namespace: set GRAPHWAN_KERNEL_EGRESS_REMOTE")
	}
	server := netip.MustParseAddrPort(remote)
	for _, mode := range []model.GatewayMode{model.GatewaySNAT, model.GatewayRoute} {
		t.Run(string(mode), func(t *testing.T) {
			agents, devices, state := graphAgents(t, model.TCP, streamOptions{kernelEgress: true}, 3, 2, func(s *model.State) {
				subnet := netip.PrefixFrom(server.Addr(), 24).Masked()
				s.Networks[0].Nodes[2].AdvertisedSubnets = []model.AdvertisedSubnet{{Prefix: subnet, GatewayMode: mode}}
			})
			if !agents[2].kernelEgress {
				t.Fatal("the gateway could not install the kernel egress")
			}
			payload := make([]byte, 8<<20)
			rand.Read(payload)
			got := exchange(t, devices[0], server, payload)
			line, echo, _ := bytes.Cut(got, []byte("\n"))
			if !bytes.Equal(echo, payload) {
				t.Fatal("the bytes changed")
			}
			from := netip.MustParseAddrPort(string(line)).Addr()
			client := state.Networks[0].Nodes[0].Address
			if mode == model.GatewayRoute && from != client {
				t.Fatalf("the server saw %s, not the client %s", from, client)
			}
			if mode == model.GatewaySNAT && !localDestination(from) {
				t.Fatalf("the server saw %s, not this host", from)
			}
			assertNoTCPOverTCP(t, agents)
		})
	}
}

// TestKernelEgressServer serves TestTCPEgressToGatewaySubnet's connections:
// it sends each client the address it sees on a line, then echoes it.
func TestKernelEgressServer(t *testing.T) {
	address := os.Getenv("GRAPHWAN_KERNEL_EGRESS_SERVE")
	if address == "" {
		t.Skip("serves TestTCPEgressToGatewaySubnet: set GRAPHWAN_KERNEL_EGRESS_SERVE")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for range 2 {
		conn, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		io.WriteString(conn, conn.RemoteAddr().String()+"\n")
		io.Copy(conn, conn)
		conn.Close()
	}
}

// exchange sends payload from device's stack to the destination, closes its
// side and returns all the destination sends back.
func exchange(t *testing.T, device *kernelTUN, to netip.AddrPort, payload []byte) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, device.stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(to.Addr().As4()), Port: to.Port()}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	go func() {
		conn.Write(payload)
		conn.CloseWrite()
	}()
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	return got
}
