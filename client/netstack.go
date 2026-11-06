package client

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/eWloYW8/GraphWAN/internal/tunnel"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// netstack stands in for a TUN interface. The embedding application's
// connections live in this user-space stack at the node's overlay address;
// its packets go to the data plane exactly as a TUN's would.
type netstack struct {
	config tunnel.Config
	stack  *stack.Stack
	link   *channel.Endpoint
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
}

const netstackQueue = 1024

func newNetstack(config tunnel.Config) (*netstack, error) {
	ctx, cancel := context.WithCancel(context.Background())
	n := &netstack{config: config, ctx: ctx, cancel: cancel}
	n.stack = stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
	n.link = channel.New(netstackQueue, uint32(config.MTU), "")
	if err := n.stack.CreateNIC(1, n.link); err != nil {
		n.Close()
		return nil, errors.New(err.String())
	}
	address := config.Address.Addr()
	protocol := ipv4.ProtocolNumber
	if address.Is6() {
		protocol = ipv6.ProtocolNumber
	}
	if err := n.stack.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: protocol, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice(address.AsSlice()), PrefixLen: config.Address.Bits()}}, stack.AddressProperties{}); err != nil {
		n.Close()
		return nil, errors.New(err.String())
	}
	// Every destination goes to the data plane, which owns routing.
	n.stack.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	return n, nil
}

func (n *netstack) Name() string                 { return "netstack" }
func (n *netstack) Configuration() tunnel.Config { return n.config }
func (n *netstack) address() netip.Addr          { return n.config.Address.Addr() }
func (n *netstack) protocol() tcpip.NetworkProtocolNumber {
	if n.address().Is6() {
		return ipv6.ProtocolNumber
	}
	return ipv4.ProtocolNumber
}

// Read returns the next packet the stack sends, for the data plane.
func (n *netstack) Read(p []byte) (int, error) {
	packet := n.link.ReadContext(n.ctx)
	if packet == nil {
		return 0, net.ErrClosed
	}
	defer packet.DecRef()
	view := packet.ToView()
	defer view.Release()
	if view.Size() > len(p) {
		return 0, io.ErrShortBuffer
	}
	return copy(p, view.AsSlice()), nil
}

// Write delivers a packet from the data plane to the stack.
func (n *netstack) Write(p []byte) (int, error) {
	if n.ctx.Err() != nil {
		return 0, tunnel.ErrUnavailable
	}
	if len(p) == 0 {
		return 0, nil
	}
	protocol := ipv4.ProtocolNumber
	if p[0]>>4 == 6 {
		protocol = ipv6.ProtocolNumber
	}
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p)})
	n.link.InjectInbound(protocol, packet)
	packet.DecRef()
	return len(p), nil
}

func (n *netstack) Close() error {
	n.once.Do(func() {
		n.cancel()
		n.link.Close()
		n.stack.Close()
	})
	return nil
}

func fullAddress(a netip.AddrPort) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(a.Addr().AsSlice()), Port: a.Port()}
}
