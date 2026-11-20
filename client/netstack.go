package client

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/eddiexyang/graphnet/internal/tunnel"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// netstack stands in for a TUN interface. The embedding application's
// connections live in this user-space stack at the node's overlay address;
// its packets go to the data plane exactly as a TUN's would.
type netstack struct {
	config tunnel.Config
	stack  *stack.Stack
	link   *netstackLink
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
}

const netstackQueue = 1024

// gVisor reads checksum capabilities at NIC ingress. Serialize injection so
// only packets submitted by the local TCP offload path can skip verification.
type netstackLink struct {
	*channel.Endpoint
	mu       sync.Mutex
	verified atomic.Bool
}

func (l *netstackLink) Capabilities() stack.LinkEndpointCapabilities {
	caps := l.Endpoint.Capabilities()
	if l.verified.Load() {
		caps |= stack.CapabilityRXChecksumOffload
	}
	return caps
}

func (l *netstackLink) inject(protocol tcpip.NetworkProtocolNumber, packet *stack.PacketBuffer, verified bool) {
	l.mu.Lock()
	l.verified.Store(verified)
	l.Endpoint.InjectInbound(protocol, packet)
	l.verified.Store(false)
	l.mu.Unlock()
}

func newNetstack(config tunnel.Config) (*netstack, error) {
	ctx, cancel := context.WithCancel(context.Background())
	n := &netstack{config: config, ctx: ctx, cancel: cancel}
	n.stack = stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
	n.link = &netstackLink{Endpoint: channel.New(netstackQueue, uint32(config.MTU), "")}
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

// A bound endpoint reserves a source port common to streams and packet TCP.
// Only the packet route connects the endpoint and starts a TCP handshake.
type boundTCP struct {
	tcpip.Endpoint
	queue waiter.Queue
	port  uint16
}

func (n *netstack) bindTCP() (*boundTCP, error) {
	b := &boundTCP{}
	endpoint, err := n.stack.NewEndpoint(tcp.ProtocolNumber, n.protocol(), &b.queue)
	if err != nil {
		return nil, errors.New(err.String())
	}
	b.Endpoint = endpoint
	if err := endpoint.Bind(fullAddress(netip.AddrPortFrom(n.address(), 0))); err != nil {
		endpoint.Close()
		return nil, errors.New(err.String())
	}
	address, err := endpoint.GetLocalAddress()
	if err != nil {
		endpoint.Close()
		return nil, errors.New(err.String())
	}
	b.port = address.Port
	return b, nil
}

func (b *boundTCP) connect(ctx context.Context, destination netip.AddrPort) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		b.Close()
		return nil, err
	}
	entry, ready := waiter.NewChannelEntry(waiter.WritableEvents)
	b.queue.EventRegister(&entry)
	defer b.queue.EventUnregister(&entry)
	err := b.Connect(fullAddress(destination))
	if _, pending := err.(*tcpip.ErrConnectStarted); pending {
		select {
		case <-ctx.Done():
			b.Close()
			return nil, ctx.Err()
		case <-ready:
			err = b.LastError()
		}
	}
	if err != nil {
		b.Close()
		return nil, &net.OpError{Op: "connect", Net: "tcp", Addr: net.TCPAddrFromAddrPort(destination), Err: errors.New(err.String())}
	}
	return gonet.NewTCPConn(&b.queue, b.Endpoint), nil
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
	n.link.inject(protocol, packet, false)
	packet.DecRef()
	return len(p), nil
}

// WriteTCPPacket delivers the local access stack's TCP output without
// flattening its packet buffer or splitting a coalesced segment.
func (n *netstack) WriteTCPPacket(packet *stack.PacketBuffer) error {
	if n.ctx.Err() != nil {
		return tunnel.ErrUnavailable
	}
	inbound := packet.CloneToInbound()
	defer inbound.DecRef()
	// Host GSO output carries a partial checksum. This is a trusted,
	// in-process handoff from the access stack with no wire hop.
	n.link.inject(packet.NetworkProtocolNumber, inbound, packet.GSOOptions.NeedsCsum)
	return nil
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
