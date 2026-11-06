package mesh

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/link"
	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/streamproxy"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// A carrier carries session hops over an Edge whose Links carry no streams,
// such as UDP or QUIC: a TCP between the two Agents in a stack of the Edge's
// own. Its packets travel as carrier messages on the Edge's selected Link, so
// they cross exactly this Edge and never reach the overlay or a host stack.
// Like streams, each hop keeps its own loss recovery and flow control.
const (
	carrierMTU   = model.DefaultMTU
	carrierPort  = 1
	carrierQueue = 1024
	// carrierMaxRTO bounds the retransmission timeout's exponential backoff.
	carrierMaxRTO = time.Second
)

// Each end takes the address by node ID order, as stream IDs take parity.
var carrierAddresses = [2]tcpip.Address{
	tcpip.AddrFrom16([16]byte{0xfd, 0x47, 0x57, 15: 1}),
	tcpip.AddrFrom16([16]byte{0xfd, 0x47, 0x57, 15: 2}),
}

type carrier struct {
	g      *group
	stack  *stack.Stack
	link   *channel.Endpoint
	local  tcpip.Address
	remote tcpip.Address
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// carrierLocked returns the Edge's carrier, starting it on first use.
func (g *group) carrierLocked() (*carrier, error) {
	if g.carrier != nil {
		return g.carrier, nil
	}
	if g.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	cfg := g.policy.Load()
	local, remote := carrierAddresses[0], carrierAddresses[1]
	if cfg.self > cfg.peer.Node.ID {
		local, remote = remote, local
	}
	ctx, cancel := context.WithCancel(g.ctx)
	c := &carrier{g: g, local: local, remote: remote, ctx: ctx, cancel: cancel}
	c.stack = stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol}})
	c.link = channel.New(carrierQueue, carrierMTU, "")
	fail := func(err tcpip.Error) (*carrier, error) {
		cancel()
		c.stack.Close()
		return nil, errors.New(err.String())
	}
	if err := c.stack.CreateNIC(1, c.link); err != nil {
		return fail(err)
	}
	if err := c.stack.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv6.ProtocolNumber, AddressWithPrefix: local.WithPrefix()}, stack.AddressProperties{}); err != nil {
		return fail(err)
	}
	c.stack.SetRouteTable([]tcpip.Route{{Destination: header.IPv6EmptySubnet, NIC: 1}})
	// The carrier crosses a WAN Edge: recover losses with SACK and let the
	// windows grow with the path's bandwidth-delay product. It is one TCP over
	// one Edge, so a burst of losses, as when a datagram queue overflows, must
	// not back its retransmission off for long: the timeout stays at most 1 s.
	sack := tcpip.TCPSACKEnabled(true)
	moderate := tcpip.TCPModerateReceiveBufferOption(true)
	receive := tcpip.TCPReceiveBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: 1 << 20, Max: 16 << 20}
	send := tcpip.TCPSendBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: 1 << 20, Max: 16 << 20}
	maxRTO := tcpip.TCPMaxRTOOption(carrierMaxRTO)
	for _, option := range []tcpip.SettableTransportProtocolOption{&sack, &moderate, &receive, &send, &maxRTO} {
		if err := c.stack.SetTransportProtocolOption(tcp.ProtocolNumber, option); err != nil {
			return fail(err)
		}
	}
	c.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(c.stack, 0, streamproxy.MaxConnections, c.accept).HandlePacket)
	c.wg.Add(1)
	go c.output()
	g.carrier = c
	return c, nil
}

// output sends the stack's packets on the Edge's selected Link.
func (c *carrier) output() {
	defer c.wg.Done()
	for {
		p := c.link.ReadContext(c.ctx)
		if p == nil {
			return
		}
		view := p.ToView()
		p.DecRef()
		if l := c.g.edge.Active(); l != nil {
			l.SendCarrier(view.AsSlice())
		}
		view.Release()
	}
}

func (c *carrier) receive(raw []byte) {
	if len(raw) < header.IPv6MinimumSize || raw[0]>>4 != 6 {
		return
	}
	p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
	c.link.InjectInbound(ipv6.ProtocolNumber, p)
	p.DecRef()
}

func (c *carrier) accept(request *tcp.ForwarderRequest) {
	id := request.ID()
	if id.LocalAddress != c.local || id.LocalPort != carrierPort || id.RemoteAddress != c.remote {
		request.Complete(true)
		return
	}
	var queue waiter.Queue
	endpoint, err := request.CreateEndpoint(&queue)
	request.Complete(err != nil)
	if err != nil {
		return
	}
	c.g.mesh.acceptHop(c.g, newCarrierConn(endpoint, &queue))
}

func (c *carrier) dial(ctx context.Context) (streamproxy.Conn, error) {
	var queue waiter.Queue
	endpoint, err := c.stack.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &queue)
	if err != nil {
		return nil, errors.New(err.String())
	}
	entry, ready := waiter.NewChannelEntry(waiter.WritableEvents)
	queue.EventRegister(&entry)
	defer queue.EventUnregister(&entry)
	err = endpoint.Connect(tcpip.FullAddress{NIC: 1, Addr: c.remote, Port: carrierPort})
	if _, started := err.(*tcpip.ErrConnectStarted); started {
		select {
		case <-ctx.Done():
			endpoint.Close()
			return nil, ctx.Err()
		case <-ready:
		}
		err = endpoint.LastError()
	}
	if err != nil {
		endpoint.Close()
		return nil, errors.New("connect carrier: " + err.String())
	}
	return newCarrierConn(endpoint, &queue), nil
}

func (c *carrier) close() {
	c.cancel()
	c.stack.Close()
	for _, endpoint := range c.stack.CleanupEndpoints() {
		endpoint.Abort()
	}
	c.link.Close()
	c.wg.Wait()
}

// carrierConn is a session hop on a carrier.
type carrierConn struct {
	*gonet.TCPConn
	endpoint tcpip.Endpoint
}

func newCarrierConn(endpoint tcpip.Endpoint, queue *waiter.Queue) *carrierConn {
	return &carrierConn{TCPConn: gonet.NewTCPConn(queue, endpoint), endpoint: endpoint}
}

// Abort resets the carrier connection, as a reset stream does.
func (c *carrierConn) Abort() { c.endpoint.Abort() }

// receiveCarrier is a Link's carrier handler.
func (g *group) receiveCarrier(_ *link.Link, raw []byte) {
	g.mu.Lock()
	c, err := g.carrierLocked()
	g.mu.Unlock()
	if err == nil {
		c.receive(raw)
	}
}

// CarrierAvailable reports whether a session hop to remote can take a carrier:
// the Edge's selected Link confirmed sessions.
func (m *Mesh) CarrierAvailable(network, remote model.ID) bool {
	m.mu.Lock()
	g := m.groups[key{network, remote}]
	m.mu.Unlock()
	if g == nil {
		return false
	}
	l := g.edge.Active()
	return l != nil && l.Resume()
}

// OpenCarrier connects a session hop to remote on the Edge's carrier.
func (m *Mesh) OpenCarrier(ctx context.Context, network, remote model.ID) (streamproxy.Conn, error) {
	m.mu.Lock()
	g := m.groups[key{network, remote}]
	m.mu.Unlock()
	if g == nil {
		return nil, link.ErrUnavailable
	}
	g.mu.Lock()
	c, err := g.carrierLocked()
	g.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return c.dial(ctx)
}

// IsCarrier reports whether a session hop is a carrier connection.
func IsCarrier(hop streamproxy.Conn) bool {
	_, ok := hop.(*carrierConn)
	return ok
}
