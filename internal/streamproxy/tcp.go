package streamproxy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/packetbuf"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const ConnectTimeout = 10 * time.Second

// Hold a full default TCP send window at ordinary access MTUs plus ACKs. A
// smaller packet-count queue can drop a local burst before socket backpressure.
const accessPacketQueue = 2048

// Engine owns only access-side TCP. output emits packets to the local TUN or
// authenticated WireGuard leaf; open returns the graph's application byte stream.
type Engine struct {
	stack       *stack.Stack
	link        *channel.Endpoint
	ingress     *accessLink
	ctx         context.Context
	cancel      context.CancelFunc
	output      func([]byte) error
	outputBatch func([][]byte) error
	open        func(context.Context, netip.AddrPort, netip.AddrPort) (Conn, error)
	mu          sync.Mutex
	closed      bool
	slots       chan struct{}
	wg          sync.WaitGroup
	flowHook    atomic.Pointer[func(from, to netip.AddrPort, open bool)]
}

// SetFlowHook reports when an accepted connection starts and ends its relay.
func (e *Engine) SetFlowHook(hook func(from, to netip.AddrPort, open bool)) {
	e.flowHook.Store(&hook)
}

func (e *Engine) flow(from, to netip.AddrPort, open bool) {
	if hook := e.flowHook.Load(); hook != nil {
		(*hook)(from, to, open)
	}
}

// gVisor normalizes RXChecksumValidated from link capabilities during the
// synchronous NIC entry, discarding the packet's original flag. Serialize that
// entry and expose only this packet's verified state; subsequent TCP work owns
// its packet reference and checksum flag independently.
type accessLink struct {
	*channel.Endpoint
	mu        sync.Mutex
	validated atomic.Bool
	closed    atomic.Bool
	writeTCP  func(*stack.PacketBuffer) error
}

// Native TUN writes consume packet slices synchronously. Keep the stack's
// reference through the callback instead of cloning it into a goroutine queue.
// Non-native access adapters retain channel's existing queued output.
func (l *accessLink) WritePackets(packets stack.PacketBufferList) (int, tcpip.Error) {
	if l.writeTCP == nil {
		return l.Endpoint.WritePackets(packets)
	}
	for i, packet := range packets.AsSlice() {
		if l.closed.Load() {
			return i, &tcpip.ErrClosedForSend{}
		}
		if err := l.writeTCP(packet); err != nil {
			return i, &tcpip.ErrNoBufferSpace{}
		}
	}
	return packets.Len(), nil
}

func (l *accessLink) Close() {
	l.closed.Store(true)
	l.Endpoint.Close()
}

func (l *accessLink) Capabilities() stack.LinkEndpointCapabilities {
	capabilities := l.Endpoint.Capabilities()
	if l.validated.Load() {
		capabilities |= stack.CapabilityRXChecksumOffload
	}
	return capabilities
}

func (l *accessLink) GSOMaxSize() uint32 {
	if l.Endpoint.SupportedGSO() == stack.HostGSOSupported {
		// Native TUN admits/writes complete IP packets up to 65535 bytes.
		// channel's generic 32-KiB limit otherwise splits every large local
		// TCP write despite the kernel's available segmentation capability.
		return 65535
	}
	return l.Endpoint.GSOMaxSize()
}

func (l *accessLink) inject(p *stack.PacketBuffer) {
	l.mu.Lock()
	l.validated.Store(p.RXChecksumValidated)
	l.Endpoint.InjectInbound(p.NetworkProtocolNumber, p)
	l.validated.Store(false)
	l.mu.Unlock()
}

func NewEngine(parent context.Context, mtu int, output func([]byte) error, open func(context.Context, netip.AddrPort, netip.AddrPort) (Conn, error), batches ...func([][]byte) error) (*Engine, error) {
	var batch func([][]byte) error
	if len(batches) > 0 {
		batch = batches[0]
	}
	return newEngine(parent, mtu, output, open, batch, nil)
}

func NewOffloadEngine(parent context.Context, mtu int, output func([]byte) error, open func(context.Context, netip.AddrPort, netip.AddrPort) (Conn, error), outputGSO func(*stack.PacketBuffer) error) (*Engine, error) {
	if outputGSO == nil {
		return nil, errors.New("TCP offload callback is required")
	}
	return newEngine(parent, mtu, output, open, nil, outputGSO)
}

func newEngine(parent context.Context, mtu int, output func([]byte) error, open func(context.Context, netip.AddrPort, netip.AddrPort) (Conn, error), batch func([][]byte) error, outputGSO func(*stack.PacketBuffer) error) (*Engine, error) {
	if output == nil || open == nil {
		return nil, errors.New("TCP callbacks are required")
	}
	ctx, cancel := context.WithCancel(parent)
	e := &Engine{ctx: ctx, cancel: cancel, output: output, outputBatch: batch, open: open, slots: make(chan struct{}, MaxConnections)}
	e.stack = stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol}})
	// Access TCP remains on the local host. gVisor's SACK recovery can count
	// stale, out-of-window segments as pipe after a receiver shrinks its window,
	// preventing progress until each subsequent RTO. Use standard NewReno on
	// this local adapter; graph byte sockets retain the operating system stack.
	sack := tcpip.TCPSACKEnabled(false)
	if err := e.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		cancel()
		e.stack.Close()
		return nil, errors.New(err.String())
	}
	// With SACK off, RACK cannot run and its flag also suppresses the
	// NewReno recovery branch. Select the matching loss-recovery algorithm
	// explicitly so duplicate ACKs can retransmit before the next RTO.
	recovery := tcpip.TCPRecovery(0)
	if err := e.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &recovery); err != nil {
		cancel()
		e.stack.Close()
		return nil, errors.New(err.String())
	}
	// This is a host-local TCP adapter, with the same transmit working set as
	// sing-tun's local stack. A WAN-sized queue can leave megabytes awaiting ACK
	// after the application receiver shrinks its window.
	sendBuffer := tcpip.TCPSendBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: 32 << 10, Max: 128 << 10}
	if err := e.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sendBuffer); err != nil {
		cancel()
		e.stack.Close()
		return nil, errors.New(err.String())
	}
	e.link = channel.New(accessPacketQueue, uint32(mtu), "")
	e.ingress = &accessLink{Endpoint: e.link, writeTCP: outputGSO}
	if outputGSO != nil {
		e.link.SupportedGSOKind = stack.HostGSOSupported
	}
	if err := e.stack.CreateNIC(1, e.ingress); err != nil {
		cancel()
		e.link.Close()
		e.stack.Close()
		return nil, errors.New(err.String())
	}
	e.stack.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	e.stack.SetSpoofing(1, true)
	e.stack.SetPromiscuousMode(1, true)
	e.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(e.stack, 0, MaxConnections, e.forward).HandlePacket)
	if outputGSO == nil {
		e.wg.Add(1)
		go e.writePackets()
	}
	return e, nil
}

func (e *Engine) forward(request *tcp.ForwarderRequest) {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		request.Complete(true)
		return
	}
	select {
	case e.slots <- struct{}{}:
	default:
		e.mu.Unlock()
		request.Complete(true)
		return
	}
	e.wg.Add(1)
	e.mu.Unlock()
	defer e.wg.Done()
	defer func() { <-e.slots }()
	id := request.ID()
	from, to := netip.AddrPortFrom(addr(id.RemoteAddress), id.RemotePort), netip.AddrPortFrom(addr(id.LocalAddress), id.LocalPort)
	e.flow(from, to, true)
	defer e.flow(from, to, false)
	ctx, cancel := context.WithTimeout(e.ctx, ConnectTimeout)
	remote, err := e.open(ctx, from, to)
	cancel()
	if err != nil {
		request.Complete(true)
		return
	}
	defer remote.Close()
	var queue waiter.Queue
	endpoint, tcpErr := request.CreateEndpoint(&queue)
	request.Complete(tcpErr != nil)
	if tcpErr != nil {
		return
	}
	local := &accessConn{TCPConn: gonet.NewTCPConn(&queue, endpoint), endpoint: endpoint, queue: &queue}
	Relay(e.ctx, local, remote)
}

func addr(a tcpip.Address) netip.Addr {
	if a.Len() == 4 {
		return netip.AddrFrom4(a.As4())
	}
	return netip.AddrFrom16(a.As16())
}
func tcpAddr(a netip.Addr) tcpip.Address {
	if a.Is4() {
		return tcpip.AddrFrom4(a.As4())
	}
	return tcpip.AddrFrom16(a.As16())
}

func (e *Engine) Inject(raw []byte) {
	protocol := ipv4.ProtocolNumber
	if raw[0]>>4 == 6 {
		protocol = ipv6.ProtocolNumber
	}
	// MakeWithData copies synchronously into an owned gVisor chunk. The TUN
	// reader can immediately reuse raw; an intermediate heap copy adds no owner.
	p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
	p.NetworkProtocolNumber = protocol
	e.InjectOwned(p)
}

// InjectOwned consumes the reader's packet reference. Its storage and checksum
// state already belong to the stack, so asynchronous TCP processing is safe.
func (e *Engine) InjectOwned(p *stack.PacketBuffer) {
	e.ingress.inject(p)
	p.DecRef()
}
func (e *Engine) SetMTU(mtu int) { e.link.SetMTU(uint32(mtu)) }

// Dial preserves the access TCP tuple, including for subnet and WireGuard
// destinations. Endpoint cleanup covers cancellation, bind and connect failures.
func (e *Engine) Dial(ctx context.Context, from, to netip.AddrPort) (Conn, error) {
	protocol := ipv4.ProtocolNumber
	if to.Addr().Is6() {
		protocol = ipv6.ProtocolNumber
	}
	var queue waiter.Queue
	endpoint, err := e.stack.NewEndpoint(tcp.ProtocolNumber, protocol, &queue)
	if err != nil {
		return nil, errors.New(err.String())
	}
	connected := false
	defer func() {
		if !connected {
			endpoint.Close()
		}
	}()
	entry, ready := waiter.NewChannelEntry(waiter.WritableEvents)
	queue.EventRegister(&entry)
	defer queue.EventUnregister(&entry)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err = endpoint.Bind(tcpip.FullAddress{NIC: 1, Addr: tcpAddr(from.Addr()), Port: from.Port()}); err != nil {
		return nil, errors.New(err.String())
	}
	err = endpoint.Connect(tcpip.FullAddress{NIC: 1, Addr: tcpAddr(to.Addr()), Port: to.Port()})
	if _, started := err.(*tcpip.ErrConnectStarted); started {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ready:
		}
		err = endpoint.LastError()
	}
	if err != nil {
		return nil, fmt.Errorf("connect TCP target: %s", err.String())
	}
	connected = true
	return &accessConn{TCPConn: gonet.NewTCPConn(&queue, endpoint), endpoint: endpoint, queue: &queue}, nil
}

type accessConn struct {
	*gonet.TCPConn
	endpoint tcpip.Endpoint
	queue    *waiter.Queue
}

func (c *accessConn) Abort() {
	if endpoint, ok := c.endpoint.(interface{ Abort() }); ok {
		endpoint.Abort()
	}
}

func (e *Engine) writePackets() {
	defer e.wg.Done()
	var views [packetbuf.BatchSize]*buffer.View
	var packets [packetbuf.BatchSize][]byte
	for {
		p := e.link.ReadContext(e.ctx)
		if p == nil {
			return
		}
		count := 0
		for {
			// ToView transfers an independent owned view; retain it through the
			// output callback while releasing the packet's queue reference now.
			views[count] = p.ToView()
			packets[count] = views[count].AsSlice()
			p.DecRef()
			count++
			if e.outputBatch == nil || count == len(packets) {
				break
			}
			p = e.link.Read()
			if p == nil {
				break
			}
		}
		if e.outputBatch != nil {
			e.outputBatch(packets[:count])
		} else {
			e.output(packets[0])
		}
		for i := range count {
			views[i].Release()
			views[i], packets[i] = nil, nil
		}
	}
}
func (e *Engine) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	e.cancel()
	e.mu.Unlock()
	e.stack.Close()
	for _, endpoint := range e.stack.CleanupEndpoints() {
		endpoint.Abort()
	}
	e.ingress.Close()
	e.wg.Wait()
	e.stack.Wait()
	return nil
}
