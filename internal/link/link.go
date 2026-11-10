package link

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/packet"
	"github.com/eWloYW8/GraphWAN/internal/packetbuf"
	"github.com/eWloYW8/GraphWAN/internal/peer"
)

const (
	dataMessage    = 1
	pingMessage    = 2
	pongMessage    = 3
	prepareMessage = 4
	acceptMessage  = 5
	commitMessage  = 6
	confirmMessage = 7
	pathMessage    = 8
	retireMessage  = 9
	retiredMessage = 10
	// Stream messages are sent only after the accepting side confirms support:
	// a Link without the capability closes on any message kind it does not know.
	streamHelloMessage = 11
	streamMessage      = 12
	// Link-state advertisements follow the same in-band confirmation.
	linkStateHelloMessage = 13
	linkStateMessage      = 14
	linkStateQueue        = 256
	// Compact data omits the packet header after the same in-band confirmation:
	// [compactDataMessage][hop limit][IP packet]. The receiver rebuilds it.
	compactHelloMessage = 15
	compactDataMessage  = 16
	// The acceptor confirms resumable TCP sessions offered in the
	// introduction; see Options.Resume.
	resumeHelloMessage = 20
	// The acceptor confirms stream windows taken from the kernel's receive
	// buffer, offered in the introduction; see Options.Windows.
	windowHelloMessage = 24
	// A stream message whose data is sealed end to end, which the channel
	// does not encrypt again; see peer.SealedPayload.
	sealedStreamMessage = peer.SealedPayload
	// A compact frame of a packet sealed end to end keeps its source and
	// destination Nodes, which its seal depends on: [compactSealedMessage][hop
	// limit][source][destination][IP packet][trailer]. A frame of such a
	// packet, compact or not, travels in a sealedFrame envelope, whose
	// readable part the channel seals: [peer.SealedPrefix][k][message].
	compactSealedMessage = 22
	sealedFrame          = peer.SealedPrefix
	// Leave room for multiple kernel GSO bursts while writers process bounded
	// batches. The queue is still finite; control messages use a separate queue.
	queueSize = 512
	// TCP-backed links retain at most 256 KiB of queued plaintext frames.
	tcpQueueBytes = 256 * 1024
	// acceptedProbe paces an accepted Link's own RTT samples.
	acceptedProbe = 30 * time.Second
	// pingSize is a ping: its nonce, then the last pong nonce its sender
	// received.
	pingSize = 17
)

var ErrQueueFull = errors.New("link packet queue is full")

// ErrTCPOverTCP refuses TCP packets on a TCP, WS, WSS or gRPC Link: TCP
// crosses those Links only as streams.
var ErrTCPOverTCP = errors.New("TCP packets are not sent on a TCP-backed Link")
var ErrUnavailable = errors.New("edge has no healthy link")

type Channel interface {
	ID() string
	Send(context.Context, []byte) error
	Receive(context.Context) ([]byte, error)
	Close() error
	RemoteAddr() net.Addr
	NeedsRekey() bool
	Created() time.Time
}
type Info struct {
	NetworkID, EdgeID, PeerID model.ID
	CandidateID               string
	Transport                 model.Transport
}
type Options struct {
	// Heartbeat probes every Link at a fixed cadence: Link failure drives
	// route convergence, so idle Links fail as quickly as busy ones.
	Heartbeat, Timeout, WriteTimeout, RenewAfter time.Duration
	// Accepted Links leave liveness probing to the dialer: received pings
	// prove liveness, and own pings only sample RTT every acceptedProbe.
	// The ping format is unchanged, so older peers keep probing as before.
	Accepted bool
	// PathExchange is enabled by the authenticated introduction capability.
	PathExchange bool
	// OwnedPackets opts into explicit packet ownership. Consumers must release
	// every buffer received from ReadOwnedBatch; the legacy Packets API is unused.
	OwnedPackets bool
	// Streams carries byte streams on this Link when both sides support them.
	// The accepting side sets StreamHello and announces support; the dialing
	// side enables streams when that announcement arrives.
	Streams     StreamHandler
	StreamHello bool
	// Resume offers (dialer) or confirms (acceptor) resumable TCP sessions on
	// the streams. The acceptor confirms with a hello message.
	Resume bool
	// Windows offers (dialer) or confirms (acceptor) stream windows that
	// follow the kernel's receive buffer, whose acknowledgements state what
	// the receiver consumed. The acceptor confirms with a hello message.
	Windows bool
	// LinkState carries link-state advertisements; LinkStateHello is set by
	// the accepting side, as for streams. Any transport may carry them.
	LinkState      LinkStateHandler
	LinkStateHello bool
	// Compact rebuilds the packet header of a compact data frame from its inner
	// addresses; it is set when both sides offered the capability. The accepting
	// side sets CompactHello and sends compact frames at once; the dialer only
	// after that announcement arrives. Either side accepts them throughout.
	Compact      CompactHeader
	CompactHello bool
	// SizeProbe holds the Link back from traffic until a full-size probe is
	// answered; see sizeprobe.go. SizeProbeHello is set by the accepting side.
	SizeProbe      bool
	SizeProbeHello bool
	// Failed is called after the Link stopped, so routes leave it without
	// waiting to poll it. It must not block.
	Failed func()
}

// CompactHeader writes the omitted packet header into header[:packet.HeaderSize]
// for payload, or reports that its addresses have no admitted owners.
type CompactHeader func(header []byte, network [16]byte, hopLimit uint8, payload []byte) bool

// LinkStateHandler receives advertisements; payload is only valid during the call.
type LinkStateHandler interface {
	LinkStateReady(*Link)
	ReceiveLinkState(*Link, []byte)
}

// StreamHandler owns stream state for every Link of one Edge. Frames returned by
// PullStream start with the stream message kind and must not be modified later;
// the Link releases each frame's owner, if any, once it sent the frame.
type StreamHandler interface {
	StreamsReady(*Link)
	// ReceiveStream may keep raw beyond the call only as an owner of its
	// buffer (nil when raw is not pooled).
	ReceiveStream(*Link, []byte, *packetbuf.Buffer) bool
	PullStream(*Link, [][]byte, []*packetbuf.Buffer) int
}

func (o Options) defaults() Options {
	if o.Heartbeat <= 0 {
		o.Heartbeat = 2 * time.Second
	}
	if o.Timeout <= 0 {
		o.Timeout = 6 * time.Second
	}
	if o.WriteTimeout <= 0 {
		o.WriteTimeout = 2 * time.Second
	}
	if o.RenewAfter <= 0 {
		o.RenewAfter = 50 * time.Minute
	}
	return o
}

type Link struct {
	channel                       Channel
	info                          Info
	options                       Options
	ctx                           context.Context
	cancel                        context.CancelFunc
	stopOnce                      sync.Once
	wg                            sync.WaitGroup
	done                          chan struct{}
	data                          [queueSize]queuedPacket
	dataHead, dataCount           int
	dataBytes                     int
	dataReady                     chan struct{}
	selection                     chan Selection
	retirements                   chan Retirement
	pathEnabled, pathAcknowledged bool
	observedLocal                 string
	lastPath                      time.Time
	// Odd generations permit data; changing generations invalidates queued data.
	dataGeneration atomic.Uint64
	// loggedActive tracks selection for logs only. New Links start with an
	// active data generation, so it cannot be derived from dataGeneration.
	loggedActive atomic.Bool
	// loggedUp records that "link up" was logged: the Link became healthy.
	// up, set by its Edge, then runs once.
	loggedUp     atomic.Bool
	up           atomic.Pointer[func()]
	control      chan []byte
	packets      chan []byte
	ownedPackets *packetbuf.Queue
	queueMu      sync.Mutex
	mu           sync.Mutex
	pending      map[uint64]time.Time
	nextPing     uint64
	lastPong     time.Time
	lastPing     time.Time
	probeSince   time.Time
	started      time.Time
	peerPing     time.Time
	// A ping carries the nonce of the last pong its sender received. When
	// that grows, the peer has received a newer message from this side:
	// confirmed is the largest such nonce, peerHeard when it last grew, and
	// lastPongNonce what this side's own pings confirm.
	confirmed       uint64
	peerHeard       time.Time
	lastPongNonce   uint64
	lastTraffic     time.Time
	sampledRX       uint64
	sampledTX       uint64
	rtt             time.Duration
	sent, lost      uint64
	rx, tx, dropped atomic.Uint64
	streamsReady    atomic.Bool
	resume          atomic.Bool
	windows         atomic.Bool
	streamWake      chan struct{}
	linkStateReady  atomic.Bool
	linkStateOut    chan []byte
	linkStateLost   atomic.Uint64
	compactOut      atomic.Bool
	networkWire     [16]byte
	// tcpPackets counts TCP packets refused on a TCP-backed Link: TCP over
	// TCP, which access TCP termination exists to prevent.
	tcpPackets atomic.Uint64
	// Size probe state, guarded by mu. The zero value is a verified Link.
	sizeMode     sizeProbeMode
	unverified   bool
	sizeNonce    uint64
	sizeSent     time.Time
	sizeVerified time.Time
	sizeFailed   bool
}

func New(parent context.Context, channel Channel, info Info, options Options) (*Link, error) {
	options = options.defaults()
	if options.Timeout < 2*options.Heartbeat || options.Timeout/options.Heartbeat > 64 {
		return nil, errors.New("link timeout must span 2–64 heartbeats")
	}
	if channel == nil || channel.ID() == "" || info.CandidateID == "" || !info.Transport.Valid() {
		return nil, errors.New("invalid link identity")
	}
	for _, id := range []model.ID{info.NetworkID, info.EdgeID, info.PeerID} {
		if err := id.Validate(); err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithCancel(parent)
	l := &Link{channel: channel, info: info, options: options, ctx: ctx, cancel: cancel, done: make(chan struct{}), dataReady: make(chan struct{}, 1), selection: make(chan Selection, 8), control: make(chan []byte, 8), packets: make(chan []byte, queueSize), pending: map[uint64]time.Time{}, started: time.Now()}
	l.pathEnabled = options.PathExchange
	l.retirements = make(chan Retirement, 8)
	l.streamWake = make(chan struct{}, 1)
	l.linkStateOut = make(chan []byte, linkStateQueue)
	if _, ok := channel.(interface {
		ReceiveOwnedBatch(context.Context) ([]*packetbuf.Buffer, error)
	}); ok && options.OwnedPackets {
		l.ownedPackets = packetbuf.NewQueue(queueSize)
	}
	l.dataGeneration.Store(1)
	// The size-probe hello must precede every other message; see sizeprobe.go.
	l.initSizeProbe()
	if options.Windows && options.Accepted {
		// Before the streams' announcement: the dialer knows the windows'
		// format before it sends a stream frame.
		l.control <- []byte{windowHelloMessage, 1}
		l.windows.Store(true)
	}
	if options.Streams != nil && options.StreamHello && l.tcpBacked() {
		// The queue is empty here, so the announcement precedes every stream frame.
		l.control <- []byte{streamHelloMessage, 1}
		l.streamsReady.Store(true)
	}
	if options.Resume && options.Accepted {
		l.control <- []byte{resumeHelloMessage, 1}
		l.resume.Store(true)
	}
	if options.LinkState != nil && options.LinkStateHello {
		l.control <- []byte{linkStateHelloMessage, 1}
		l.linkStateReady.Store(true)
	}
	if options.Compact != nil {
		if _, err := hex.Decode(l.networkWire[:], []byte(info.NetworkID)); err != nil {
			cancel()
			return nil, err
		}
		if options.CompactHello {
			// The dialer offered compact frames, so it already accepts them.
			l.control <- []byte{compactHelloMessage, 1}
			l.compactOut.Store(true)
		}
	}
	l.wg.Add(3)
	go l.readLoop()
	go l.writeLoop()
	go l.healthLoop()
	if l.streamsReady.Load() {
		options.Streams.StreamsReady(l)
	}
	if l.linkStateReady.Load() {
		options.LinkState.LinkStateReady(l)
	}
	go func() {
		l.wg.Wait()
		close(l.packets)
		if l.ownedPackets != nil {
			l.ownedPackets.Close()
		}
		close(l.done)
	}()
	return l, nil
}

type queuedPacket struct {
	generation uint64
	raw        []byte
	buffer     *packetbuf.Buffer
}

// Selection messages are delivered separately so overlay backpressure cannot
// block negotiation. The sender retries dropped control messages.
func (l *Link) Selections() <-chan Selection { return l.selection }
func (l *Link) setActive(active bool) {
	generation := l.dataGeneration.Load()
	if (generation%2 == 1) != active {
		l.dataGeneration.Add(1)
	}
	if l.loggedActive.Swap(active) != active {
		if active {
			slog.Info("link selected", l.logAttrs()...)
		} else {
			slog.Info("link deselected", l.logAttrs()...)
		}
	}
}

// logAttrs identifies the Link in health and selection logs.
func (l *Link) logAttrs(extra ...any) []any {
	attrs := []any{"peer", l.info.PeerID, "edge", l.info.EdgeID, "candidate", l.info.CandidateID, "transport", l.info.Transport}
	if l.channel != nil {
		if remote := l.channel.RemoteAddr(); remote != nil {
			attrs = append(attrs, "remote", remote.String())
		}
		attrs = append(attrs, "link", l.ID())
	}
	return append(attrs, extra...)
}
func (l *Link) ID() string         { return l.channel.ID() }
func (l *Link) StreamsReady() bool { return l.streamsReady.Load() }

// Resume reports whether both ends carry resumable TCP sessions.
func (l *Link) Resume() bool { return l.resume.Load() }

// Windows reports whether both sides take stream windows from the kernel's
// receive buffer.
func (l *Link) Windows() bool { return l.windows.Load() }

// ReceiveWindow reports the kernel's receive buffer of this Link's
// connection, when its transport is a kernel TCP socket.
func (l *Link) ReceiveWindow() (int, bool) {
	if c, ok := l.channel.(interface{ ReceiveWindow() (int, bool) }); ok {
		return c.ReceiveWindow()
	}
	return 0, false
}

func (l *Link) LinkStateReady() bool { return l.linkStateReady.Load() }

// LinkStateLost counts advertisements dropped by a full send queue; the
// origin's periodic refresh repairs them.
func (l *Link) LinkStateLost() uint64 { return l.linkStateLost.Load() }

// SendLinkState queues one advertisement without blocking.
func (l *Link) SendLinkState(payload []byte) bool {
	if !l.linkStateReady.Load() || len(payload)+1 > packet.MaxFrame {
		return false
	}
	select {
	case l.linkStateOut <- append([]byte{linkStateMessage}, payload...):
		return true
	default:
		l.linkStateLost.Add(1)
		return false
	}
}

// WakeStreams asks the writer to pull stream frames. It never blocks.
func (l *Link) WakeStreams() {
	select {
	case l.streamWake <- struct{}{}:
	default:
	}
}
func (l *Link) Info() Info             { return l.info }
func (l *Link) Packets() <-chan []byte { return l.packets }
func (l *Link) Done() <-chan struct{}  { return l.done }
func (l *Link) Created() time.Time     { return l.channel.Created() }
func (l *Link) RenewalDue() bool       { return time.Since(l.channel.Created()) >= l.options.RenewAfter }
func (l *Link) stop() {
	l.stopOnce.Do(func() { l.queueMu.Lock(); l.cancel(); l.queueMu.Unlock(); l.channel.Close() })
}
func (l *Link) Close() error {
	l.stop()
	<-l.done
	return nil
}
func (l *Link) ReadOwnedBatch(ctx context.Context, dst []*packetbuf.Buffer) (int, error) {
	if l.ownedPackets == nil {
		return 0, errors.New("owned packet receive is not enabled")
	}
	return l.ownedPackets.Read(ctx, dst)
}
func (l *Link) Send(ctx context.Context, frame []byte) error {
	return l.SendBatch(ctx, [][]byte{frame})
}

// SendBatch copies and publishes a burst under one lock, preventing the writer
// from breaking a producer's burst into tiny batches. Capacity remains packets.
func (l *Link) SendBatch(ctx context.Context, frames [][]byte) error {
	return l.enqueue(ctx, frames, nil)
}

// SendOwnedBatch consumes every buffer, including on cancellation or overflow.
func (l *Link) SendOwnedBatch(ctx context.Context, buffers []*packetbuf.Buffer) error {
	if len(buffers) > 128 {
		packetbuf.ReleaseAll(buffers)
		return errors.New("invalid overlay batch size")
	}
	var frames [128][]byte
	for i, b := range buffers {
		if b != nil {
			frames[i] = b.Data
		}
	}
	return l.enqueue(ctx, frames[:len(buffers)], buffers)
}

func (l *Link) enqueue(ctx context.Context, frames [][]byte, owners []*packetbuf.Buffer) error {
	accepted, refused, consumed := 0, 0, 0
	defer func() {
		if owners != nil {
			packetbuf.ReleaseAll(owners[consumed:])
		}
	}()
	if len(frames) == 0 || len(frames) > 128 {
		return errors.New("invalid overlay batch size")
	}
	for _, frame := range frames {
		if len(frame) <= packet.HeaderSize || len(frame) > packet.MaxFrame {
			return errors.New("invalid overlay frame size")
		}
	}
	l.queueMu.Lock()
	defer l.queueMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if l.ctx.Err() != nil {
		return net.ErrClosed
	}
	generation := l.dataGeneration.Load()
	if generation%2 == 0 {
		return ErrUnavailable
	}
	limit := min(len(frames), len(l.data)-l.dataCount)
	tcpBacked := l.tcpBacked()
	for i, frame := range frames[:limit] {
		if tcpBacked && packet.IsTCP(frame[packet.HeaderSize:]) {
			l.tcpPackets.Add(1)
			if owners != nil {
				owners[i].Release()
			}
			refused, consumed = refused+1, i+1
			continue
		}
		if tcpBacked && l.dataBytes+len(frame)+1 > tcpQueueBytes {
			break
		}
		var buffer *packetbuf.Buffer
		if packet.IsSealed(frame) {
			buffer = sealedFrameOf(frame, owners, i, l.compactOut.Load())
		} else if l.compactOut.Load() {
			buffer = compactFrame(frame, owners, i)
		} else if owners != nil && owners[i].PrependByte(dataMessage) {
			buffer = owners[i]
		} else {
			buffer = packetbuf.Get(len(frame) + 1)
			buffer.Data[0] = dataMessage
			copy(buffer.Data[1:], frame)
			if owners != nil {
				owners[i].Release()
			}
		}
		l.data[(l.dataHead+l.dataCount)%len(l.data)] = queuedPacket{generation: generation, raw: buffer.Data, buffer: buffer}
		l.dataCount++
		l.dataBytes += len(buffer.Data)
		accepted, consumed = accepted+1, i+1
	}
	if l.dataCount > 0 {
		l.notifyData()
	}
	if accepted+refused != len(frames) {
		l.dropped.Add(uint64(len(frames) - accepted - refused))
		return ErrQueueFull
	}
	if refused > 0 {
		return ErrTCPOverTCP
	}
	return nil
}

// compactFrame replaces the packet header with the two-byte compact prefix,
// in place for an owned buffer; frame[3] is the overlay hop limit.
func compactFrame(frame []byte, owners []*packetbuf.Buffer, i int) *packetbuf.Buffer {
	if owners != nil {
		buffer := owners[i]
		buffer.Data[packet.HeaderSize-2] = compactDataMessage
		buffer.Data[packet.HeaderSize-1] = frame[3]
		buffer.Data = buffer.Data[packet.HeaderSize-2:]
		return buffer
	}
	buffer := packetbuf.Get(len(frame) - packet.HeaderSize + 2)
	buffer.Data[0], buffer.Data[1] = compactDataMessage, frame[3]
	copy(buffer.Data[2:], frame[packet.HeaderSize:])
	return buffer
}

// sealedFrameOf wraps the frame of a sealed packet in its envelope, in place
// for an owned buffer with the headroom; the channel seals the envelope, the
// message's kind, the packet header or hop limit, and the readable headers.
func sealedFrameOf(frame []byte, owners []*packetbuf.Buffer, i int, compact bool) *packetbuf.Buffer {
	readable := packet.HeaderLen(frame[packet.HeaderSize : len(frame)-packet.Trailer])
	var buffer *packetbuf.Buffer
	if compact {
		const prefix = 4 + 32
		hop := frame[3]
		if owners != nil {
			// The destination moves first: the source's new place covers it.
			buffer = owners[i]
			buffer.Data = buffer.Data[packet.HeaderSize-prefix:]
			copy(buffer.Data[20:36], frame[40:56])
			copy(buffer.Data[4:20], frame[24:40])
		} else {
			buffer = packetbuf.Get(len(frame) - packet.HeaderSize + prefix)
			copy(buffer.Data[4:20], frame[24:40])
			copy(buffer.Data[20:36], frame[40:56])
			copy(buffer.Data[prefix:], frame[packet.HeaderSize:])
		}
		buffer.Data[2], buffer.Data[3] = compactSealedMessage, hop
		readable += prefix
	} else {
		if owners != nil && owners[i].PrependByte(dataMessage) && owners[i].PrependByte(0) && owners[i].PrependByte(sealedFrame) {
			buffer = owners[i]
		} else {
			buffer = packetbuf.Get(len(frame) + 3)
			buffer.Data[2] = dataMessage
			copy(buffer.Data[3:], frame)
			if owners != nil {
				owners[i].Release()
			}
		}
		readable += 3 + packet.HeaderSize
	}
	buffer.Data[0], buffer.Data[1] = sealedFrame, byte(readable)
	return buffer
}

// TCPBacked reports a TCP, WS, WSS or gRPC Link.
func (l *Link) TCPBacked() bool { return l.tcpBacked() }

func (l *Link) tcpBacked() bool {
	switch l.info.Transport {
	case model.TCP, model.WS, model.WSS, model.GRPC:
		return true
	default:
		return false
	}
}

func (l *Link) notifyData() {
	select {
	case l.dataReady <- struct{}{}:
	default:
	}
}

// takeData is called with queueMu held, which also fences shutdown and enqueue.
func (l *Link) takeData() queuedPacket {
	data := l.data[l.dataHead]
	l.data[l.dataHead] = queuedPacket{}
	l.dataHead = (l.dataHead + 1) % len(l.data)
	l.dataCount--
	l.dataBytes -= len(data.raw)
	return data
}
func (l *Link) healthy() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.healthyLocked(time.Now())
}

// Healthy avoids allocating formatted telemetry during connection maintenance.
func (l *Link) Healthy() bool { return l.healthy() }

// heardLocked is when this side last sent a message that the peer confirmed
// receiving, or when the Link started.
func (l *Link) heardLocked() time.Time {
	if l.peerHeard.After(l.started) {
		return l.peerHeard
	}
	return l.started
}

func (l *Link) healthyLocked(now time.Time) bool {
	if l.ctx.Err() != nil || l.unverified {
		return false
	}
	if l.options.Accepted {
		return !l.peerPing.IsZero() && now.Sub(l.peerPing) < l.options.Timeout && now.Sub(l.heardLocked()) < l.options.Timeout
	}
	return !l.lastPong.IsZero() && (l.probeSince.IsZero() || now.Sub(l.probeSince) < l.options.Timeout)
}
func (l *Link) Stats() model.LinkStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	healthy := l.healthyLocked(time.Now())
	loss := float64(0)
	if l.sent > 0 {
		loss = float64(l.lost) / float64(l.sent)
	}
	local := ""
	if channel, ok := l.channel.(interface{ LocalAddr() net.Addr }); ok && channel.LocalAddr() != nil {
		local = channel.LocalAddr().String()
	}
	return model.LinkStatus{NetworkID: l.info.NetworkID, EdgeID: l.info.EdgeID, LinkID: l.ID(), CandidateID: l.info.CandidateID, Transport: l.info.Transport, Local: local, ObservedLocal: l.observedLocal, Remote: l.channel.RemoteAddr().String(), Healthy: healthy, RTTMillis: float64(l.rtt) / float64(time.Millisecond), Loss: loss, RXBytes: l.rx.Load(), TXBytes: l.tx.Load(), Dropped: l.dropped.Load(), TCPPackets: l.tcpPackets.Load()}
}
func (l *Link) readLoop() {
	owned, owning := l.channel.(interface {
		ReceiveOwnedBatch(context.Context) ([]*packetbuf.Buffer, error)
	})
	var ownedPending []*packetbuf.Buffer
	var current *packetbuf.Buffer
	var ready [packetbuf.BatchSize]*packetbuf.Buffer
	count := 0
	flush := func() {
		if count == 0 {
			return
		}
		l.dropped.Add(uint64(l.ownedPackets.Put(ready[:count])))
		clear(ready[:count])
		count = 0
	}
	owning = owning && l.ownedPackets != nil
	batch, batching := l.channel.(interface {
		ReceiveBatch(context.Context) ([][]byte, error)
	})
	var pending [][]byte
	defer l.wg.Done()
	defer func() { current.Release(); packetbuf.ReleaseAll(ownedPending); packetbuf.ReleaseAll(ready[:count]) }()
	defer l.stop()
	for {
		var raw []byte
		var err error
		current.Release()
		current = nil
		if owning {
			if len(ownedPending) == 0 {
				flush()
				ownedPending, err = owned.ReceiveOwnedBatch(l.ctx)
			}
			if err != nil || len(ownedPending) == 0 {
				return
			}
			current, ownedPending[0] = ownedPending[0], nil
			ownedPending = ownedPending[1:]
			raw = current.Data
		} else if batching {
			if len(pending) == 0 {
				pending, err = batch.ReceiveBatch(l.ctx)
			}
			if err != nil || len(pending) == 0 {
				return
			}
			raw, pending[0] = pending[0], nil
			pending = pending[1:]
		} else {
			raw, err = l.channel.Receive(l.ctx)
		}
		if err != nil {
			return
		}
		if len(raw) == 0 {
			return
		}
		if raw[0] == sealedFrame {
			if len(raw) < 3 || raw[2] != dataMessage && raw[2] != compactSealedMessage {
				return
			}
			raw = raw[2:]
		}
		switch raw[0] {
		case pathMessage, retireMessage, retiredMessage:
			if !l.handlePathControl(raw) {
				return
			}
		case dataMessage:
			if len(raw) <= packet.HeaderSize+1 || len(raw) > packet.MaxFrame+1 {
				return
			}
			l.rx.Add(uint64(len(raw) - 1))
			if current != nil {
				current.Data = raw
				current.Advance(1)
				ready[count], current = current, nil
				count++
				if count == len(ready) {
					flush()
				}
			} else {
				select {
				case l.packets <- raw[1:]:
				default:
					l.dropped.Add(1)
				}
			}
		case compactHelloMessage:
			if len(raw) != 2 || l.options.Compact == nil || l.options.CompactHello {
				return
			}
			l.sizeProbeUnsupported()
			l.compactOut.Store(true)
		case compactSealedMessage:
			const prefix = 2 + 32
			if len(raw) <= prefix || len(raw)-prefix > packet.MaxPayload {
				return
			}
			var buffer *packetbuf.Buffer
			if owning {
				buffer = packetbuf.Get(packet.HeaderSize + len(raw) - prefix)
			} else {
				buffer = packetbuf.Wrap(make([]byte, packet.HeaderSize+len(raw)-prefix))
			}
			packet.PutHeader(buffer.Data, l.networkWire, [16]byte(raw[2:18]), [16]byte(raw[18:34]), raw[1], len(raw)-prefix)
			packet.SetSealed(buffer.Data, true)
			copy(buffer.Data[packet.HeaderSize:], raw[prefix:])
			l.rx.Add(uint64(len(buffer.Data)))
			if owning {
				ready[count] = buffer
				count++
				if count == len(ready) {
					flush()
				}
				continue
			}
			select {
			case l.packets <- buffer.Data:
			default:
				l.dropped.Add(1)
			}
		case compactDataMessage:
			if l.options.Compact == nil || len(raw) <= 2 || len(raw)-2 > packet.MaxPayload {
				return
			}
			// Owned receivers release pooled buffers; packets channel readers keep
			// their frames, which therefore need their own allocation.
			var buffer *packetbuf.Buffer
			if owning {
				buffer = packetbuf.Get(packet.HeaderSize + len(raw) - 2)
			} else {
				buffer = packetbuf.Wrap(make([]byte, packet.HeaderSize+len(raw)-2))
			}
			if !l.options.Compact(buffer.Data[:packet.HeaderSize], l.networkWire, raw[1], raw[2:]) {
				buffer.Release()
				l.dropped.Add(1)
				continue
			}
			copy(buffer.Data[packet.HeaderSize:], raw[2:])
			l.rx.Add(uint64(len(buffer.Data)))
			if owning {
				ready[count] = buffer
				count++
				if count == len(ready) {
					flush()
				}
				continue
			}
			select {
			case l.packets <- buffer.Data:
			default:
				l.dropped.Add(1)
			}
		case streamHelloMessage:
			if len(raw) != 2 || l.options.Streams == nil || l.options.StreamHello || !l.tcpBacked() {
				return
			}
			l.sizeProbeUnsupported()
			if !l.streamsReady.Swap(true) {
				l.options.Streams.StreamsReady(l)
			}
		case resumeHelloMessage:
			if len(raw) != 2 || !l.options.Resume || l.options.Accepted {
				return
			}
			l.sizeProbeUnsupported()
			l.resume.Store(true)
		case windowHelloMessage:
			if len(raw) != 2 || !l.options.Windows || l.options.Accepted {
				return
			}
			l.sizeProbeUnsupported()
			l.windows.Store(true)
		case linkStateHelloMessage:
			if len(raw) != 2 || l.options.LinkState == nil || l.options.LinkStateHello {
				return
			}
			l.sizeProbeUnsupported()
			if !l.linkStateReady.Swap(true) {
				l.options.LinkState.LinkStateReady(l)
			}
		case linkStateMessage:
			if !l.linkStateReady.Load() || len(raw) < 2 {
				return
			}
			l.options.LinkState.ReceiveLinkState(l, raw[1:])
		case streamMessage, sealedStreamMessage:
			if !l.streamsReady.Load() {
				return
			}
			l.rx.Add(uint64(len(raw) - 1))
			if !l.options.Streams.ReceiveStream(l, raw[1:], current) {
				return
			}
		case pingMessage:
			if len(raw) != pingSize {
				return
			}
			if !l.receivePing(binary.BigEndian.Uint64(raw[1:9]), binary.BigEndian.Uint64(raw[9:]), time.Now()) {
				continue
			}
			response := append([]byte{}, raw[:9]...)
			response[0] = pongMessage
			select {
			case l.control <- response:
			case <-l.ctx.Done():
				return
			default:
			}
		case prepareMessage, acceptMessage, commitMessage, confirmMessage:
			if len(raw) != 25 {
				return
			}
			message := Selection{kind: raw[0], sequence: binary.BigEndian.Uint64(raw[17:])}
			copy(message.term[:], raw[1:17])
			if message.sequence == 0 || message.term == [16]byte{} {
				return
			}
			select {
			case l.selection <- message:
			default:
			}
		case pongMessage:
			if len(raw) != 9 {
				return
			}
			nonce := binary.BigEndian.Uint64(raw[1:])
			l.sizeProbeUnsupported()
			l.recordPong(nonce, time.Now())
		case sizeProbeHelloMessage:
			if !l.receiveSizeProbeHello(raw) {
				return
			}
		case sizeProbeMessage:
			if !l.answerSizeProbe(raw) {
				return
			}
		case sizeProbeReplyMessage:
			if !l.receiveSizeProbeReply(raw, time.Now()) {
				return
			}
		default:
			return
		}
	}
}
func (l *Link) writeLoop() {
	batch, batching := l.channel.(interface {
		SendBatch(context.Context, [][]byte) error
	})
	var messages [packetbuf.BatchSize][]byte
	var owners [packetbuf.BatchSize]*packetbuf.Buffer
	limit := 1
	if batching {
		limit = len(messages)
	}
	// Alternate stream frames and packets when both are waiting.
	preferStreams := false
	defer l.wg.Done()
	defer func() {
		l.stop()
		packetbuf.ReleaseAll(owners[:])
		l.queueMu.Lock()
		defer l.queueMu.Unlock()
		for l.dataCount > 0 {
			l.takeData().buffer.Release()
		}
	}()
	for {
		count := 0
		// Control traffic has priority at every bounded batch boundary.
		select {
		case messages[0] = <-l.control:
			count = 1
		default:
		}
		if count == 0 {
			select {
			case messages[0] = <-l.linkStateOut:
				count = 1
			default:
			}
		}
		if count == 0 && preferStreams {
			select {
			case <-l.streamWake:
				count = l.pullStreams(messages[:limit], owners[:limit])
			default:
			}
		}
		if count == 0 {
			select {
			case <-l.ctx.Done():
				return
			case messages[0] = <-l.control:
				count = 1
			case messages[0] = <-l.linkStateOut:
				count = 1
			case <-l.streamWake:
				count = l.pullStreams(messages[:limit], owners[:limit])
			case <-l.dataReady:
				l.queueMu.Lock()
				for l.dataCount > 0 && count < limit {
					data := l.takeData()
					if data.generation%2 == 0 || data.generation != l.dataGeneration.Load() {
						l.dropped.Add(1)
						data.buffer.Release()
						continue
					}
					messages[count], owners[count] = data.raw, data.buffer
					count++
				}
				if l.dataCount > 0 {
					l.notifyData()
				}
				l.queueMu.Unlock()
			}
		}
		if count == 0 {
			continue
		}
		preferStreams = len(messages[0]) == 0 || messages[0][0] != streamMessage && messages[0][0] != sealedStreamMessage
		ctx, cancel := context.WithTimeout(l.ctx, l.options.WriteTimeout)
		var err error
		if batching {
			err = batch.SendBatch(ctx, messages[:count])
		} else {
			err = l.channel.Send(ctx, messages[0])
		}
		cancel()
		if err != nil {
			return
		}
		for i, raw := range messages[:count] {
			if raw[0] == sealedFrame {
				raw = raw[2:]
			}
			switch raw[0] {
			case dataMessage, streamMessage, sealedStreamMessage:
				l.tx.Add(uint64(len(raw) - 1))
			case compactDataMessage:
				l.tx.Add(uint64(len(raw) - 2 + packet.HeaderSize))
			case compactSealedMessage:
				l.tx.Add(uint64(len(raw) - 34 + packet.HeaderSize))
			}
			messages[i] = nil
			owners[i].Release()
			owners[i] = nil
		}
	}
}

// streamBatch bounds the stream frames of one write, about the kernel's
// unsent backlog, so a heartbeat waits behind no more than that: on a Link
// that has just taken over a bulk transfer the TCP window is still small, and
// a heartbeat behind a whole batch could outlast the peer's timeout.
const streamBatch = 8

// pullStreams re-arms the wake signal when the handler may hold more frames,
// so packets and control messages still get their turn between batches.
func (l *Link) pullStreams(dst [][]byte, owners []*packetbuf.Buffer) int {
	if !l.streamsReady.Load() {
		return 0
	}
	dst, owners = dst[:min(len(dst), streamBatch)], owners[:min(len(owners), streamBatch)]
	count := l.options.Streams.PullStream(l, dst, owners)
	if count == len(dst) {
		l.WakeStreams()
	}
	return count
}

// healthLoop also wakes at the health deadline, so a Link closes as soon as it
// stops being healthy. Waiting for the next heartbeat let a late reply revive a
// Link that selection had already dropped.
func (l *Link) healthLoop() {
	defer l.wg.Done()
	defer l.failed()
	defer l.stop()
	now := time.Now()
	next := now
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		if !l.heartbeat(now) {
			l.logDown(l.failureReason())
			return
		}
		if l.channel.NeedsRekey() {
			l.logDown("rekey")
			return
		}
		for !next.After(now) {
			next = next.Add(l.options.Heartbeat)
		}
		wake := next
		l.mu.Lock()
		if deadline := l.deadlineLocked(); !deadline.IsZero() && deadline.Before(wake) {
			wake = deadline
		}
		l.mu.Unlock()
		timer.Reset(max(time.Until(wake), 0))
		select {
		case <-l.ctx.Done():
			l.logDown("closed")
			return
		case now = <-timer.C:
		}
	}
}

// deadlineLocked is the earliest time at which heartbeat reports failure, or
// zero when no response is awaited.
func (l *Link) deadlineLocked() time.Time {
	var deadline time.Time
	earliest := func(t time.Time) {
		if deadline.IsZero() || t.Before(deadline) {
			deadline = t
		}
	}
	if !l.probeSince.IsZero() {
		earliest(l.probeSince.Add(l.options.Timeout))
	}
	if l.options.Accepted {
		heard := l.started
		if l.peerPing.After(heard) {
			heard = l.peerPing
		}
		earliest(heard.Add(l.options.Timeout))
	}
	if l.sizeMode == sizeProbeOn && !l.sizeSent.IsZero() {
		earliest(l.sizeSent.Add(l.options.Timeout))
	}
	return deadline
}

// expiredLocked reports a Link past its health deadline. Responses arriving
// then are ignored: the Link is closing and must not become healthy again.
func (l *Link) expiredLocked(now time.Time) bool {
	deadline := l.deadlineLocked()
	return !deadline.IsZero() && !now.Before(deadline)
}

func (l *Link) logDown(reason string) {
	wasUp := l.loggedUp.Load()
	slog.Info("link down", l.logAttrs("reason", reason, "was_up", wasUp, "age", time.Since(l.started).Round(time.Second).String(), "rx_bytes", l.rx.Load(), "tx_bytes", l.tx.Load())...)
}

// receivePing records a peer's ping, which is answered unless the Link
// expired: an accepted Link's liveness, and when the ping confirms a newer
// pong of this side's, that this side's messages arrive.
func (l *Link) receivePing(nonce, confirmed uint64, now time.Time) bool {
	l.mu.Lock()
	if l.expiredLocked(now) {
		l.mu.Unlock()
		return false
	}
	if confirmed > l.confirmed {
		l.confirmed, l.peerHeard = confirmed, now
	}
	first := l.options.Accepted && l.peerPing.IsZero() && !l.unverified
	if l.options.Accepted {
		l.peerPing = now
	}
	l.mu.Unlock()
	if first {
		l.logUp()
	}
	return true
}

func (l *Link) recordPong(nonce uint64, now time.Time) {
	l.mu.Lock()
	sent, ok := l.pending[nonce]
	if !ok || l.expiredLocked(now) {
		l.mu.Unlock()
		return
	}
	l.lastPongNonce = max(l.lastPongNonce, nonce)
	first := l.lastPong.IsZero() && !l.options.Accepted && !l.unverified
	sample := now.Sub(sent)
	if l.rtt == 0 {
		l.rtt = sample
	} else {
		l.rtt = (l.rtt*4 + sample) / 5
	}
	l.lastPong, l.probeSince = now, time.Time{}
	delete(l.pending, nonce)
	l.mu.Unlock()
	// Log outside the lock so probing and selection are not delayed.
	if first {
		l.logUp("rtt_ms", sample.Milliseconds())
	}
}

// logUp logs "link up" once, when the Link first becomes healthy: on its first
// ping exchange, or for a size-probed Link once its probe is also answered.
func (l *Link) logUp(attrs ...any) {
	if l.loggedUp.CompareAndSwap(false, true) {
		slog.Info("link up", l.logAttrs(attrs...)...)
		if up := l.up.Load(); up != nil {
			(*up)()
		}
	}
}

func (l *Link) failed() {
	if l.options.Failed != nil {
		l.options.Failed()
	}
}

// Sample user-byte counters during maintenance/selection, not on the packet
// hot path. Control messages and keepalives do not extend the activity window.
func (l *Link) sampleTrafficLocked(now time.Time) {
	rx, tx := l.rx.Load(), l.tx.Load()
	if rx != l.sampledRX || tx != l.sampledTX {
		l.lastTraffic = now
		l.sampledRX, l.sampledTX = rx, tx
	}
}

func (l *Link) recentlyActive(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sampleTrafficLocked(now)
	return !l.lastTraffic.IsZero() && now.Sub(l.lastTraffic) < 5*time.Second
}

// Only the health worker calls heartbeat. Sampling existing user-byte counters
// avoids adding clocks or synchronization to the packet forwarding hot path.
func (l *Link) heartbeat(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pathEnabled && !l.pathAcknowledged && now.Sub(l.lastPath) >= time.Second {
		l.sendPathLocked()
		l.lastPath = now
	}
	for seq, sent := range l.pending {
		if now.Sub(sent) >= l.options.Timeout {
			delete(l.pending, seq)
			l.lost++
		}
	}
	if !l.probeSince.IsZero() && now.Sub(l.probeSince) >= l.options.Timeout {
		return false
	}
	if !l.sizeProbeLocked(now) {
		return false
	}
	interval := l.options.Heartbeat
	if l.options.Accepted {
		heard := l.started
		if l.peerPing.After(heard) {
			heard = l.peerPing
		}
		// Both directions must work: the dialer's pings arrive, and they
		// confirm that this side's pongs arrive too.
		if now.Sub(heard) >= l.options.Timeout || now.Sub(l.heardLocked()) >= l.options.Timeout {
			return false
		}
		interval = acceptedProbe
	}
	// Keeps lastTraffic current for selection hysteresis (recentlyActive).
	l.sampleTrafficLocked(now)
	if !l.lastPing.IsZero() && now.Sub(l.lastPing) < interval {
		return true
	}
	l.nextPing++
	raw := make([]byte, pingSize)
	raw[0] = pingMessage
	binary.BigEndian.PutUint64(raw[1:], l.nextPing)
	binary.BigEndian.PutUint64(raw[9:], l.lastPongNonce)
	select {
	case l.control <- raw:
		l.pending[l.nextPing] = now
		l.lastPing = now
		if l.probeSince.IsZero() {
			l.probeSince = now
		}
		l.sent++
	default:
	}
	return true
}
