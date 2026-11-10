package mesh

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/link"
	"github.com/eWloYW8/GraphWAN/internal/packetbuf"
	"github.com/eWloYW8/GraphWAN/internal/peer"
	"github.com/eWloYW8/GraphWAN/internal/secure"
	"github.com/eWloYW8/GraphWAN/internal/streamproxy"
)

// Stream frames share an Edge's existing Links with packets. A stream belongs
// to the Edge, not to one Link: data carries byte offsets, the receiver
// acknowledges contiguous bytes, and unacknowledged frames are sent again when
// the Edge moves streams to another Link (failure, renewal or rekey).
const (
	muxData      = 1
	muxAck       = 2
	muxReset     = 3
	muxWindowAck = 4

	muxFin = 1
	// With muxFin on a TCP session hop: the session's direction ended. Session
	// hops are torn down by resets, so their FINs always carry it.
	muxEnd = 2
	// On every data frame of a stream whose windows follow the kernel's
	// receive buffer: its receiver starts it so, and both ends acknowledge
	// with muxWindowAck.
	muxWindowed = 4

	// link kind + frame type + stream ID
	muxHeader     = 1 + 1 + 8
	muxDataHeader = muxHeader + 8 + 1
	muxAckSize    = muxHeader + 8 + 8
	muxMaxData    = secure.MaxPlaintext - muxDataHeader
	// A TCP session relay's acknowledgements add the far end's delivered
	// offset; a session reset adds whether it resets the connection.
	muxSessionAckSize = muxAckSize + 8
	// A windowed stream's acknowledgement also states what the receiver
	// consumed, since its window varies: [received][limit][consumed], and a
	// session relay's adds [delivered].
	muxWindowAckSize        = muxAckSize + 8
	muxWindowSessionAckSize = muxWindowAckSize + 8
	muxAbortSize            = muxHeader + 1

	// The receive window of a stream without windowed acknowledgements, or on
	// a Link whose kernel receive buffer is unknown: one stream at 3 Gbit/s
	// over 80 ms.
	muxWindow = 32 << 20
	// A windowed stream's credit before its first acknowledgement.
	muxInitialWindow = 256 << 10
	// A windowed stream that consumed nothing this long stopped: it keeps its
	// credit but no longer shares the Link's buffer.
	muxIdle         = time.Second
	muxAckThreshold = 256 << 10
	// Frames handed to one Link writer per stream before others get a turn.
	muxBurst = 16
	// Streams wait this long for an Edge to regain a stream-capable Link.
	muxLinkLoss = 30 * time.Second
	// A TCP session hop whose sent frames see no acknowledgement this long is
	// reset; the ingress rebuilds the session from what the egress delivered.
	muxStall = time.Second
	// Ended peer streams are remembered so frames sent again after a Link
	// change cannot start them a second time.
	muxTombstoneLifetime = 10 * time.Minute
	muxMaxTombstones     = 1 << 16
)

// streamMessageKind mirrors the Link message kind that prefixes every frame;
// a data frame of a session sealed end to end has sealedStreamKind, so the
// Link seals only its header.
const (
	streamMessageKind = 12
	sealedStreamKind  = peer.SealedPayload
)

var _ [0]struct{} = [muxDataHeader - peer.SealedHeader]struct{}{}

var errStreamReset = &streamError{syscall.ECONNRESET}

type streamError struct{ errno syscall.Errno }

func (e *streamError) Error() string { return "peer stream reset" }
func (e *streamError) Unwrap() error { return e.errno }

// recvChunk is received bytes and the Link buffer holding them, or nil.
type recvChunk struct {
	data  []byte
	owner *packetbuf.Buffer
}

type muxFrame struct {
	end uint64 // offset after this frame; a FIN occupies one virtual byte
	raw []byte
	buf *packetbuf.Buffer // pooled storage of a data frame, or nil
	at  int               // where raw starts in buf.Data
}

type mux struct {
	g             *group
	even          bool
	handler       func(*muxStream)
	mu            sync.Mutex
	ready         map[*link.Link]bool
	current       *link.Link
	next          uint64
	ended         map[uint64]time.Time
	lastPurge     time.Time
	streams       map[uint64]*muxStream
	pending       []*muxStream
	queuedStreams map[*muxStream]bool
	resets        []muxResetEntry
	lostSince     time.Time
	closed        bool
	// queued is the bytes of frames waiting for the Link writer. Once it
	// reaches muxQueue a stream waits while it holds its share of that, so a
	// stream reads no further ahead of its Link than that and the rest waits
	// in its source, and a stream that starts later, such as a session sending
	// again on a new chain, is not queued behind another's backlog. Nothing is
	// queued past twice muxQueue. drained is closed when frames leave while
	// writers wait on it.
	queued  int
	waiting int
	drained chan struct{}
	// share is each windowed stream's part of the current Link's kernel
	// receive buffer, split between the streams consuming; maintain sets it.
	// receiveWindow replaces the Link's buffer in tests.
	share         uint64
	receiveWindow func() (int, bool)
}

// muxQueue bounds the frames an Edge holds for its Link writer: a few of its
// write batches.
const muxQueue = 2 << 20

func newMux(g *group, even bool, handler func(*muxStream)) *mux {
	m := &mux{g: g, even: even, handler: handler, ready: map[*link.Link]bool{}, streams: map[uint64]*muxStream{}, queuedStreams: map[*muxStream]bool{}, ended: map[uint64]time.Time{}, drained: make(chan struct{})}
	// The peer's mux can outlive this Agent, retaining live stream IDs and
	// tombstones across Link reconnections. A fresh random counter origin
	// avoids deterministic reuse after an Agent restart or group recreation.
	var seed [8]byte
	for m.next == 0 {
		rand.Read(seed[:])
		m.next = binary.BigEndian.Uint64(seed[:]) &^ 1
		if !even {
			m.next |= 1
		}
	}
	return m
}

func (m *mux) peerStream(id uint64) bool { return (id%2 == 0) != m.even }

func (m *mux) endedLocked(id uint64) {
	if !m.peerStream(id) {
		return
	}
	now := time.Now()
	if len(m.ended) >= muxMaxTombstones || now.Sub(m.lastPurge) > muxTombstoneLifetime {
		m.lastPurge = now
		for k, at := range m.ended {
			if now.Sub(at) > muxTombstoneLifetime {
				delete(m.ended, k)
			}
		}
	}
	m.ended[id] = now
}

// Available reports whether new streams can start now. Existing streams keep
// waiting through a brief Link change instead.
func (m *mux) Available() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.closed && m.current != nil
}

// Resumable reports whether new streams can carry resumable TCP sessions.
func (m *mux) Resumable() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.closed && m.current != nil && m.current.Resume()
}

func (m *mux) Open(ctx context.Context) (*muxStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.current == nil {
		return nil, link.ErrUnavailable
	}
	if m.next == 0 {
		return nil, errors.New("edge stream IDs exhausted")
	}
	s := m.newStreamLocked(m.next, m.current.Windows())
	if m.next > ^uint64(0)-2 {
		m.next = 0
	} else {
		m.next += 2
	}
	return s, nil
}

func (m *mux) newStreamLocked(id uint64, windowed bool) *muxStream {
	ctx, cancel := context.WithCancel(m.g.ctx)
	initial := uint64(muxWindow)
	if windowed {
		initial = muxInitialWindow
	}
	s := &muxStream{m: m, id: id, ctx: ctx, cancel: cancel, peerLimit: initial, advertised: initial, windowed: windowed, window: initial, fresh: true, sendWake: make(chan struct{}, 1), readWake: make(chan struct{}, 1)}
	m.streams[id] = s
	if windowed {
		// It shares the Link's buffer from its first acknowledgement.
		m.shareLocked()
	}
	return s
}

// StreamsReady is called once per Link, possibly with the group lock held.
func (m *mux) StreamsReady(l *link.Link) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.ready[l] = true
	switched := false
	if m.current == nil || !m.current.Healthy() {
		m.switchLocked(l)
		switched = true
	}
	m.mu.Unlock()
	if switched {
		l.WakeStreams()
	}
	go func() {
		<-l.Done()
		m.linkDone(l)
	}()
}

func (m *mux) linkDone(l *link.Link) {
	m.mu.Lock()
	delete(m.ready, l)
	var next *link.Link
	if m.current == l {
		m.current = nil
		if next = m.bestLocked(); next != nil {
			m.switchLocked(next)
		} else {
			m.lostSince = time.Now()
		}
	}
	m.mu.Unlock()
	if next != nil {
		next.WakeStreams()
	}
}

func (m *mux) bestLocked() *link.Link {
	var best *link.Link
	for l := range m.ready {
		select {
		case <-l.Done():
			continue
		default:
		}
		if !l.Healthy() {
			continue
		}
		if best == nil || best.RenewalDue() && !l.RenewalDue() || best.RenewalDue() == l.RenewalDue() && l.Stats().RTTMillis < best.Stats().RTTMillis {
			best = l
		}
	}
	return best
}

// switchLocked resends every unacknowledged frame and the receive state of
// every stream on l. The receiver discards bytes it already has.
func (m *mux) switchLocked(l *link.Link) {
	m.current = l
	m.lostSince = time.Time{}
	resent := 0
	for _, s := range m.streams {
		resent += s.unsent
		for _, frame := range s.frames[:s.unsent] {
			m.queueLocked(s, len(frame.raw))
		}
		s.unsent = 0
		s.ackDue = true
		m.enqueueLocked(s)
	}
	if m.g != nil && m.g.mesh != nil {
		m.g.mesh.muxResent.Add(uint64(resent))
	}
}

// streamCount reports the streams the mux carries.
func (m *mux) streamCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.streams)
}

// maintain runs on the Edge scheduler. A Link stays in use while healthy and
// not due for renewal, so streams do not move between Links needlessly.
func (m *mux) maintain() {
	m.mu.Lock()
	var wake *link.Link
	if m.current == nil || !m.current.Healthy() || m.current.RenewalDue() {
		if best := m.bestLocked(); best != nil && best != m.current && (m.current == nil || !m.current.Healthy() || !best.RenewalDue()) {
			m.switchLocked(best)
			wake = best
		}
	}
	var failed []*muxStream
	now := time.Now()
	for _, s := range m.streams {
		switch {
		case s.session:
			// A session rebuilds what a stalled hop holds instead of waiting.
			if len(s.frames) > 0 && now.Sub(s.progress) >= muxStall {
				failed = append(failed, s)
			}
		case m.current == nil && !m.lostSince.IsZero() && now.Sub(m.lostSince) >= muxLinkLoss:
			failed = append(failed, s)
		}
	}
	for _, s := range failed {
		s.failLocked(errStreamReset)
		if s.session {
			m.resetLocked(s.id)
			if m.g != nil && m.g.mesh != nil {
				m.g.mesh.stallResets.Add(1)
			}
		}
	}
	m.shareLocked()
	// ACK receipt independently of application consumption. Small messages
	// release retransmission storage even when the reader has stopped; only
	// consumed bytes increase the receive window.
	for _, s := range m.streams {
		if s.received != s.ackReceived || s.consumed+s.windowLocked() > s.advertised || s.session && !s.local && s.delivered != s.ackDelivered {
			s.ackDue = true
			m.enqueueLocked(s)
			wake = m.current
		}
	}
	m.mu.Unlock()
	if wake != nil {
		wake.WakeStreams()
	}
}

// shareLocked splits the current Link's kernel receive buffer, which bounds
// what is in flight on the Link, between the windowed streams consuming. A
// stream that stopped consuming keeps the credit it was given, as a connection
// whose reader stopped keeps its own buffer, and gets no more; it holds none
// of the Link's buffer, whose bytes it already took. On a Link whose buffer is
// unknown, each stream has muxWindow.
func (m *mux) shareLocked() {
	budget, known := 0, false
	if m.receiveWindow != nil {
		budget, known = m.receiveWindow()
	} else if m.current != nil {
		budget, known = m.current.ReceiveWindow()
	}
	var consuming []*muxStream
	now := time.Now()
	for _, s := range m.streams {
		if !s.windowed || s.err != nil {
			continue
		}
		if s.fresh || s.consumed != s.lastConsumed {
			s.fresh, s.lastConsumed, s.consuming = false, s.consumed, now
		}
		if now.Sub(s.consuming) < muxIdle {
			consuming = append(consuming, s)
		}
	}
	share := uint64(muxWindow)
	if known {
		share = max(muxMaxData, uint64(budget)/uint64(max(1, len(consuming))))
	}
	m.share = share
	for _, s := range m.streams {
		if s.windowed {
			s.window = min(s.window, share)
		}
	}
	for _, s := range consuming {
		s.window = share
	}
}

func (m *mux) close() {
	m.mu.Lock()
	m.closed = true
	for _, s := range m.streams {
		s.failLocked(net.ErrClosed)
	}
	m.mu.Unlock()
}

// queueLocked adds n bytes of frames waiting for the Link writer to s and to
// the Edge, or removes them when n is negative.
func (m *mux) queueLocked(s *muxStream, n int) {
	s.queued += n
	m.queued += n
	if n < 0 && m.waiting > 0 {
		close(m.drained)
		m.drained = make(chan struct{})
		m.waiting = 0
	}
}

// fullLocked reports whether s waits for the Link writer before queueing more.
func (m *mux) fullLocked(s *muxStream) bool {
	if m.queued < muxQueue {
		return false
	}
	return m.queued >= 2*muxQueue || s.queued >= muxQueue/max(1, len(m.queuedStreams))
}

func (m *mux) enqueueLocked(s *muxStream) {
	if !m.queuedStreams[s] {
		m.queuedStreams[s] = true
		m.pending = append(m.pending, s)
	}
}

func (m *mux) wake() {
	m.mu.Lock()
	l := m.current
	m.mu.Unlock()
	if l != nil {
		l.WakeStreams()
	}
}

type muxResetEntry struct {
	id    uint64
	abort bool // the reset resets a TCP session's connection
}

func (m *mux) resetLocked(id uint64) { m.resetKindLocked(id, false) }

func (m *mux) resetKindLocked(id uint64, abort bool) {
	if len(m.resets) < 1024 {
		m.resets = append(m.resets, muxResetEntry{id, abort})
	}
}

func frameHeader(raw []byte, kind byte, id uint64) {
	raw[0] = streamMessageKind
	raw[1] = kind
	binary.BigEndian.PutUint64(raw[2:10], id)
}

// PullStream hands the Link writer immutable frames. Frames stay referenced by
// their stream until acknowledged, so a later Link can send them again; the
// writer owns a data frame's buffer in owners until it has sent the frame.
func (m *mux) PullStream(l *link.Link, dst [][]byte, owners []*packetbuf.Buffer) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l != m.current {
		return 0
	}
	n := 0
	for n < len(dst) && len(m.resets) > 0 {
		reset := m.resets[0]
		raw := make([]byte, muxHeader, muxAbortSize)
		frameHeader(raw, muxReset, reset.id)
		if reset.abort {
			raw = append(raw, 1)
		}
		m.resets = m.resets[1:]
		dst[n], owners[n] = raw, nil
		n++
	}
	for n < len(dst) && len(m.pending) > 0 {
		s := m.pending[0]
		m.pending[0] = nil
		m.pending = m.pending[1:]
		if s.ackDue {
			dst[n], owners[n] = s.ackFrameLocked(), nil
			n++
			if s.session {
				s.finishLocked()
			}
		}
		for burst := 0; burst < muxBurst && n < len(dst) && s.unsent < len(s.frames); burst++ {
			frame := s.frames[s.unsent]
			frame.buf.Retain()
			dst[n], owners[n] = frame.raw, frame.buf
			m.queueLocked(s, -len(frame.raw))
			s.unsent++
			n++
		}
		if s.ackDue || s.unsent < len(s.frames) {
			m.pending = append(m.pending, s)
		} else {
			delete(m.queuedStreams, s)
		}
	}
	return n
}

// ReceiveStream keeps received data in the Link's buffer as one of its owners,
// or copies it when raw is not pooled: the Link reuses raw after returning.
func (m *mux) ReceiveStream(l *link.Link, raw []byte, owner *packetbuf.Buffer) bool {
	if len(raw) < muxHeader-1 {
		return false
	}
	kind, id := raw[0], binary.BigEndian.Uint64(raw[1:9])
	if id == 0 {
		return false
	}
	switch kind {
	case muxData:
		if len(raw) < muxDataHeader-1 {
			return false
		}
		return m.receiveData(id, binary.BigEndian.Uint64(raw[9:17]), raw[17], raw[18:], owner)
	case muxAck:
		switch len(raw) {
		case muxAckSize - 1:
			m.receiveAck(id, binary.BigEndian.Uint64(raw[9:17]), binary.BigEndian.Uint64(raw[17:25]), 0, false)
		case muxSessionAckSize - 1:
			m.receiveAck(id, binary.BigEndian.Uint64(raw[9:17]), binary.BigEndian.Uint64(raw[17:25]), binary.BigEndian.Uint64(raw[25:33]), true)
		default:
			return false
		}
		return true
	case muxWindowAck:
		switch len(raw) {
		case muxWindowAckSize - 1:
			m.receiveWindowAck(id, binary.BigEndian.Uint64(raw[9:17]), binary.BigEndian.Uint64(raw[17:25]), binary.BigEndian.Uint64(raw[25:33]), 0, false)
		case muxWindowSessionAckSize - 1:
			m.receiveWindowAck(id, binary.BigEndian.Uint64(raw[9:17]), binary.BigEndian.Uint64(raw[17:25]), binary.BigEndian.Uint64(raw[25:33]), binary.BigEndian.Uint64(raw[33:41]), true)
		default:
			return false
		}
		return true
	case muxReset:
		if len(raw) != muxHeader-1 && (len(raw) != muxAbortSize-1 || raw[9] != 1) {
			return false
		}
		m.mu.Lock()
		if s := m.streams[id]; s != nil {
			s.peerAborted = len(raw) == muxAbortSize-1
			s.failLocked(errStreamReset)
		}
		m.mu.Unlock()
		return true
	default:
		return false
	}
}

// receiveData keeps received bytes in the Link's buffer when owner is not nil,
// as an owner until they are read, and copies them otherwise.
func (m *mux) receiveData(id, offset uint64, flags byte, data []byte, owner *packetbuf.Buffer) bool {
	if flags&^(muxFin|muxEnd|muxWindowed) != 0 || flags&muxEnd != 0 && flags&muxFin == 0 || flags&muxFin != 0 && len(data) != 0 {
		return false
	}
	m.mu.Lock()
	s := m.streams[id]
	accepted := false
	if s == nil {
		if m.closed {
			m.mu.Unlock()
			return true
		}
		_, ended := m.ended[id]
		if !m.peerStream(id) || ended || offset != 0 {
			// A stream that already ended, or one this Edge cannot take.
			m.resetLocked(id)
			m.endedLocked(id)
			l := m.current
			m.mu.Unlock()
			if l != nil {
				l.WakeStreams()
			}
			return true
		}
		s = m.newStreamLocked(id, flags&muxWindowed != 0)
		accepted = true
	}
	if s.err != nil {
		m.mu.Unlock()
		return true
	}
	end := offset + uint64(len(data))
	if end > max(s.advertised, s.consumed+s.windowLocked()) || s.finRecv && end > s.finAt {
		s.failLocked(errStreamReset)
		m.resetLocked(id)
		m.mu.Unlock()
		m.wake()
		return true
	}
	// Frames arrive in order on one Link; after a Link change the sender starts
	// again at our acknowledged offset, so only duplicates precede received.
	if offset <= s.received && end > s.received {
		chunk := data[s.received-offset:]
		if owner != nil {
			owner.Retain()
		} else {
			chunk = append([]byte(nil), chunk...)
		}
		s.recv = append(s.recv, recvChunk{chunk, owner})
		s.recvBytes += len(chunk)
		s.received = end
		s.rx.Add(uint64(len(chunk)))
		signal(s.readWake)
		if s.windowed && s.session && s.local && s.received-s.ackReceived >= muxAckThreshold {
			// The far end releases what this end received.
			s.ackDue = true
			m.enqueueLocked(s)
		}
	}
	if flags&muxFin != 0 && offset == s.received && !s.finRecv {
		s.finRecv, s.finAt, s.peerEnd = true, offset, flags&muxEnd != 0
		s.ackDue = true
		m.enqueueLocked(s)
		signal(s.readWake)
	}
	var l *link.Link
	if s.ackDue {
		l = m.current
	}
	m.mu.Unlock()
	if l != nil {
		l.WakeStreams()
	}
	if accepted {
		m.handler(s)
	}
	return true
}

func (m *mux) receiveAck(id, received, limit, delivered uint64, explicit bool) {
	m.receiveAckConsumed(id, received, limit, 0, false, delivered, explicit)
}

// receiveWindowAck takes a windowed stream's acknowledgement, which states
// what the receiver consumed.
func (m *mux) receiveWindowAck(id, received, limit, consumed, delivered uint64, explicit bool) {
	m.receiveAckConsumed(id, received, limit, consumed, true, delivered, explicit)
}

func (m *mux) receiveAckConsumed(id, received, limit, consumed uint64, stated bool, delivered uint64, explicit bool) {
	m.mu.Lock()
	s := m.streams[id]
	if s == nil || s.err != nil {
		m.mu.Unlock()
		return
	}
	before := s.peerDeliveredLocked()
	if stated {
		s.peerConsumed = max(s.peerConsumed, consumed)
	}
	if explicit {
		s.explicitPeer = true
		s.peerDelivered = max(s.peerDelivered, delivered)
	}
	if received > s.acked {
		s.progress = time.Now()
		s.acked = received
		drop := 0
		for drop < len(s.frames) && s.frames[drop].end <= received {
			if drop >= s.unsent {
				m.queueLocked(s, -len(s.frames[drop].raw)) // acknowledged before this Link sent it
			}
			s.frames[drop].buf.Release()
			s.frames[drop] = muxFrame{}
			drop++
		}
		if drop == len(s.frames) {
			// Every frame was acknowledged: the next ones reuse the storage
			// from its start instead of growing past its end.
			s.frames = s.frames[:0]
		} else {
			s.frames = s.frames[drop:]
		}
		s.unsent = max(0, s.unsent-drop)
	}
	if limit > s.peerLimit {
		s.peerLimit = limit
		signal(s.sendWake)
	}
	s.finishLocked()
	notify := s.onDelivered
	changed := s.session && s.peerDeliveredLocked() != before
	m.mu.Unlock()
	if changed && notify != nil {
		notify()
	}
}

func signal(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

// muxStream implements streamproxy.Conn over an Edge's Links.
type muxStream struct {
	m       *mux
	id      uint64
	ctx     context.Context
	cancel  context.CancelFunc
	writeMu sync.Mutex
	rx, tx  atomic.Uint64

	// Guarded by m.mu.
	sendNext    uint64
	peerLimit   uint64
	acked       uint64
	frames      []muxFrame
	unsent      int
	queued      int // bytes of frames[unsent:], counted in the mux's queued
	writeClosed bool
	finOffset   uint64

	recv        []recvChunk
	recvBytes   int
	received    uint64
	ackReceived uint64
	consumed    uint64
	advertised  uint64
	ackDue      bool
	// A windowed stream's receive window; see mux.shareLocked. Its
	// acknowledgements state consumed, and the peer's state peerConsumed.
	windowed     bool
	window       uint64
	fresh        bool      // not yet counted by shareLocked
	lastConsumed uint64    // consumed when shareLocked last saw it change
	consuming    time.Time // then
	peerConsumed uint64
	finRecv      bool
	finAt        uint64

	closed   bool
	err      error
	sendWake chan struct{}
	readWake chan struct{}

	// A TCP session hop; see streamproxy.Hop. Its session offsets count from
	// sendStart at this stream's offset sendMark.
	session       bool
	sendStart     uint64
	sendMark      uint64
	local         bool   // the far end infers delivery from what this end received
	recvMark      uint64 // where the session's received bytes start
	delivered     uint64 // reported in acknowledgements unless local
	ackDelivered  uint64
	explicitPeer  bool
	peerDelivered uint64
	onDelivered   func()
	peerEnd       bool
	peerAborted   bool
	leftover      []byte
	keep          *streamproxy.Keep
	progress      time.Time // when sent frames last saw an acknowledgement
	// sealed: the data written from now on is sealed end to end.
	sealed atomic.Bool
}

// CarrySealed marks the data written from now on as sealed end to end, so
// the Link seals only the frames' headers.
func (s *muxStream) CarrySealed() { s.sealed.Store(true) }

// windowLocked is the bytes past what the stream consumed that it lets the
// sender send.
func (s *muxStream) windowLocked() uint64 {
	if s.windowed {
		return s.window
	}
	return muxWindow
}

// dataFlags marks a windowed stream's data frames.
func (s *muxStream) dataFlags() byte {
	if s.windowed {
		return muxWindowed
	}
	return 0
}

func (s *muxStream) ackFrameLocked() []byte {
	kind, size := byte(muxAck), muxAckSize
	if s.windowed {
		kind, size = muxWindowAck, muxWindowAckSize
	}
	relay := s.session && !s.local
	if relay {
		size += 8
	}
	raw := make([]byte, size)
	frameHeader(raw, kind, s.id)
	received := s.received
	if s.finRecv {
		received++
	}
	limit := max(s.advertised, s.consumed+s.windowLocked())
	binary.BigEndian.PutUint64(raw[10:18], received)
	binary.BigEndian.PutUint64(raw[18:26], limit)
	at := 26
	if s.windowed {
		binary.BigEndian.PutUint64(raw[at:at+8], s.consumed)
		at += 8
	}
	if relay {
		binary.BigEndian.PutUint64(raw[at:at+8], s.delivered)
		s.ackDelivered = s.delivered
	}
	s.advertised = max(s.advertised, limit)
	s.ackReceived = s.received
	s.ackDue = false
	return raw
}

// frameBuilder lays out data frames in pooled buffers as bytes arrive, as
// peer.Stream's record builder does, taking a buffer only for bytes it holds.
// Each frame's buffer has one owner per holder: the stream until the frame is
// acknowledged, a session end's keep until delivery, and a Link while it
// sends the frame.
//
// With records, each frame carries one record of an end-to-end sealed
// session: its bytes arrive as plaintext after the record's length, and seal
// turns them into the record in place.
type frameBuilder struct {
	kind    byte // the Link message kind of its frames
	flags   byte // its data frames' flags
	id      uint64
	offset  uint64
	limit   int
	bytes   int // session bytes, records' length and tag included
	frames  []muxFrame
	records *streamproxy.Records
}

func newFrameBuilder(id, offset uint64, limit int, records *streamproxy.Records) *frameBuilder {
	return &frameBuilder{kind: streamMessageKind, id: id, offset: offset, limit: limit, frames: make([]muxFrame, 0, (limit+muxMaxData-1)/muxMaxData), records: records}
}

// newBuilder returns a builder for s's data frames.
func (s *muxStream) newBuilder(offset uint64, limit int, records *streamproxy.Records) *frameBuilder {
	b := newFrameBuilder(s.id, offset, limit, records)
	b.flags = s.dataFlags()
	if s.sealed.Load() {
		b.kind = sealedStreamKind
	}
	return b
}

// layout reports a frame's plaintext room, the record length bytes before it
// and the bytes a frame adds to the session's offsets.
func (b *frameBuilder) layout() (room, prefix, overhead int) {
	if b.records != nil {
		return muxMaxData - streamproxy.RecordOverhead, streamproxy.RecordHeader, streamproxy.RecordOverhead
	}
	return muxMaxData, 0, 0
}

// space returns the last frame with room for more plaintext, starting a frame
// when the last one is full, or nil when the credit is used up.
func (b *frameBuilder) space() *muxFrame {
	room, prefix, overhead := b.layout()
	last := len(b.frames) - 1
	if last < 0 || len(b.frames[last].raw)-muxDataHeader-prefix == room {
		if b.bytes >= b.limit || b.limit-b.bytes <= overhead {
			return nil
		}
		buf := packetbuf.Get(muxDataHeader + muxMaxData)
		// Pooled storage is not cleared: every header byte is written.
		raw := buf.Data[:muxDataHeader]
		frameHeader(raw, muxData, b.id)
		raw[0] = b.kind
		binary.BigEndian.PutUint64(raw[10:18], b.offset+uint64(b.bytes))
		raw[18] = b.flags
		raw = raw[:muxDataHeader+prefix]
		b.bytes += overhead
		b.frames = append(b.frames, muxFrame{raw: raw, buf: buf})
		last++
	}
	return &b.frames[last]
}

func (b *frameBuilder) Write(data []byte) (int, error) {
	written := 0
	room, prefix, _ := b.layout()
	for len(data) > 0 && b.bytes < b.limit {
		frame := b.space()
		if frame == nil {
			break
		}
		n := min(len(data), b.limit-b.bytes, room-(len(frame.raw)-muxDataHeader-prefix))
		frame.raw = append(frame.raw, data[:n]...)
		b.bytes += n
		written += n
		data = data[n:]
	}
	if len(data) > 0 {
		return written, io.ErrShortWrite
	}
	return written, nil
}

// Room is how many bytes Write takes now, for a source that must not read
// more than it can write.
func (b *frameBuilder) Room() int {
	room, prefix, overhead := b.layout()
	credit, total := b.limit-b.bytes, 0
	if last := len(b.frames) - 1; last >= 0 {
		take := min(credit, room-(len(b.frames[last].raw)-muxDataHeader-prefix))
		total, credit = take, credit-take
	}
	for credit > overhead {
		take := min(credit-overhead, room)
		total, credit = total+take, credit-take-overhead
	}
	return total
}

// seal turns each frame's plaintext into its record. The frames' offsets
// already count the records' length and tag.
func (b *frameBuilder) seal() error {
	if b.records == nil {
		return nil
	}
	for i := range b.frames {
		record, err := b.records.Seal(b.frames[i].raw[muxDataHeader:])
		if err != nil {
			return err
		}
		b.frames[i].raw = b.frames[i].raw[:muxDataHeader+len(record)]
	}
	return nil
}

func (b *frameBuilder) finish() []muxFrame {
	offset := b.offset
	for i := range b.frames {
		raw := b.frames[i].raw
		offset += uint64(len(raw) - muxDataHeader)
		b.frames[i].end, b.frames[i].raw = offset, raw[:len(raw):len(raw)]
	}
	return b.frames
}

// release returns the buffers of frames that were not published.
func (b *frameBuilder) release() {
	for _, frame := range b.frames {
		frame.buf.Release()
	}
	b.frames = nil
}

// reserve waits for send credit and returns the next offset and how many
// bytes may follow it. Callers hold writeMu.
func (s *muxStream) reserve() (uint64, int, error) {
	m := s.m
	for {
		m.mu.Lock()
		if s.err != nil {
			err := s.err
			m.mu.Unlock()
			return 0, 0, err
		}
		if s.writeClosed {
			m.mu.Unlock()
			return 0, 0, io.ErrClosedPipe
		}
		available := s.peerLimit - s.sendNext
		start := s.sendNext
		drained, full := m.drained, m.fullLocked(s)
		if full {
			m.waiting++
		}
		m.mu.Unlock()
		if full {
			// The Link writer has enough waiting: the bytes stay in their
			// source until it catches up.
			select {
			case <-drained:
			case <-s.ctx.Done():
				return 0, 0, s.errOr(net.ErrClosed)
			}
			continue
		}
		if available > 0 {
			return start, int(min(available, muxBurst*muxMaxData)), nil
		}
		select {
		case <-s.sendWake:
		case <-s.ctx.Done():
			return 0, 0, s.errOr(net.ErrClosed)
		}
	}
}

// publish queues frames built outside the lock; writers are serialized, so
// offsets stay contiguous while receivers and other streams proceed.
func (s *muxStream) publish(b *frameBuilder) error {
	m := s.m
	m.mu.Lock()
	if s.err != nil {
		err := s.err
		m.mu.Unlock()
		return err
	}
	frames := b.finish()
	if len(s.frames) == 0 {
		s.progress = time.Now()
	}
	for _, frame := range frames {
		m.queueLocked(s, len(frame.raw))
	}
	s.frames = append(s.frames, frames...)
	s.sendNext += uint64(b.bytes)
	if s.keep != nil {
		// Frames are immutable; the session end keeps their payloads until the
		// far end delivered them. Under the lock, a reset of this hop either
		// follows the bytes into the keep or fails this publish.
		for _, frame := range frames {
			s.keep.Add(frame.raw[muxDataHeader:], frame.buf, frame.at+muxDataHeader)
		}
	}
	m.enqueueLocked(s)
	l := m.current
	m.mu.Unlock()
	if l != nil {
		l.WakeStreams()
	}
	s.tx.Add(uint64(b.bytes))
	return nil
}

// payload copies what a builder holds, for a ReadFrom that could not send it.
func (b *frameBuilder) payload() []byte {
	out := make([]byte, 0, b.bytes)
	for _, frame := range b.frames {
		out = append(out, frame.raw[muxDataHeader:]...)
	}
	return out
}

// keptExclusive bounds how long WriteKept waits for a Link still sending a
// kept buffer's earlier frame before it copies the bytes instead.
const keptExclusive = time.Second

// WriteKept sends a session's kept bytes in the buffer that already holds
// them: their old frame header precedes them there, and is rewritten for this
// stream once only the keep and the caller own the buffer. It reports false
// when it cannot, and the caller copies the bytes.
func (s *muxStream) WriteKept(kept streamproxy.Kept) (bool, error) {
	if kept.Owner == nil || kept.At < muxDataHeader || len(kept.Data) == 0 || len(kept.Data) > muxMaxData || kept.At+len(kept.Data) > len(kept.Owner.Data) {
		return false, nil
	}
	for deadline := time.Now().Add(keptExclusive); kept.Owner.Owners() > 2; time.Sleep(100 * time.Microsecond) {
		if time.Now().After(deadline) {
			return false, nil
		}
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	start, err := s.reserveAll(len(kept.Data))
	if err != nil {
		return false, err
	}
	at := kept.At - muxDataHeader
	raw := kept.Owner.Data[at : kept.At+len(kept.Data) : kept.At+len(kept.Data)]
	frameHeader(raw, muxData, s.id)
	if s.sealed.Load() {
		raw[0] = sealedStreamKind
	}
	binary.BigEndian.PutUint64(raw[10:18], start)
	raw[18] = s.dataFlags()
	kept.Owner.Retain()
	b := &frameBuilder{id: s.id, offset: start, limit: len(kept.Data), bytes: len(kept.Data), frames: []muxFrame{{raw: raw, buf: kept.Owner, at: at}}}
	if err := s.publish(b); err != nil {
		b.release()
		return false, err
	}
	return true, nil
}

// reserveAll waits until n bytes of send credit are available.
func (s *muxStream) reserveAll(n int) (uint64, error) {
	for {
		start, limit, err := s.reserve()
		if err != nil || limit >= n {
			return start, err
		}
		m := s.m
		m.mu.Lock()
		short := s.peerLimit-s.sendNext < uint64(n)
		m.mu.Unlock()
		if !short {
			continue
		}
		select {
		case <-s.sendWake:
		case <-s.ctx.Done():
			return 0, s.errOr(net.ErrClosed)
		}
	}
}

func (s *muxStream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	written := 0
	for len(p) > 0 {
		room, err := s.waitKeep(1)
		if err != nil {
			return written, s.errOr(err)
		}
		start, limit, err := s.reserve()
		if err != nil {
			return written, err
		}
		limit = min(limit, room)
		b := s.newBuilder(start, min(len(p), limit), nil)
		b.Write(p[:b.limit])
		if err := s.publish(b); err != nil {
			b.release()
			return written, err
		}
		written += b.bytes
		p = p[b.bytes:]
	}
	return written, nil
}

type muxWriterOnly struct{ io.Writer }

// ReadFrom lets the access TCP endpoint deliver bytes straight into frames,
// as peer.Stream does, saving the relay's intermediate copy.
func (s *muxStream) ReadFrom(src io.Reader) (int64, error) {
	reader, ok := src.(interface{ ReadInto(io.Writer) (int, error) })
	if !ok {
		return io.CopyBuffer(muxWriterOnly{s}, src, make([]byte, 64*1024))
	}
	// A session's end that seals it end to end has its bytes sealed here,
	// in the frames that carry them.
	var records *streamproxy.Records
	if sealed, ok := src.(interface{ Records() *streamproxy.Records }); ok {
		records = sealed.Records()
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	need := 1
	if records != nil {
		need = streamproxy.RecordOverhead + 1
	}
	var total int64
	for {
		room, err := s.waitKeep(need)
		if err != nil {
			return total, s.errOr(err)
		}
		start, limit, err := s.reserve()
		if err != nil {
			return total, err
		}
		limit = min(limit, room)
		if records != nil && limit <= streamproxy.RecordOverhead {
			// Too little credit for a record's plaintext.
			if _, err := s.reserveAll(streamproxy.RecordOverhead + 1); err != nil {
				return total, err
			}
			continue
		}
		b := s.newBuilder(start, limit, records)
		n, readErr := reader.ReadInto(b)
		if n > 0 {
			if err := b.seal(); err != nil {
				// A channel out of record numbers ends the connection.
				b.release()
				s.AbortSession()
				return total, err
			}
			if err := s.publish(b); err != nil {
				// What was read from the access connection but not sent goes to
				// the session's next hop.
				s.m.mu.Lock()
				s.leftover = append(s.leftover, b.payload()...)
				s.m.mu.Unlock()
				b.release()
				return total, err
			}
			total += int64(n)
		}
		if readErr == io.EOF {
			return total, nil
		}
		if readErr != nil {
			return total, readErr
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
	}
}

func (s *muxStream) CloseWrite() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	m := s.m
	m.mu.Lock()
	if s.err != nil || s.writeClosed {
		err := s.err
		m.mu.Unlock()
		return err
	}
	s.writeClosed, s.finOffset = true, s.sendNext
	raw := make([]byte, muxDataHeader)
	frameHeader(raw, muxData, s.id)
	binary.BigEndian.PutUint64(raw[10:18], s.sendNext)
	raw[18] = muxFin | s.dataFlags()
	if s.session {
		raw[18] |= muxEnd
	}
	if len(s.frames) == 0 {
		s.progress = time.Now()
	}
	s.frames = append(s.frames, muxFrame{end: s.sendNext + 1, raw: raw})
	m.queueLocked(s, len(raw))
	m.enqueueLocked(s)
	l := m.current
	m.mu.Unlock()
	if l != nil {
		l.WakeStreams()
	}
	return nil
}

// Buffered reports bytes that Read returns without waiting, or 0.
func (s *muxStream) Buffered() int {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	return s.recvBytes
}

// ReadWindow reports bytes that Read can return without waiting.
func (s *muxStream) ReadWindow() (int, error) {
	m := s.m
	for {
		m.mu.Lock()
		if s.recvBytes > 0 {
			n := s.recvBytes
			m.mu.Unlock()
			return n, nil
		}
		if s.finRecv && s.consumed == s.finAt {
			m.mu.Unlock()
			return 0, io.EOF
		}
		if s.err != nil {
			err := s.err
			m.mu.Unlock()
			return 0, err
		}
		m.mu.Unlock()
		select {
		case <-s.readWake:
		case <-s.ctx.Done():
			return 0, s.errOr(net.ErrClosed)
		}
	}
}

func (s *muxStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if _, err := s.ReadWindow(); err != nil {
		return 0, err
	}
	m := s.m
	m.mu.Lock()
	n := 0
	for n < len(p) && len(s.recv) > 0 {
		c := copy(p[n:], s.recv[0].data)
		n += c
		if c == len(s.recv[0].data) {
			s.recv[0].owner.Release()
			s.recv[0] = recvChunk{}
			s.recv = s.recv[1:]
		} else {
			s.recv[0].data = s.recv[0].data[c:]
		}
	}
	s.recvBytes -= n
	m.mu.Unlock()
	s.consume(n)
	return n, nil
}

// consume counts n received bytes as read, opening the window by them.
func (s *muxStream) consume(n int) {
	m := s.m
	m.mu.Lock()
	s.consumed += uint64(n)
	var l *link.Link
	// A session hop that read up to its FIN acknowledges at once: the far end
	// finishes the session only when it learns that everything was delivered.
	window := s.windowLocked()
	if (s.consumed+window > s.advertised && s.consumed+window-s.advertised >= min(muxAckThreshold, window/4) || s.session && s.finRecv && s.consumed == s.finAt && s.consumed+window > s.advertised) && s.err == nil {
		s.ackDue = true
		m.enqueueLocked(s)
		l = m.current
	}
	m.mu.Unlock()
	if l != nil {
		l.WakeStreams()
	}
}

// TakeChunk returns the next bytes received in one frame, without copying
// them, and the Link buffer holding them, which passes to the caller, or nil.
func (s *muxStream) TakeChunk() ([]byte, *packetbuf.Buffer, error) {
	if _, err := s.ReadWindow(); err != nil {
		return nil, nil, err
	}
	m := s.m
	m.mu.Lock()
	if len(s.recv) == 0 {
		m.mu.Unlock()
		return nil, nil, nil
	}
	c := s.recv[0]
	s.recv[0] = recvChunk{}
	s.recv = s.recv[1:]
	s.recvBytes -= len(c.data)
	m.mu.Unlock()
	s.consume(len(c.data))
	return c.data, c.owner, nil
}

// RelayTo sends what s receives on to, as a TCP session's relay does. A
// received frame leaves in the Link buffer it arrived in: to's header is
// written over the bytes before its payload, which held its own header. Bytes
// not in such a buffer are copied. s opens its window by what to queued, so
// the relay holds no more than its streams' windows. It returns at s's end;
// the caller ends to's direction.
func (s *muxStream) RelayTo(hop streamproxy.Hop) (int64, error) {
	to, ok := hop.(*muxStream)
	if !ok {
		return io.CopyBuffer(muxWriterOnly{hop}, s, make([]byte, 64*1024))
	}
	to.writeMu.Lock()
	defer to.writeMu.Unlock()
	m := s.m
	var total int64
	for {
		if _, err := s.ReadWindow(); err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
		// The chunk's owner passes to forward with it.
		m.mu.Lock()
		if len(s.recv) == 0 {
			m.mu.Unlock()
			continue
		}
		c := s.recv[0]
		s.recv[0] = recvChunk{}
		s.recv = s.recv[1:]
		s.recvBytes -= len(c.data)
		m.mu.Unlock()
		if err := to.forward(c.data, c.owner); err != nil {
			return total, err
		}
		s.consume(len(c.data))
		total += int64(len(c.data))
	}
}

// forward queues data, whose owner passes to it, as the stream's next bytes:
// in its own buffer under a header written in front of it when the buffer
// holds the muxDataHeader bytes before data, and copied otherwise. Callers
// hold writeMu.
func (s *muxStream) forward(data []byte, owner *packetbuf.Buffer) error {
	at, inPlace := bufferOffset(data, owner)
	if !inPlace || at < muxDataHeader || len(data) > muxMaxData {
		defer owner.Release()
		if m := s.m; m.g != nil && m.g.mesh != nil {
			m.g.mesh.relayCopied.Add(uint64(len(data)))
		}
		for len(data) > 0 {
			start, limit, err := s.reserve()
			if err != nil {
				return err
			}
			b := s.newBuilder(start, min(len(data), limit), nil)
			b.Write(data[:b.limit])
			if err := s.publish(b); err != nil {
				b.release()
				return err
			}
			data = data[b.bytes:]
		}
		return nil
	}
	start, err := s.reserveAll(len(data))
	if err != nil {
		owner.Release()
		return err
	}
	end := at + len(data)
	raw := owner.Data[at-muxDataHeader : end : end]
	frameHeader(raw, muxData, s.id)
	if s.sealed.Load() {
		raw[0] = sealedStreamKind
	}
	binary.BigEndian.PutUint64(raw[10:18], start)
	raw[18] = s.dataFlags()
	frames := [1]muxFrame{{raw: raw, buf: owner, at: at - muxDataHeader}}
	b := frameBuilder{id: s.id, offset: start, limit: len(data), bytes: len(data), frames: frames[:]}
	if err := s.publish(&b); err != nil {
		owner.Release()
		return err
	}
	if m := s.m; m.g != nil && m.g.mesh != nil {
		m.g.mesh.relayForwarded.Add(uint64(len(data)))
	}
	return nil
}

// waitKeep holds a session end's writes while its send buffer is full, and
// returns how many bytes it may write.
func (s *muxStream) waitKeep(need int) (int, error) {
	s.m.mu.Lock()
	keep := s.keep
	s.m.mu.Unlock()
	if keep == nil {
		return math.MaxInt, nil
	}
	return keep.Wait(s.ctx, need)
}

// bufferOffset reports where data starts in owner.Data, if data is a view of
// it.
func bufferOffset(data []byte, owner *packetbuf.Buffer) (int, bool) {
	if owner == nil || len(data) == 0 {
		return 0, false
	}
	at := cap(owner.Data) - cap(data)
	if at < 0 || at+len(data) > len(owner.Data) || &owner.Data[at] != &data[0] {
		return 0, false
	}
	return at, true
}

// Close ends the stream. After both directions finished it waits for the FIN
// acknowledgement in the background; otherwise the peer receives a reset.
func (s *muxStream) Close() error {
	m := s.m
	m.mu.Lock()
	if s.err == nil && !s.closed {
		s.closed = true
		if !(s.writeClosed && s.finRecv && s.consumed == s.finAt) {
			s.failLocked(net.ErrClosed)
			m.resetLocked(s.id)
		} else {
			if s.session && (s.consumed+s.windowLocked() > s.advertised || s.received != s.ackReceived || !s.local && s.delivered != s.ackDelivered) {
				// The far end learns what this end delivered from this ACK.
				s.ackDue = true
				m.enqueueLocked(s)
			}
			s.finishLocked()
		}
	}
	l := m.current
	m.mu.Unlock()
	if l != nil {
		l.WakeStreams()
	}
	return nil
}

func (s *muxStream) Abort() {
	m := s.m
	m.mu.Lock()
	if s.err == nil {
		s.failLocked(errStreamReset)
		m.resetLocked(s.id)
	}
	l := m.current
	m.mu.Unlock()
	if l != nil {
		l.WakeStreams()
	}
}

func (s *muxStream) finishLocked() {
	// A session hop's last acknowledgement may carry the delivered end.
	if s.closed && s.writeClosed && s.acked > s.finOffset && !(s.session && s.ackDue) {
		s.failLocked(net.ErrClosed)
	}
}

func (s *muxStream) failLocked(err error) {
	if s.err != nil {
		return
	}
	s.err = err
	if s.queued != 0 {
		s.m.queueLocked(s, -s.queued)
	}
	for _, frame := range s.frames {
		frame.buf.Release()
	}
	if !(s.session && s.local && s.windowed) {
		for _, chunk := range s.recv {
			chunk.owner.Release()
		}
		s.recv, s.recvBytes = nil, 0
	}
	// A session end's peer released what this hop received: the end takes it
	// with Detach.
	s.frames = nil
	s.ackDue = false
	delete(s.m.streams, s.id)
	s.m.endedLocked(s.id)
	s.cancel()
}

func (s *muxStream) errOr(fallback error) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	return fallback
}

// Bytes reports application bytes received and sent on this stream.
func (s *muxStream) Bytes() (rx, tx uint64) { return s.rx.Load(), s.tx.Load() }

// Begin starts a session hop's accounting: send is the session offset of the
// next byte written. See streamproxy.Hop.
func (s *muxStream) Begin(send uint64) {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	s.session = true
	s.sendStart, s.sendMark = send, s.sendNext
}

// DeliverLocal makes acknowledgements imply the delivered offset: this end's
// reader delivers what it consumes, which they already report.
func (s *muxStream) DeliverLocal() {
	s.m.mu.Lock()
	s.local = true
	// What was read before is the chain's request or answer.
	s.recvMark = s.consumed
	s.m.mu.Unlock()
}

// SetDelivered sets the offset this relay's acknowledgements report.
func (s *muxStream) SetDelivered(e uint64) {
	m := s.m
	m.mu.Lock()
	if e <= s.delivered || s.err != nil {
		m.mu.Unlock()
		return
	}
	s.delivered = e
	var l *link.Link
	// After its own input ended, the hop has nothing else to acknowledge, so
	// the end's delivery goes out at once.
	if e-s.ackDelivered >= muxAckThreshold || s.finRecv && s.consumed == s.finAt {
		s.ackDue = true
		m.enqueueLocked(s)
		l = m.current
	}
	m.mu.Unlock()
	if l != nil {
		l.WakeStreams()
	}
}

func (s *muxStream) PeerDelivered() uint64 {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	return s.peerDeliveredLocked()
}

// peerDeliveredLocked is the far end's delivered offset: reported by a relay,
// or what the end itself consumed, one more once it took the end.
func (s *muxStream) peerDeliveredLocked() uint64 {
	if s.explicitPeer {
		return s.peerDelivered
	}
	if s.windowed {
		// The far end of a windowed hop keeps what it received, through a
		// failure of the hop too: received bytes are delivered, and its FIN
		// counts as the end.
		if s.acked < s.sendMark {
			return s.sendStart
		}
		return s.sendStart + s.acked - s.sendMark
	}
	consumed := s.peerLimit - muxWindow
	if consumed < s.sendMark {
		return s.sendStart
	}
	e := s.sendStart + consumed - s.sendMark
	if s.writeClosed && s.acked > s.finOffset && consumed == s.finOffset {
		e++
	}
	return e
}

// Received is the session's bytes this stream received, read or not.
func (s *muxStream) Received() uint64 {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	return s.received - min(s.recvMark, s.received)
}

// Detach hands the bytes received and not yet read to the caller, which owns
// their buffers. A session end's peer counts them delivered once received, so
// the end takes them from a hop it leaves, even a failed one.
func (s *muxStream) Detach() []streamproxy.Kept {
	m := s.m
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]streamproxy.Kept, 0, len(s.recv))
	for _, chunk := range s.recv {
		at, ok := bufferOffset(chunk.data, chunk.owner)
		if !ok {
			at = 0
		}
		out = append(out, streamproxy.Kept{Data: chunk.data, Owner: chunk.owner, At: at})
	}
	s.recv, s.recvBytes = nil, 0
	return out
}

func (s *muxStream) PeerEnded() bool {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	return s.writeClosed && s.peerDeliveredLocked() > s.sendStart+s.finOffset-s.sendMark
}

func (s *muxStream) Done() <-chan struct{} { return s.ctx.Done() }

func (s *muxStream) OnDelivered(notify func()) {
	s.m.mu.Lock()
	s.onDelivered = notify
	s.m.mu.Unlock()
}

func (s *muxStream) SetRetention(k *streamproxy.Keep) {
	s.m.mu.Lock()
	s.keep = k
	s.m.mu.Unlock()
}

func (s *muxStream) Leftover() []byte {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	left := s.leftover
	s.leftover = nil
	return left
}

// Ended reports, after Read returned io.EOF, that the FIN ended the session's
// direction.
func (s *muxStream) Ended() bool {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	return s.peerEnd
}

// Aborted reports that the peer reset the session's connection.
func (s *muxStream) Aborted() bool {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	return s.peerAborted
}

// AbortSession resets the hop as a reset of the session's connection.
func (s *muxStream) AbortSession() {
	m := s.m
	m.mu.Lock()
	if s.err == nil {
		s.failLocked(errStreamReset)
		m.resetKindLocked(s.id, true)
	}
	l := m.current
	m.mu.Unlock()
	if l != nil {
		l.WakeStreams()
	}
}
