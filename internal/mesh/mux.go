package mesh

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
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
	muxData  = 1
	muxAck   = 2
	muxReset = 3

	muxFin = 1
	// With muxFin on a TCP session hop: the session's direction ended. Session
	// hops are torn down by resets, so their FINs always carry it.
	muxEnd = 2

	// link kind + frame type + stream ID
	muxHeader     = 1 + 1 + 8
	muxDataHeader = muxHeader + 8 + 1
	muxAckSize    = muxHeader + 8 + 8
	muxMaxData    = secure.MaxPlaintext - muxDataHeader
	// A TCP session relay's acknowledgements add the far end's delivered
	// offset; a session reset adds whether it resets the connection.
	muxSessionAckSize = muxAckSize + 8
	muxAbortSize      = muxHeader + 1

	// The receive window covers one stream at 3 Gbit/s over 80 ms.
	muxWindow       = 32 << 20
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
	s := m.newStreamLocked(m.next)
	if m.next > ^uint64(0)-2 {
		m.next = 0
	} else {
		m.next += 2
	}
	return s, nil
}

func (m *mux) newStreamLocked(id uint64) *muxStream {
	ctx, cancel := context.WithCancel(m.g.ctx)
	s := &muxStream{m: m, id: id, ctx: ctx, cancel: cancel, peerLimit: muxWindow, advertised: muxWindow, sendWake: make(chan struct{}, 1), readWake: make(chan struct{}, 1)}
	m.streams[id] = s
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
	// ACK receipt independently of application consumption. Small messages
	// release retransmission storage even when the reader has stopped; only
	// consumed bytes increase the receive window.
	for _, s := range m.streams {
		if s.received != s.ackReceived || s.consumed+muxWindow > s.advertised || s.session && !s.local && s.delivered != s.ackDelivered {
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
	if flags&^(muxFin|muxEnd) != 0 || flags&muxEnd != 0 && flags&muxFin == 0 || flags&muxFin != 0 && len(data) != 0 {
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
		s = m.newStreamLocked(id)
		accepted = true
	}
	if s.err != nil {
		m.mu.Unlock()
		return true
	}
	end := offset + uint64(len(data))
	if end > max(s.advertised, s.consumed+muxWindow) || s.finRecv && end > s.finAt {
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
	m.mu.Lock()
	s := m.streams[id]
	if s == nil || s.err != nil {
		m.mu.Unlock()
		return
	}
	before := s.peerDeliveredLocked()
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
		s.frames = s.frames[drop:]
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
	finRecv     bool
	finAt       uint64

	closed   bool
	err      error
	sendWake chan struct{}
	readWake chan struct{}

	// A TCP session hop; see streamproxy.Hop. Its session offsets count from
	// sendStart at this stream's offset sendMark.
	session       bool
	sendStart     uint64
	sendMark      uint64
	local         bool   // the far end infers delivery from what this end consumed
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

func (s *muxStream) ackFrameLocked() []byte {
	size := muxAckSize
	if s.session && !s.local {
		size = muxSessionAckSize
	}
	raw := make([]byte, size)
	frameHeader(raw, muxAck, s.id)
	received := s.received
	if s.finRecv {
		received++
	}
	limit := s.consumed + muxWindow
	binary.BigEndian.PutUint64(raw[10:18], received)
	binary.BigEndian.PutUint64(raw[18:26], limit)
	if size == muxSessionAckSize {
		binary.BigEndian.PutUint64(raw[26:34], s.delivered)
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
	if s.sealed.Load() {
		b.kind = sealedStreamKind
	}
	return b
}

func (b *frameBuilder) Write(data []byte) (int, error) {
	written := 0
	// room is a frame's plaintext, after prefix bytes of record length.
	room, prefix, overhead := muxMaxData, 0, 0
	if b.records != nil {
		room, prefix, overhead = muxMaxData-streamproxy.RecordOverhead, streamproxy.RecordHeader, streamproxy.RecordOverhead
	}
	for len(data) > 0 && b.bytes < b.limit {
		last := len(b.frames) - 1
		if last < 0 || len(b.frames[last].raw)-muxDataHeader-prefix == room {
			if b.limit-b.bytes <= overhead {
				break
			}
			buf := packetbuf.Get(muxDataHeader + muxMaxData)
			// Pooled storage is not cleared: every header byte is written.
			raw := buf.Data[:muxDataHeader]
			frameHeader(raw, muxData, b.id)
			raw[0] = b.kind
			binary.BigEndian.PutUint64(raw[10:18], b.offset+uint64(b.bytes))
			raw[18] = 0 // flags
			raw = raw[:muxDataHeader+prefix]
			b.bytes += overhead
			b.frames = append(b.frames, muxFrame{raw: raw, buf: buf})
			last++
		}
		frame := &b.frames[last]
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
	room, prefix, overhead := muxMaxData, 0, 0
	if b.records != nil {
		room, prefix, overhead = muxMaxData-streamproxy.RecordOverhead, streamproxy.RecordHeader, streamproxy.RecordOverhead
	}
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
	raw[18] = 0 // flags
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
		start, limit, err := s.reserve()
		if err != nil {
			return written, err
		}
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
	var total int64
	for {
		start, limit, err := s.reserve()
		if err != nil {
			return total, err
		}
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
	raw[18] = muxFin
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
	s.consumed += uint64(n)
	var l *link.Link
	// A session hop that read up to its FIN acknowledges at once: the far end
	// finishes the session only when it learns that everything was delivered.
	if (s.consumed+muxWindow-s.advertised >= muxAckThreshold || s.session && s.finRecv && s.consumed == s.finAt && s.consumed+muxWindow > s.advertised) && s.err == nil {
		s.ackDue = true
		m.enqueueLocked(s)
		l = m.current
	}
	m.mu.Unlock()
	if l != nil {
		l.WakeStreams()
	}
	return n, nil
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
			if s.session && (s.consumed+muxWindow > s.advertised || s.received != s.ackReceived || !s.local && s.delivered != s.ackDelivered) {
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
	for _, chunk := range s.recv {
		chunk.owner.Release()
	}
	s.frames, s.recv, s.recvBytes = nil, nil, 0
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
