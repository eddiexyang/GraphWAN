package mesh

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/link"
	"github.com/eWloYW8/GraphWAN/internal/secure"
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

	// link kind + frame type + stream ID
	muxHeader     = 1 + 1 + 8
	muxDataHeader = muxHeader + 8 + 1
	muxAckSize    = muxHeader + 8 + 8
	muxMaxData    = secure.MaxPlaintext - muxDataHeader

	// The receive window covers one stream at 3 Gbit/s over 80 ms.
	muxWindow       = 32 << 20
	muxAckThreshold = 256 << 10
	muxMaxStreams   = 4096
	// Frames handed to one Link writer per stream before others get a turn.
	muxBurst = 16
	// Streams wait this long for an Edge to regain a stream-capable Link.
	muxLinkLoss = 30 * time.Second
	// Ended peer streams are remembered so frames sent again after a Link
	// change cannot start them a second time.
	muxTombstoneLifetime = 10 * time.Minute
	muxMaxTombstones     = 1 << 16
)

// streamMessageKind mirrors the Link message kind that prefixes every frame.
const streamMessageKind = 12

var errStreamReset = &streamError{syscall.ECONNRESET}

type streamError struct{ errno syscall.Errno }

func (e *streamError) Error() string { return "peer stream reset" }
func (e *streamError) Unwrap() error { return e.errno }

type muxFrame struct {
	end uint64 // offset after this frame; a FIN occupies one virtual byte
	raw []byte
}

type mux struct {
	g         *group
	even      bool
	handler   func(*muxStream)
	mu        sync.Mutex
	ready     map[*link.Link]bool
	current   *link.Link
	next      uint64
	ended     map[uint64]time.Time
	lastPurge time.Time
	streams   map[uint64]*muxStream
	pending   []*muxStream
	queued    map[*muxStream]bool
	resets    []uint64
	lostSince time.Time
	closed    bool
}

func newMux(g *group, even bool, handler func(*muxStream)) *mux {
	m := &mux{g: g, even: even, handler: handler, ready: map[*link.Link]bool{}, streams: map[uint64]*muxStream{}, queued: map[*muxStream]bool{}, ended: map[uint64]time.Time{}}
	if even {
		m.next = 2
	} else {
		m.next = 1
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

func (m *mux) Open(ctx context.Context) (*muxStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.current == nil {
		return nil, link.ErrUnavailable
	}
	if len(m.streams) >= muxMaxStreams {
		return nil, errors.New("edge stream limit reached")
	}
	s := m.newStreamLocked(m.next)
	m.next += 2
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
	for _, s := range m.streams {
		s.unsent = 0
		s.ackDue = true
		m.enqueueLocked(s)
	}
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
	if m.current == nil && !m.lostSince.IsZero() && time.Since(m.lostSince) >= muxLinkLoss {
		for _, s := range m.streams {
			failed = append(failed, s)
		}
	}
	for _, s := range failed {
		s.failLocked(errStreamReset)
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

func (m *mux) enqueueLocked(s *muxStream) {
	if !m.queued[s] {
		m.queued[s] = true
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

func (m *mux) resetLocked(id uint64) {
	if len(m.resets) < 1024 {
		m.resets = append(m.resets, id)
	}
}

func frameHeader(raw []byte, kind byte, id uint64) {
	raw[0] = streamMessageKind
	raw[1] = kind
	binary.BigEndian.PutUint64(raw[2:10], id)
}

// PullStream hands the Link writer immutable frames. Frames stay referenced by
// their stream until acknowledged, so a later Link can send them again.
func (m *mux) PullStream(l *link.Link, dst [][]byte) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l != m.current {
		return 0
	}
	n := 0
	for n < len(dst) && len(m.resets) > 0 {
		raw := make([]byte, muxHeader)
		frameHeader(raw, muxReset, m.resets[0])
		m.resets = m.resets[1:]
		dst[n] = raw
		n++
	}
	for n < len(dst) && len(m.pending) > 0 {
		s := m.pending[0]
		m.pending[0] = nil
		m.pending = m.pending[1:]
		if s.ackDue {
			dst[n] = s.ackFrameLocked()
			n++
		}
		for burst := 0; burst < muxBurst && n < len(dst) && s.unsent < len(s.frames); burst++ {
			dst[n] = s.frames[s.unsent].raw
			s.unsent++
			n++
		}
		if s.ackDue || s.unsent < len(s.frames) {
			m.pending = append(m.pending, s)
		} else {
			delete(m.queued, s)
		}
	}
	return n
}

// ReceiveStream copies what it keeps: the Link reuses raw after returning.
func (m *mux) ReceiveStream(l *link.Link, raw []byte) bool {
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
		return m.receiveData(id, binary.BigEndian.Uint64(raw[9:17]), raw[17], raw[18:])
	case muxAck:
		if len(raw) != muxAckSize-1 {
			return false
		}
		m.receiveAck(id, binary.BigEndian.Uint64(raw[9:17]), binary.BigEndian.Uint64(raw[17:25]))
		return true
	case muxReset:
		if len(raw) != muxHeader-1 {
			return false
		}
		m.mu.Lock()
		if s := m.streams[id]; s != nil {
			s.failLocked(errStreamReset)
		}
		m.mu.Unlock()
		return true
	default:
		return false
	}
}

func (m *mux) receiveData(id, offset uint64, flags byte, data []byte) bool {
	if flags&^muxFin != 0 || flags&muxFin != 0 && len(data) != 0 {
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
		if !m.peerStream(id) || ended || offset != 0 || len(m.streams) >= muxMaxStreams {
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
		chunk := append([]byte(nil), data[s.received-offset:]...)
		s.recv = append(s.recv, chunk)
		s.recvBytes += len(chunk)
		s.received = end
		s.rx.Add(uint64(len(chunk)))
		signal(s.readWake)
	}
	if flags&muxFin != 0 && offset == s.received && !s.finRecv {
		s.finRecv, s.finAt = true, offset
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

func (m *mux) receiveAck(id, received, limit uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.streams[id]
	if s == nil || s.err != nil {
		return
	}
	if received > s.acked {
		s.acked = received
		drop := 0
		for drop < len(s.frames) && s.frames[drop].end <= received {
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
	writeClosed bool
	finOffset   uint64

	recv       [][]byte
	recvBytes  int
	received   uint64
	consumed   uint64
	advertised uint64
	ackDue     bool
	finRecv    bool
	finAt      uint64

	closed   bool
	err      error
	sendWake chan struct{}
	readWake chan struct{}
}

func (s *muxStream) ackFrameLocked() []byte {
	raw := make([]byte, muxAckSize)
	frameHeader(raw, muxAck, s.id)
	received := s.received
	if s.finRecv {
		received++
	}
	limit := s.consumed + muxWindow
	binary.BigEndian.PutUint64(raw[10:18], received)
	binary.BigEndian.PutUint64(raw[18:26], limit)
	s.advertised = max(s.advertised, limit)
	s.ackDue = false
	return raw
}

// frameBuilder lays out data frames in one allocation as bytes arrive, as
// peer.Stream's record builder does. Frames stay referenced until acknowledged.
type frameBuilder struct {
	id     uint64
	offset uint64
	limit  int
	bytes  int
	chunk  []byte
	used   int
	frames []muxFrame
	starts []int
}

func newFrameBuilder(id, offset uint64, limit int) *frameBuilder {
	count := (limit + muxMaxData - 1) / muxMaxData
	return &frameBuilder{id: id, offset: offset, limit: limit, chunk: make([]byte, limit+count*muxDataHeader), frames: make([]muxFrame, 0, count), starts: make([]int, 0, count)}
}

func (b *frameBuilder) Write(data []byte) (int, error) {
	written := 0
	for len(data) > 0 && b.bytes < b.limit {
		last := len(b.frames) - 1
		if last < 0 || b.used-b.starts[last]-muxDataHeader == muxMaxData {
			raw := b.chunk[b.used : b.used+muxDataHeader]
			frameHeader(raw, muxData, b.id)
			binary.BigEndian.PutUint64(raw[10:18], b.offset+uint64(b.bytes))
			b.frames = append(b.frames, muxFrame{})
			b.starts = append(b.starts, b.used)
			b.used += muxDataHeader
			last++
		}
		n := min(len(data), b.limit-b.bytes, muxMaxData-(b.used-b.starts[last]-muxDataHeader))
		copy(b.chunk[b.used:], data[:n])
		b.used += n
		b.bytes += n
		written += n
		data = data[n:]
	}
	if len(data) > 0 {
		return written, io.ErrShortWrite
	}
	return written, nil
}

func (b *frameBuilder) finish() []muxFrame {
	offset := b.offset
	for i, start := range b.starts {
		end := b.used
		if i+1 < len(b.starts) {
			end = b.starts[i+1]
		}
		offset += uint64(end - start - muxDataHeader)
		b.frames[i] = muxFrame{end: offset, raw: b.chunk[start:end:end]}
	}
	return b.frames
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
		m.mu.Unlock()
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
	s.frames = append(s.frames, b.finish()...)
	s.sendNext += uint64(b.bytes)
	m.enqueueLocked(s)
	l := m.current
	m.mu.Unlock()
	if l != nil {
		l.WakeStreams()
	}
	s.tx.Add(uint64(b.bytes))
	return nil
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
		b := newFrameBuilder(s.id, start, min(len(p), limit))
		b.Write(p[:b.limit])
		if err := s.publish(b); err != nil {
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
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	var total int64
	for {
		start, limit, err := s.reserve()
		if err != nil {
			return total, err
		}
		b := newFrameBuilder(s.id, start, limit)
		n, readErr := reader.ReadInto(b)
		if n > 0 {
			if err := s.publish(b); err != nil {
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
	s.frames = append(s.frames, muxFrame{end: s.sendNext + 1, raw: raw})
	m.enqueueLocked(s)
	l := m.current
	m.mu.Unlock()
	if l != nil {
		l.WakeStreams()
	}
	return nil
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
		c := copy(p[n:], s.recv[0])
		n += c
		if c == len(s.recv[0]) {
			s.recv[0] = nil
			s.recv = s.recv[1:]
		} else {
			s.recv[0] = s.recv[0][c:]
		}
	}
	s.recvBytes -= n
	s.consumed += uint64(n)
	var l *link.Link
	if s.consumed+muxWindow-s.advertised >= muxAckThreshold && s.err == nil {
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
	if s.closed && s.writeClosed && s.acked > s.finOffset {
		s.failLocked(net.ErrClosed)
	}
}

func (s *muxStream) failLocked(err error) {
	if s.err != nil {
		return
	}
	s.err = err
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
