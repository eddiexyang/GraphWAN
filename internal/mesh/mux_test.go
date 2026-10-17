package mesh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/link"
	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
)

var memChannelID atomic.Uint64

// memChannel is one end of an in-memory, ordered and reliable Channel.
type memChannel struct {
	id   string
	in   chan []byte
	out  chan []byte
	done chan struct{}
	peer *memChannel
	once sync.Once
	sent atomic.Uint64
	// streamKinds counts sent stream hello and stream messages.
	streamKinds atomic.Uint64
}

func memChannelPair() (*memChannel, *memChannel) {
	a2b, b2a := make(chan []byte, 4096), make(chan []byte, 4096)
	id := fmt.Sprintf("mem-%d", memChannelID.Add(1))
	a := &memChannel{id: id, in: b2a, out: a2b, done: make(chan struct{})}
	b := &memChannel{id: id, in: a2b, out: b2a, done: make(chan struct{})}
	a.peer, b.peer = b, a
	return a, b
}
func (c *memChannel) ID() string { return c.id }
func (c *memChannel) Send(ctx context.Context, raw []byte) error {
	c.sent.Add(1)
	if len(raw) > 0 && (raw[0] == streamMessageKind || raw[0] == streamMessageKind-1) {
		c.streamKinds.Add(1)
	}
	select {
	case c.out <- append([]byte(nil), raw...):
		return nil
	case <-c.done:
		return net.ErrClosed
	case <-c.peer.done:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (c *memChannel) Receive(ctx context.Context) ([]byte, error) {
	select {
	case raw := <-c.in:
		return raw, nil
	case <-c.done:
		return nil, net.ErrClosed
	case <-c.peer.done:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (c *memChannel) Close() error         { c.once.Do(func() { close(c.done) }); return nil }
func (c *memChannel) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }
func (c *memChannel) NeedsRekey() bool     { return false }
func (c *memChannel) Created() time.Time   { return time.Now() }

type muxPair struct {
	ctx      context.Context
	a, b     *mux
	accepted chan *muxStream
}

func newMuxPair(t *testing.T) *muxPair {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p := &muxPair{ctx: ctx, accepted: make(chan *muxStream, 64)}
	p.a = newMux(&group{ctx: ctx}, true, func(s *muxStream) { s.Abort() })
	p.b = newMux(&group{ctx: ctx}, false, func(s *muxStream) { p.accepted <- s })
	return p
}

var linkOptions = link.Options{Heartbeat: 20 * time.Millisecond, Timeout: 400 * time.Millisecond}

// connect creates one Link on each side. The acceptor (b) announces streams
// unless it does not support them.
func (p *muxPair) connect(t *testing.T, acceptorStreams bool) (*link.Link, *link.Link, *memChannel) {
	t.Helper()
	ca, cb := memChannelPair()
	info := func(peer int) link.Info {
		return link.Info{NetworkID: testutil.ID(1), EdgeID: testutil.ID(2), PeerID: testutil.ID(peer), CandidateID: ca.id, Transport: model.TCP}
	}
	oa, ob := linkOptions, linkOptions
	oa.Streams = p.a
	if acceptorStreams {
		ob.Streams, ob.StreamHello = p.b, true
	}
	la, err := link.New(p.ctx, ca, info(3), oa)
	if err != nil {
		t.Fatal(err)
	}
	lb, err := link.New(p.ctx, cb, info(4), ob)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { la.Close(); lb.Close() })
	return la, lb, ca
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (p *muxPair) accept(t *testing.T) *muxStream {
	t.Helper()
	select {
	case s := <-p.accepted:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("stream was not accepted")
		return nil
	}
}

func TestMuxStreamsShareOneLink(t *testing.T) {
	p := newMuxPair(t)
	p.connect(t, true)
	waitFor(t, "streams", p.a.Available)
	const count = 16
	var wg sync.WaitGroup
	errs := make(chan error, count)
	for i := range count {
		s, err := p.a.Open(p.ctx)
		if err != nil {
			t.Fatal(err)
		}
		payload := bytes.Repeat([]byte{byte(i)}, 300*1024+i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer s.Close()
			if _, err := s.Write(payload); err != nil {
				errs <- err
				return
			}
			s.CloseWrite()
			echo, err := io.ReadAll(s)
			if err == nil && !bytes.Equal(echo, payload) {
				err = errors.New("echo changed")
			}
			errs <- err
		}()
	}
	for range count {
		s := p.accept(t)
		go func() {
			defer s.Close()
			raw, err := io.ReadAll(s)
			if err == nil {
				s.Write(raw)
				s.CloseWrite()
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "graceful stream cleanup", func() bool {
		p.a.mu.Lock()
		defer p.a.mu.Unlock()
		return len(p.a.streams) == 0
	})
}

// Closing the Link in use moves streams to another Link; unacknowledged bytes
// are sent again and the receiver keeps each byte exactly once, in order.
func TestMuxStreamSurvivesLinkChange(t *testing.T) {
	p := newMuxPair(t)
	first, _, _ := p.connect(t, true)
	waitFor(t, "streams", p.a.Available)
	p.connect(t, true)
	waitFor(t, "second link health", func() bool {
		p.a.mu.Lock()
		defer p.a.mu.Unlock()
		healthy := 0
		for l := range p.a.ready {
			if l.Healthy() {
				healthy++
			}
		}
		return healthy == 2
	})
	s, err := p.a.Open(p.ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 48<<20)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	want := sha256.Sum256(payload)
	writeErr := make(chan error, 1)
	go func() {
		_, err := s.Write(payload)
		if err == nil {
			err = s.CloseWrite()
		}
		writeErr <- err
	}()
	r := p.accept(t)
	half := make([]byte, 16<<20)
	if _, err := io.ReadFull(r, half); err != nil {
		t.Fatal(err)
	}
	first.Close()
	rest, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256.Sum256(append(half, rest...)); got != want {
		t.Fatalf("bytes changed across the Link change: got %d bytes", len(half)+len(rest))
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
}

// One stream whose reader stops must not hold up another on the same Link.
func TestMuxFlowControlIsolatesStreams(t *testing.T) {
	p := newMuxPair(t)
	p.connect(t, true)
	waitFor(t, "streams", p.a.Available)
	stalled, err := p.a.Open(p.ctx)
	if err != nil {
		t.Fatal(err)
	}
	filled := make(chan error, 1)
	go func() {
		_, err := stalled.Write(make([]byte, muxWindow))
		filled <- err
	}()
	idle := p.accept(t) // never read
	if err := <-filled; err != nil {
		t.Fatal(err)
	}
	blocked := make(chan struct{})
	go func() {
		stalled.Write([]byte{1})
		close(blocked)
	}()
	select {
	case <-blocked:
		t.Fatal("write beyond the receive window did not wait")
	case <-time.After(100 * time.Millisecond):
	}
	other, err := p.a.Open(p.ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("other"), 200*1024)
	go func() {
		other.Write(payload)
		other.CloseWrite()
	}()
	r := p.accept(t)
	raw, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(raw, payload) {
		t.Fatal("second stream was held up", err)
	}
	// Reading the first stream reopens its window.
	if _, err := io.ReadFull(idle, make([]byte, muxWindow)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("window did not reopen")
	}
}

func TestMuxResetReachesPeer(t *testing.T) {
	p := newMuxPair(t)
	p.connect(t, true)
	waitFor(t, "streams", p.a.Available)
	s, err := p.a.Open(p.ctx)
	if err != nil {
		t.Fatal(err)
	}
	s.Write([]byte("hello"))
	r := p.accept(t)
	if _, err := io.ReadFull(r, make([]byte, 5)); err != nil {
		t.Fatal(err)
	}
	s.Abort()
	if _, err := r.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatal("reset not delivered", err)
	}
	if _, err := s.Write([]byte("x")); err == nil {
		t.Fatal("write after abort")
	}
}

// An acceptor without stream support never receives a stream frame, which
// would make it close the Link.
func TestMuxRequiresAcceptorSupport(t *testing.T) {
	p := newMuxPair(t)
	la, lb, channel := p.connect(t, false)
	waitFor(t, "link health", la.Healthy)
	time.Sleep(100 * time.Millisecond)
	if p.a.Available() {
		t.Fatal("streams offered without acceptor support")
	}
	if _, err := p.a.Open(p.ctx); err == nil {
		t.Fatal("stream opened without acceptor support")
	}
	if !la.Healthy() || !lb.Healthy() {
		t.Fatal("link closed")
	}
	if channel.streamKinds.Load() != 0 || channel.peer.streamKinds.Load() != 0 {
		t.Fatal("stream message sent without acceptor support")
	}
}

// Each ReadInto models one small access-stack read while the TCP connection
// remains open. It deliberately never fills the mux batch.
type sparseMuxReader struct {
	payload []byte
	reads   int
}

func (r *sparseMuxReader) Read([]byte) (int, error) { panic("ReadInto bypassed") }
func (r *sparseMuxReader) ReadInto(w io.Writer) (int, error) {
	if r.reads == 0 {
		return 0, io.EOF
	}
	r.reads--
	return w.Write(r.payload)
}

func TestMuxSparseBatchStorage(t *testing.T) {
	p := newMuxPair(t)
	s := p.a.newStreamLocked(2)
	for _, size := range []int{1, 31, muxMaxData - 1, muxMaxData, muxMaxData + 7, 64 << 10, muxBurst * muxMaxData} {
		b := newFrameBuilder(s.id, s.sendNext, muxBurst*muxMaxData)
		payload := bytes.Repeat([]byte("x"), size)
		b.Write(payload)
		original := &b.chunk[0]
		if err := s.publish(b); err != nil {
			t.Fatal(err)
		}
		if size < muxMaxData && len(b.chunk) > 2*b.used {
			t.Errorf("%d bytes retained a %d-byte batch", size, len(b.chunk))
		}
		if size >= muxMaxData && &b.chunk[0] != original {
			t.Fatal("bulk read was copied")
		}
		var got []byte
		for _, f := range b.frames {
			got = append(got, f.raw[muxDataHeader:]...)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("compaction changed payload")
		}
		p.a.receiveAck(s.id, s.sendNext, muxWindow)
	}
}

func TestMuxSparseACKAndCredit(t *testing.T) {
	p := newMuxPair(t)
	s := p.a.newStreamLocked(2)
	const reads = 72
	payload := bytes.Repeat([]byte("x"), 31)
	transfer := func(from, to *mux) int {
		var dst [128][]byte
		n := from.PullStream(nil, dst[:])
		for _, raw := range dst[:n] {
			if !to.ReceiveStream(nil, raw[1:]) {
				t.Fatal("invalid frame")
			}
		}
		return n
	}
	for cycle := range 8 {
		if n, err := s.ReadFrom(&sparseMuxReader{payload, reads}); err != nil || n != reads*int64(len(payload)) {
			t.Fatal(n, err)
		}
		if transfer(p.a, p.b) != reads {
			t.Fatal("missing frames")
		}
		if cycle == 0 {
			<-p.accepted
		}
		r := p.b.streams[s.id]
		// A Link change replays the compacted, unacknowledged frames. The
		// receiver must retain each byte once and acknowledge the same offset.
		p.a.switchLocked(nil)
		if transfer(p.a, p.b) != reads+1 {
			t.Fatal("Link change did not resend data and receive state")
		}
		if r.recvBytes != reads*len(payload) || r.received != uint64((cycle+1)*reads*len(payload)) {
			t.Fatal("Link change duplicated sparse messages")
		}
		before := s.peerLimit
		p.b.maintain()
		if transfer(p.b, p.a) != 1 || len(s.frames) != 0 {
			t.Fatal("small unread messages were not acknowledged")
		}
		if s.peerLimit != before {
			t.Fatal("unread bytes granted receive credit")
		}
		got := make([]byte, reads*len(payload))
		if _, err := io.ReadFull(r, got); err != nil || !bytes.Equal(got, bytes.Repeat(payload, reads)) {
			t.Fatal("payload changed", err)
		}
		p.b.maintain()
		if transfer(p.b, p.a) != 1 || s.peerLimit != before+uint64(len(got)) {
			t.Fatal("small reads did not reopen credit")
		}
		p.b.maintain()
		if transfer(p.b, p.a) != 0 {
			t.Fatal("idle stream emitted ACK")
		}
	}
}

func BenchmarkMuxBatchPublish(b *testing.B) {
	for _, size := range []int{31, 64 << 10, muxBurst * muxMaxData} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			m := newMux(&group{ctx: ctx}, true, nil)
			s := m.newStreamLocked(2)
			payload := bytes.Repeat([]byte("x"), size)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				batch := newFrameBuilder(s.id, s.sendNext, muxBurst*muxMaxData)
				batch.Write(payload)
				if err := s.publish(batch); err != nil {
					b.Fatal(err)
				}
				m.receiveAck(s.id, s.sendNext, s.sendNext+muxWindow)
			}
		})
	}
}

// Keep the receiver alive across sender restarts, as happens when only one
// production Agent is upgraded. Both live streams and tombstones survive.
func TestMuxRestartKeepsNewStreamsDistinct(t *testing.T) {
	for _, even := range []bool{false, true} {
		t.Run(fmt.Sprint(even), func(t *testing.T) {
			p := newMuxPair(t)
			p.b = newMux(&group{ctx: p.ctx}, !even, func(s *muxStream) { p.accepted <- s })
			seen := map[uint64]bool{}
			for restart := range 16 {
				fresh := newMux(&group{ctx: p.ctx}, even, nil)
				// Open only needs a selected Link. Frames are delivered below
				// synchronously so old receive state survives deterministically.
				fresh.current = &link.Link{}
				s, err := fresh.Open(p.ctx)
				if err != nil {
					t.Fatal(err)
				}
				if s.id == 0 || (s.id%2 == 0) != even || seen[s.id] {
					t.Fatalf("restart %d reused or invalidated stream ID %d", restart, s.id)
				}
				seen[s.id] = true
				payload := fmt.Sprintf("request after restart %d", restart)
				if _, err := s.Write([]byte(payload)); err != nil {
					t.Fatal(err)
				}
				if !p.b.ReceiveStream(nil, s.frames[0].raw[1:]) || len(p.accepted) != 1 {
					t.Fatal("surviving peer rejected the new stream")
				}
				r := <-p.accepted
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(r, got); err != nil || string(got) != payload {
					t.Fatal("restart changed payload", err)
				}
				if restart%2 == 0 {
					r.Close()
				}
				fresh.close()
			}
		})
	}
}

func TestMuxStreamIDExhaustion(t *testing.T) {
	p := newMuxPair(t)
	p.a.current = &link.Link{}
	p.a.next = ^uint64(0) - 1
	s, err := p.a.Open(p.ctx)
	if err != nil || s.id != ^uint64(0)-1 {
		t.Fatal("last ID was not usable", err)
	}
	if _, err := p.a.Open(p.ctx); err == nil {
		t.Fatal("stream ID wrapped around")
	}
}
