package mesh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
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
	"github.com/eWloYW8/GraphWAN/internal/packetbuf"
	"github.com/eWloYW8/GraphWAN/internal/streamproxy"
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
	p.a.g.mesh = &Mesh{}
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
	if p.a.g.mesh.Counters()["mux_resent_frames"] == 0 {
		t.Fatal("frames sent again after the Link change were not counted")
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

// A builder takes one pooled buffer per frame it fills, however much the read
// window allowed.
func TestMuxSparseBatchStorage(t *testing.T) {
	p := newMuxPair(t)
	s := p.a.newStreamLocked(2)
	for _, size := range []int{1, 31, muxMaxData - 1, muxMaxData, muxMaxData + 7, 64 << 10, muxBurst * muxMaxData} {
		b := newFrameBuilder(s.id, s.sendNext, muxBurst*muxMaxData, nil)
		payload := bytes.Repeat([]byte("x"), size)
		b.Write(payload)
		if err := s.publish(b); err != nil {
			t.Fatal(err)
		}
		if want := (size + muxMaxData - 1) / muxMaxData; len(b.frames) != want {
			t.Errorf("%d bytes took %d frames, want %d", size, len(b.frames), want)
		}
		var got []byte
		for _, f := range b.frames {
			if f.buf == nil || &f.raw[0] != &f.buf.Data[0] {
				t.Fatal("frame not in its pooled buffer")
			}
			got = append(got, f.raw[muxDataHeader:]...)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("payload changed")
		}
		p.a.receiveAck(s.id, s.sendNext, muxWindow, 0, false)
	}
}

func TestMuxSparseACKAndCredit(t *testing.T) {
	p := newMuxPair(t)
	s := p.a.newStreamLocked(2)
	const reads = 72
	payload := bytes.Repeat([]byte("x"), 31)
	transfer := func(from, to *mux) int {
		var dst [128][]byte
		var owners [128]*packetbuf.Buffer
		n := from.PullStream(nil, dst[:], owners[:])
		for i, raw := range dst[:n] {
			if !to.ReceiveStream(nil, raw[1:], nil) {
				t.Fatal("invalid frame")
			}
			owners[i].Release()
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
				batch := newFrameBuilder(s.id, s.sendNext, muxBurst*muxMaxData, nil)
				batch.Write(payload)
				if err := s.publish(batch); err != nil {
					b.Fatal(err)
				}
				m.receiveAck(s.id, s.sendNext, s.sendNext+muxWindow, 0, false)
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
				if !p.b.ReceiveStream(nil, s.frames[0].raw[1:], nil) || len(p.accepted) != 1 {
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

// A data frame's pooled buffer returns only after the stream, the session's
// keep and the sending Link have all let it go, in any order.
func TestMuxFrameBufferOwners(t *testing.T) {
	p := newMuxPair(t)
	s := p.a.newStreamLocked(2)
	s.Begin(0)
	keep := streamproxy.NewKeep()
	s.SetRetention(keep)
	if _, err := s.Write(bytes.Repeat([]byte("x"), 3*muxMaxData)); err != nil {
		t.Fatal(err)
	}
	frames := append([]muxFrame(nil), s.frames...)
	var dst [16][]byte
	var owners [16]*packetbuf.Buffer
	n := p.a.PullStream(nil, dst[:], owners[:])
	freed := func() int {
		count := 0
		for _, f := range frames {
			if f.buf.Data == nil {
				count++
			}
		}
		return count
	}
	p.a.receiveAck(s.id, s.sendNext, muxWindow, 0, false) // the stream lets go
	keep.Release(uint64(3 * muxMaxData))                  // delivered
	if freed() != 0 {
		t.Fatal("a buffer returned while the Link still sent it")
	}
	packetbuf.ReleaseAll(owners[:n])
	if freed() != len(frames) {
		t.Fatalf("%d of %d buffers returned", freed(), len(frames))
	}
}

// Frames built in reused pooled storage carry no stale header bytes.
func TestMuxFrameHeaderInReusedStorage(t *testing.T) {
	for range 64 {
		b := packetbuf.Get(muxDataHeader + muxMaxData)
		for i := range b.Data {
			b.Data[i] = 0xff
		}
		b.Release()
	}
	builder := newFrameBuilder(7, 100, 3, nil)
	builder.Write([]byte("abc"))
	frame := builder.finish()[0]
	want := make([]byte, muxDataHeader)
	frameHeader(want, muxData, 7)
	binary.BigEndian.PutUint64(want[10:18], 100)
	if !bytes.Equal(frame.raw[:muxDataHeader], want) {
		t.Fatalf("header %x, want %x", frame.raw[:muxDataHeader], want)
	}
	builder.release()
}

// Received bytes stay in the Link's buffer, which returns once they are read.
func TestMuxReceiveKeepsLinkBuffer(t *testing.T) {
	p := newMuxPair(t)
	s := p.a.newStreamLocked(2)
	if _, err := s.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	var dst [4][]byte
	var owners [4]*packetbuf.Buffer
	n := p.a.PullStream(nil, dst[:], owners[:])
	packetbuf.ReleaseAll(owners[:n])
	received := packetbuf.Get(len(dst[0]) - 1)
	copy(received.Data, dst[0][1:])
	if !p.b.ReceiveStream(nil, received.Data, received) {
		t.Fatal("invalid frame")
	}
	received.Release() // the Link is done with it
	if received.Data == nil {
		t.Fatal("buffer returned while its bytes were unread")
	}
	r := <-p.accepted
	got := make([]byte, 5)
	if _, err := io.ReadFull(r, got); err != nil || string(got) != "hello" {
		t.Fatal(string(got), err)
	}
	if received.Data != nil {
		t.Fatal("buffer kept after its bytes were read")
	}
}

// A session's kept bytes go out on its next hop in the buffers that hold them,
// once no Link still sends their earlier frame, and arrive unchanged.
func TestMuxResendsKeptBuffers(t *testing.T) {
	p := newMuxPair(t)
	old := p.a.newStreamLocked(2)
	old.Begin(0)
	keep := streamproxy.NewKeep()
	old.SetRetention(keep)
	payload := bytes.Repeat([]byte("kept"), muxMaxData/4)
	if _, err := old.Write(payload); err != nil {
		t.Fatal(err)
	}
	original := old.frames[0]
	// A Link is still sending the old frame when the hop fails.
	var dst [4][]byte
	var owners [4]*packetbuf.Buffer
	n := p.a.PullStream(nil, dst[:], owners[:])
	p.a.mu.Lock()
	old.failLocked(errStreamReset)
	p.a.mu.Unlock()

	next := p.a.newStreamLocked(4)
	next.Begin(0)
	chunks, ok := keep.From(0)
	if !ok || len(chunks) != 1 {
		t.Fatal("nothing kept")
	}
	sent := make(chan bool, 1)
	go func() {
		ok, err := next.WriteKept(chunks[0])
		if err != nil {
			t.Error(err)
		}
		sent <- ok
	}()
	select {
	case <-sent:
		t.Fatal("rewrote a header a Link was still sending")
	case <-time.After(50 * time.Millisecond):
	}
	packetbuf.ReleaseAll(owners[:n]) // the Link is done
	if !<-sent {
		t.Fatal("kept buffer not reused")
	}
	chunks[0].Owner.Release()
	frame := next.frames[0]
	if frame.buf != original.buf || &frame.raw[muxDataHeader] != &original.raw[muxDataHeader] {
		t.Fatal("kept bytes were copied")
	}
	if id := binary.BigEndian.Uint64(frame.raw[2:10]); id != next.id {
		t.Fatalf("frame for stream %d, want %d", id, next.id)
	}
	n = p.a.PullStream(nil, dst[:], owners[:])
	for i, raw := range dst[:n] {
		if !p.b.ReceiveStream(nil, raw[1:], nil) {
			t.Fatal("invalid frame")
		}
		owners[i].Release()
	}
	r := p.b.streams[next.id]
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(r, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatal("resent bytes changed", err)
	}
}

// A stream reads no further ahead of its Link than muxQueue: a writer waits
// while the Link writer has that much waiting, and continues once it pulls.
func TestMuxWritersWaitForTheLink(t *testing.T) {
	p := newMuxPair(t)
	s := p.a.newStreamLocked(2)
	wrote := make(chan int, 1)
	go func() {
		n, _ := s.Write(make([]byte, 3*muxQueue))
		wrote <- n
	}()
	waitFor(t, "the queue to fill", func() bool {
		p.a.mu.Lock()
		defer p.a.mu.Unlock()
		return p.a.queued >= muxQueue
	})
	select {
	case n := <-wrote:
		t.Fatalf("wrote %d bytes past a full queue", n)
	case <-time.After(50 * time.Millisecond):
	}
	p.a.mu.Lock()
	if p.a.queued > muxQueue+muxBurst*(muxDataHeader+muxMaxData) {
		t.Errorf("%d bytes queued, want about %d", p.a.queued, muxQueue)
	}
	p.a.mu.Unlock()
	var dst [128][]byte
	var owners [128]*packetbuf.Buffer
	done := time.After(10 * time.Second)
	for {
		select {
		case n := <-wrote:
			if n != 3*muxQueue {
				t.Fatalf("wrote %d", n)
			}
			p.a.mu.Lock()
			defer p.a.mu.Unlock()
			if p.a.queued != s.queued {
				t.Fatalf("Edge queues %d, its one stream %d", p.a.queued, s.queued)
			}
			return
		case <-done:
			t.Fatal("writer did not continue as the Link pulled")
		default:
		}
		n := p.a.PullStream(nil, dst[:], owners[:])
		packetbuf.ReleaseAll(owners[:n])
		p.a.receiveAck(s.id, s.sendNext, s.sendNext+muxWindow, 0, false)
		time.Sleep(time.Millisecond)
	}
}

// A stream that starts writing while another fills the queue, as a session
// sending again on a new chain does, is queued at once with its share.
func TestMuxLaterStreamIsNotQueuedBehindABacklog(t *testing.T) {
	p := newMuxPair(t)
	first := p.a.newStreamLocked(2)
	go first.Write(make([]byte, 3*muxQueue))
	waitFor(t, "the queue to fill", func() bool {
		p.a.mu.Lock()
		defer p.a.mu.Unlock()
		return p.a.queued >= muxQueue
	})
	later := p.a.newStreamLocked(4)
	wrote := make(chan error, 1)
	go func() {
		_, err := later.Write(make([]byte, muxQueue/4))
		wrote <- err
	}()
	select {
	case err := <-wrote:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a later stream waited behind another's backlog")
	}
	p.a.mu.Lock()
	defer p.a.mu.Unlock()
	if p.a.queued > 2*muxQueue+muxBurst*(muxDataHeader+muxMaxData) {
		t.Errorf("%d bytes queued, want at most about %d", p.a.queued, 2*muxQueue)
	}
	if first.queued > muxQueue+muxBurst*(muxDataHeader+muxMaxData) {
		t.Errorf("the first stream queued %d bytes, want about %d", first.queued, muxQueue)
	}
}
