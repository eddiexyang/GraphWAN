package link

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/packet"
	"github.com/eWloYW8/GraphWAN/internal/packetbuf"
)

// pipeChannel is one end of an in-memory Channel pair that records every
// message it sends.
type pipeChannel struct {
	in, out chan []byte
	done    chan struct{}
	once    *sync.Once
	mu      sync.Mutex
	sent    [][]byte
}

func pipePair() (*pipeChannel, *pipeChannel) {
	ab, ba, done, once := make(chan []byte, 64), make(chan []byte, 64), make(chan struct{}), &sync.Once{}
	return &pipeChannel{in: ba, out: ab, done: done, once: once}, &pipeChannel{in: ab, out: ba, done: done, once: once}
}
func (c *pipeChannel) ID() string           { return "pipe" }
func (c *pipeChannel) RemoteAddr() net.Addr { return &net.TCPAddr{} }
func (c *pipeChannel) NeedsRekey() bool     { return false }
func (c *pipeChannel) Created() time.Time   { return time.Now() }
func (c *pipeChannel) Close() error         { c.once.Do(func() { close(c.done) }); return nil }
func (c *pipeChannel) Send(ctx context.Context, b []byte) error {
	b = bytes.Clone(b)
	c.mu.Lock()
	c.sent = append(c.sent, b)
	c.mu.Unlock()
	select {
	case c.out <- b:
		return nil
	case <-c.done:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (c *pipeChannel) Receive(ctx context.Context) ([]byte, error) {
	select {
	case b := <-c.in:
		return b, nil
	case <-c.done:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// dataSent returns the data messages this end has sent, by kind.
func (c *pipeChannel) dataSent() (full, compact [][]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, b := range c.sent {
		switch b[0] {
		case dataMessage:
			full = append(full, b)
		case compactDataMessage:
			compact = append(compact, b)
		}
	}
	return full, compact
}

const (
	compactNetwork = model.ID("11111111111111111111111111111111")
	compactSource  = model.ID("22222222222222222222222222222222")
	compactDest    = model.ID("33333333333333333333333333333333")
)

// compactTestHeader rebuilds the fixed test addresses unless the payload is
// marked unroutable with a leading 0xff.
func compactTestHeader(header []byte, network [16]byte, hop uint8, payload []byte) bool {
	if payload[0] == 0xff {
		return false
	}
	frame, _ := (packet.Packet{Header: packet.Header{Network: compactNetwork, Source: compactSource, Destination: compactDest, HopLimit: hop}, Payload: payload}).MarshalBinary()
	if [16]byte(frame[8:24]) != network {
		return false
	}
	copy(header, frame[:packet.HeaderSize])
	return true
}

func compactTestFrame(t *testing.T, payload []byte) []byte {
	t.Helper()
	frame, err := (packet.Packet{Header: packet.Header{Network: compactNetwork, Source: compactSource, Destination: compactDest, HopLimit: 9, Epoch: 7, Flow: 5, Sequence: 3}, Payload: payload}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func newCompactTestLink(t *testing.T, channel Channel, options Options) *Link {
	t.Helper()
	info := Info{NetworkID: compactNetwork, EdgeID: compactSource, PeerID: compactDest, CandidateID: "candidate", Transport: model.TCP}
	l, err := New(context.Background(), channel, info, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func receiveFrame(t *testing.T, l *Link) []byte {
	t.Helper()
	select {
	case frame := <-l.Packets():
		return frame
	case <-time.After(5 * time.Second):
		t.Fatal("frame not delivered")
		return nil
	}
}

// Rebuilt frames keep every routing field; Epoch, Flow and Sequence, which
// receivers ignore, are zero.
func wantRebuilt(sent []byte) []byte {
	want := bytes.Clone(sent)
	clear(want[56:packet.HeaderSize])
	return want
}

func TestCompactNegotiationAndFraming(t *testing.T) {
	payload := []byte{0x45, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}
	frame := compactTestFrame(t, payload)

	t.Run("both", func(t *testing.T) {
		dialerEnd, acceptorEnd := pipePair()
		dialer := newCompactTestLink(t, dialerEnd, Options{Compact: compactTestHeader})
		acceptor := newCompactTestLink(t, acceptorEnd, Options{Compact: compactTestHeader, CompactHello: true})
		// The dialer offered, so the acceptor sends compact frames at once.
		if err := acceptor.Send(context.Background(), frame); err != nil {
			t.Fatal(err)
		}
		if got := receiveFrame(t, dialer); !bytes.Equal(got, wantRebuilt(frame)) {
			t.Fatalf("dialer received %x", got)
		}
		deadline := time.Now().Add(5 * time.Second)
		for !dialer.compactOut.Load() {
			if time.Now().After(deadline) {
				t.Fatal("dialer never enabled compact frames")
			}
			time.Sleep(time.Millisecond)
		}
		if err := dialer.Send(context.Background(), frame); err != nil {
			t.Fatal(err)
		}
		if got := receiveFrame(t, acceptor); !bytes.Equal(got, wantRebuilt(frame)) {
			t.Fatalf("acceptor received %x", got)
		}
		for name, end := range map[string]*pipeChannel{"dialer": dialerEnd, "acceptor": acceptorEnd} {
			full, compact := end.dataSent()
			if len(full) != 0 || len(compact) != 1 || !bytes.Equal(compact[0], append([]byte{compactDataMessage, 9}, payload...)) {
				t.Fatalf("%s sent full=%x compact=%x", name, full, compact)
			}
		}
		if dialer.tx.Load() != uint64(len(frame)) || acceptor.rx.Load() != uint64(len(frame)) {
			t.Fatal("compact frames not counted as their full size")
		}
	})

	t.Run("older acceptor", func(t *testing.T) {
		dialerEnd, acceptorEnd := pipePair()
		dialer := newCompactTestLink(t, dialerEnd, Options{Compact: compactTestHeader})
		acceptor := newCompactTestLink(t, acceptorEnd, Options{})
		if err := dialer.Send(context.Background(), frame); err != nil {
			t.Fatal(err)
		}
		if got := receiveFrame(t, acceptor); !bytes.Equal(got, frame) {
			t.Fatalf("older acceptor received %x", got)
		}
		if full, compact := dialerEnd.dataSent(); len(full) != 1 || len(compact) != 0 {
			t.Fatal("compact frame sent without the acceptor's confirmation")
		}
	})

	t.Run("unnegotiated", func(t *testing.T) {
		local, remote := pipePair()
		l := newCompactTestLink(t, local, Options{})
		remote.Send(context.Background(), append([]byte{compactDataMessage, 9}, payload...))
		select {
		case <-l.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("link accepted an unnegotiated compact frame")
		}
	})

	t.Run("unroutable", func(t *testing.T) {
		local, remote := pipePair()
		l := newCompactTestLink(t, local, Options{Compact: compactTestHeader})
		remote.Send(context.Background(), append([]byte{compactDataMessage, 9, 0xff}, payload...))
		remote.Send(context.Background(), append([]byte{compactDataMessage, 9}, payload...))
		if got := receiveFrame(t, l); !bytes.Equal(got, wantRebuilt(frame)) {
			t.Fatalf("received %x", got)
		}
		if l.dropped.Load() != 1 {
			t.Fatalf("dropped = %d", l.dropped.Load())
		}
	})
}

// Owned frames from the router are compacted in place, without a copy.
func TestCompactOwnedFramesInPlace(t *testing.T) {
	l := &Link{ctx: context.Background(), info: Info{Transport: model.UDP}, dataReady: make(chan struct{}, 1)}
	l.dataGeneration.Store(1)
	l.compactOut.Store(true)
	payload := []byte{0x45, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}
	frame := compactTestFrame(t, payload)
	headroom := packetbuf.GetHeadroom(len(frame), 1)
	copy(headroom.Data, frame)
	plain := packetbuf.Wrap(bytes.Clone(frame))
	storage := []*byte{&headroom.Data[packet.HeaderSize], &plain.Data[packet.HeaderSize]}
	if err := l.SendOwnedBatch(context.Background(), []*packetbuf.Buffer{headroom, plain}); err != nil {
		t.Fatal(err)
	}
	want := append([]byte{compactDataMessage, 9}, payload...)
	for i := range 2 {
		queued := l.takeData()
		if !bytes.Equal(queued.raw, want) || &queued.raw[2] != storage[i] {
			t.Fatalf("frame %d queued as %x", i, queued.raw)
		}
		queued.buffer.Release()
	}
	if l.dataBytes != 0 {
		t.Fatal("compact frames leaked byte budget")
	}
}
