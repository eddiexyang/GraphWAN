package mesh

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
	"time"
)

// windowedPair connects a pair whose Links' kernel receive buffers are budget
// bytes, and runs both Edges' maintenance as their schedulers would.
func windowedPair(t *testing.T, budget int) *muxPair {
	t.Helper()
	p := newMuxPair(t)
	window := func() (int, bool) { return budget, true }
	p.a.receiveWindow, p.b.receiveWindow = window, window
	p.connect(t, true)
	waitFor(t, "streams", p.a.Available)
	go func() {
		for p.ctx.Err() == nil {
			p.a.maintain()
			p.b.maintain()
			time.Sleep(10 * time.Millisecond)
		}
	}()
	return p
}

// openWindowed opens a stream whose windows follow the Link's buffer, as
// Open does on a Link that confirmed them.
func (p *muxPair) openWindowed() *muxStream {
	p.a.mu.Lock()
	defer p.a.mu.Unlock()
	s := p.a.newStreamLocked(p.a.next, true)
	p.a.next += 2
	return s
}

// held is the credit the receiver gave s's sender beyond what it consumed.
func (p *muxPair) held(s *muxStream) uint64 {
	p.b.mu.Lock()
	defer p.b.mu.Unlock()
	return s.advertised - s.consumed
}

func (p *muxPair) consumed(s *muxStream) uint64 {
	p.b.mu.Lock()
	defer p.b.mu.Unlock()
	return s.consumed
}

// Streams consuming split the Link's buffer: together they are given no more
// credit than it, and the sender learns what each consumed.
func TestMuxWindowedStreamsSplitTheLinkBuffer(t *testing.T) {
	const budget = 4 << 20
	p := windowedPair(t, budget)
	var senders, receivers [2]*muxStream
	payloads := [2][]byte{make([]byte, 24<<20), make([]byte, 24<<20)}
	for i := range senders {
		rand.Read(payloads[i])
		senders[i] = p.openWindowed()
		go func() {
			senders[i].Write(payloads[i])
			senders[i].CloseWrite()
		}()
		receivers[i] = p.accept(t)
		if !receivers[i].windowed {
			t.Fatal("the receiver did not take the stream as windowed")
		}
	}
	got := [2]chan []byte{make(chan []byte, 1), make(chan []byte, 1)}
	for i, r := range receivers {
		go func() {
			raw, _ := io.ReadAll(r)
			got[i] <- raw
		}()
	}
	deadline := time.Now().Add(20 * time.Second)
	var most uint64
	for done := 0; done < 2; {
		select {
		case raw := <-got[0]:
			if !bytes.Equal(raw, payloads[0]) {
				t.Fatal("the first stream's bytes changed")
			}
			got[0], done = nil, done+1
		case raw := <-got[1]:
			if !bytes.Equal(raw, payloads[1]) {
				t.Fatal("the second stream's bytes changed")
			}
			got[1], done = nil, done+1
		case <-time.After(time.Millisecond):
			// Credit given before the second stream started is not taken
			// back, as a TCP window never shrinks; it is used up once each
			// stream consumed the Link's buffer.
			if done == 0 && p.consumed(receivers[0]) > budget && p.consumed(receivers[1]) > budget {
				most = max(most, p.held(receivers[0])+p.held(receivers[1]))
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the streams did not finish")
		}
	}
	if most > budget {
		t.Fatalf("the streams were given %d bytes of credit together, more than the Link's %d", most, budget)
	}
	p.a.mu.Lock()
	consumed := senders[0].peerConsumed
	p.a.mu.Unlock()
	if consumed != uint64(len(payloads[0])) {
		t.Fatalf("the sender learned %d bytes consumed, not %d", consumed, len(payloads[0]))
	}
}

// A stream whose reader stops keeps only the credit it had, as a connection
// keeps its own buffer, and another stream on the Link gets the whole buffer.
func TestMuxStalledWindowedStreamKeepsItsShare(t *testing.T) {
	const budget = 4 << 20
	p := windowedPair(t, budget)
	stalled := p.openWindowed()
	go stalled.Write(make([]byte, 64<<20))
	idle := p.accept(t)
	if _, err := io.ReadFull(idle, make([]byte, 2<<20)); err != nil {
		t.Fatal(err)
	}
	// It stops reading: the sender stops once the credit it had is used.
	var last uint64
	waitFor(t, "the stalled stream's sender to stop", func() bool {
		p.a.mu.Lock()
		sent := stalled.sendNext
		p.a.mu.Unlock()
		stopped := sent == last && sent > 2<<20
		last = sent
		time.Sleep(50 * time.Millisecond)
		return stopped
	})
	held := p.held(idle)
	if held > budget+muxInitialWindow {
		t.Fatalf("the stalled stream holds %d bytes of credit, more than its share of %d", held, budget)
	}
	// Once it has consumed nothing for muxIdle, it no longer shares the
	// Link's buffer.
	time.Sleep(muxIdle)
	other := p.openWindowed()
	payload := make([]byte, 32<<20)
	rand.Read(payload)
	go func() {
		other.Write(payload)
		other.CloseWrite()
	}()
	r := p.accept(t)
	raw, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(raw, payload) {
		t.Fatal("the other stream was held up", err)
	}
	p.b.mu.Lock()
	window := r.window
	p.b.mu.Unlock()
	if window != budget {
		t.Fatalf("the other stream had %d bytes of window, not the Link's %d", window, budget)
	}
	if now := p.held(idle); now > held {
		t.Fatalf("the stalled stream was given %d more bytes while it consumed none", now-held)
	}
}

// One stream may have as much in flight as the Link's buffer allows, past the
// fixed window of streams without it.
func TestMuxWindowedStreamUsesTheWholeBuffer(t *testing.T) {
	const budget = 3 * muxWindow / 2
	p := windowedPair(t, budget)
	s := p.openWindowed()
	go s.Write(make([]byte, 2*budget))
	r := p.accept(t)
	if _, err := io.ReadFull(r, make([]byte, 1<<20)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the sender to pass the fixed window", func() bool {
		p.a.mu.Lock()
		defer p.a.mu.Unlock()
		return s.sendNext > 1<<20+muxWindow
	})
}
