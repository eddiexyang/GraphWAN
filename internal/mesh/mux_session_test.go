package mesh

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/link"
)

// sessionPair opens a stream from a to b and starts both as session hops; b
// delivers locally, as an egress does.
func sessionPair(t *testing.T, p *muxPair) (*muxStream, *muxStream) {
	t.Helper()
	p.connect(t, true)
	waitFor(t, "streams", p.a.Available)
	s, err := p.a.Open(p.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	peer := p.accept(t)
	if _, err := io.ReadFull(peer, make([]byte, 7)); err != nil {
		t.Fatal(err)
	}
	s.Begin(100)
	peer.Begin(200)
	peer.DeliverLocal()
	return s, peer
}

// A session over one hop sends the frames a plain stream sends: the egress's
// acknowledgements imply what it delivered, and its FIN ends the direction.
func TestMuxSessionHopAddsNoControlBytes(t *testing.T) {
	p := newMuxPair(t)
	s, peer := sessionPair(t, p)
	payload := bytes.Repeat([]byte("x"), 4<<20)
	go func() {
		s.Write(payload)
		s.CloseWrite()
	}()
	raw, err := io.ReadAll(peer)
	if err != nil || !bytes.Equal(raw, payload) || !peer.Ended() {
		t.Fatal("bytes or end changed", err)
	}
	waitFor(t, "the delivered end", func() bool { return s.PeerDelivered() == 100+uint64(len(payload))+1 })
	p.b.mu.Lock()
	defer p.b.mu.Unlock()
	if peer.ackDelivered != 0 {
		t.Fatal("the egress sent delivered offsets")
	}
}

// A relay's acknowledgements carry the far end's delivered offset.
func TestMuxSessionRelayReportsDelivered(t *testing.T) {
	p := newMuxPair(t)
	s, peer := sessionPair(t, p)
	p.b.mu.Lock()
	peer.local = false
	p.b.mu.Unlock()
	notified := make(chan struct{}, 16)
	s.OnDelivered(func() { notified <- struct{}{} })
	peer.SetDelivered(100 + 1<<20)
	select {
	case <-notified:
	case <-time.After(5 * time.Second):
		t.Fatal("no delivered offset")
	}
	if got := s.PeerDelivered(); got != 100+1<<20 {
		t.Fatal("delivered offset", got)
	}
}

// A session hop whose sent frames see no acknowledgement is reset, while a
// plain stream keeps waiting for the Edge.
func TestMuxSessionStallResets(t *testing.T) {
	p := newMuxPair(t)
	p.a.g.mesh = &Mesh{}
	s, _ := sessionPair(t, p)
	p.a.mu.Lock()
	p.a.current, p.a.ready = nil, map[*link.Link]bool{} // frames now go nowhere
	p.a.mu.Unlock()
	if _, err := s.Write([]byte("lost")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(muxStall + 50*time.Millisecond)
	p.a.maintain()
	if _, err := s.Read(make([]byte, 1)); !errors.Is(err, errStreamReset) {
		t.Fatal("stalled hop was not reset:", err)
	}
	if p.a.g.mesh.Counters()["session_stall_resets"] != 1 {
		t.Fatal("stall reset not counted")
	}
}

// A reset of the connection is told apart from a failed hop.
func TestMuxSessionAbortReachesPeer(t *testing.T) {
	p := newMuxPair(t)
	s, peer := sessionPair(t, p)
	s.AbortSession()
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("peer read after the reset")
	}
	if !peer.Aborted() {
		t.Fatal("peer did not see the connection reset")
	}
}

// An end that reads up to a FIN which arrived before it finished reading
// acknowledges at once: the far end needs that to finish the session.
func TestMuxSessionAcknowledgesTheEndAtOnce(t *testing.T) {
	p := newMuxPair(t)
	s, peer := sessionPair(t, p)
	payload := bytes.Repeat([]byte("x"), 64<<10)
	if _, err := s.Write(payload); err != nil {
		t.Fatal(err)
	}
	s.CloseWrite()
	waitFor(t, "the FIN", func() bool {
		p.b.mu.Lock()
		defer p.b.mu.Unlock()
		return peer.finRecv
	})
	if raw, err := io.ReadAll(peer); err != nil || !bytes.Equal(raw, payload) {
		t.Fatal("bytes changed", err)
	}
	deadline := time.Now().Add(time.Second)
	for s.PeerDelivered() != 100+uint64(len(payload))+1 {
		if time.Now().After(deadline) {
			t.Fatalf("delivered %d, want %d", s.PeerDelivered(), 100+len(payload)+1)
		}
		time.Sleep(time.Millisecond)
	}
}
