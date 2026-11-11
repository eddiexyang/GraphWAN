package link

import (
	"context"
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

// Exercise real probe/liveness state transitions with a clock supplied by the
// test; no sockets, goroutines, sleeps or deployed peers are needed.
func TestProbesAndFailureDetection(t *testing.T) {
	o := (Options{}).defaults()
	h := o.Heartbeat
	newLink := func() *Link {
		return &Link{ctx: context.Background(), options: o, control: make(chan []byte, 8), pending: map[uint64]time.Time{}}
	}
	start := time.Unix(1000, 0)
	reply := func(l *Link, now time.Time) {
		t.Helper()
		select {
		case raw := <-l.control:
			l.recordPong(binary.BigEndian.Uint64(raw[1:]), now.Add(time.Millisecond))
		default:
			t.Fatal("expected probe")
		}
	}
	// An idle Link is probed every heartbeat, like a busy one.
	l := newLink()
	for tick := 0; tick < 60; tick++ {
		now := start.Add(time.Duration(tick) * h)
		if !l.heartbeat(now) {
			t.Fatal("healthy idle link expired")
		}
		reply(l, now)
		if !l.healthyLocked(now.Add(2 * time.Millisecond)) {
			t.Fatal("healthy link marked offline between probes")
		}
	}
	if l.sent != 60 {
		t.Fatalf("probes = %d, want one per heartbeat", l.sent)
	}
	// A valid retry response restores health after a lost probe.
	l = newLink()
	l.heartbeat(start)
	reply(l, start)
	l.heartbeat(start.Add(h))
	l.heartbeat(start.Add(2 * h))
	l.recordPong(l.nextPing, start.Add(2*h+time.Millisecond))
	if now := start.Add(2*h + o.Timeout); !l.heartbeat(now) || !l.healthyLocked(now) {
		t.Fatal("lost probe caused failure despite a valid retry reply")
	}
	// An unrecognized pong cannot prevent failure, which comes one timeout
	// after the first unanswered probe.
	l = newLink()
	l.heartbeat(start)
	reply(l, start)
	last := int(o.Timeout/h) + 1
	var now time.Time
	for tick := 1; tick <= last; tick++ {
		now = start.Add(time.Duration(tick) * h)
		l.recordPong(999, now)
		alive := l.heartbeat(now)
		if alive != (tick < last) {
			t.Fatalf("liveness at tick %d = %v", tick, alive)
		}
	}
	if l.healthyLocked(now) || l.sent != uint64(last) {
		t.Fatal("failed link remained healthy or was not probed every heartbeat")
	}
	// Initial admission must still require a reply and expire after one timeout.
	l = newLink()
	l.heartbeat(start)
	if l.healthyLocked(start) || l.heartbeat(start.Add(o.Timeout)) {
		t.Fatal("unresponsive initial link survived")
	}
}

// The accepting side relies on the dialer's pings for liveness and probes
// only to sample RTT, halving steady per-Link heartbeat traffic.
func TestAcceptedLinkLiveness(t *testing.T) {
	o := (Options{Accepted: true}).defaults()
	h := o.Heartbeat
	start := time.Unix(1000, 0)
	newLink := func() *Link {
		return &Link{ctx: context.Background(), options: o, control: make(chan []byte, 8), pending: map[uint64]time.Time{}, started: start}
	}
	answer := func(l *Link, now time.Time) {
		select {
		case raw := <-l.control:
			l.recordPong(binary.BigEndian.Uint64(raw[1:]), now.Add(time.Millisecond))
		default:
		}
	}
	l := newLink()
	var now time.Time
	for tick := 0; tick < 60; tick++ {
		now = start.Add(time.Duration(tick) * h)
		// The dialer's ping confirms the pong for its previous one.
		l.receivePing(uint64(tick+1), uint64(tick), now)
		if !l.heartbeat(now) || !l.healthyLocked(now.Add(time.Millisecond)) {
			t.Fatalf("pinged accepted link unhealthy at tick %d", tick)
		}
		answer(l, now)
	}
	if want := uint64(60 * h / acceptedProbe); l.sent != want || l.rtt == 0 {
		t.Fatalf("accepted probes = %d, rtt = %v; want %d RTT samples", l.sent, l.rtt, want)
	}
	// Liveness ends within one timeout after the dialer's last ping, which
	// confirmed this side's pong of one heartbeat earlier.
	silent := now
	if !l.heartbeat(silent.Add(o.Timeout-h-time.Millisecond)) || l.heartbeat(silent.Add(o.Timeout)) || l.healthyLocked(silent.Add(o.Timeout)) {
		t.Fatal("accepted link outlived its silent dialer")
	}
	// A dialer that never pings cannot keep an accepted link, even if the
	// accepting side's own RTT probe is answered.
	l = newLink()
	l.heartbeat(start)
	answer(l, start)
	if l.healthyLocked(start.Add(time.Second)) || l.heartbeat(start.Add(o.Timeout)) {
		t.Fatal("accepted link survived without dialer pings")
	}
}

// An accepted Link whose own messages stop arriving fails within one timeout,
// although the dialer's pings still arrive: they stop confirming its pongs.
func TestAcceptedLinkDetectsOneWayLoss(t *testing.T) {
	o := (Options{Accepted: true}).defaults()
	h := o.Heartbeat
	start := time.Unix(1000, 0)
	l := &Link{ctx: context.Background(), options: o, control: make(chan []byte, 8), pending: map[uint64]time.Time{}, started: start}
	tick := 0
	for ; tick < 10; tick++ {
		l.receivePing(uint64(tick+1), uint64(tick), start.Add(time.Duration(tick)*h))
	}
	lost := start.Add(time.Duration(tick-1) * h) // the last pong that arrived
	var failed time.Time
	for ; tick < 40 && failed.IsZero(); tick++ {
		now := start.Add(time.Duration(tick) * h)
		l.receivePing(uint64(tick+1), uint64(10), now) // still confirms pong 10
		if !l.heartbeat(now) || !l.healthyLocked(now) {
			failed = now
		}
	}
	if failed.IsZero() || failed.Sub(lost) > o.Timeout+h {
		t.Fatalf("one-way loss detected %v after the last confirmed pong, want within %v", failed.Sub(lost), o.Timeout+h)
	}
}

// A reply that arrives after the health deadline must not revive the Link:
// selection may already have dropped it, and nothing would select it again.
func TestLateReplyCannotReviveLink(t *testing.T) {
	o := (Options{}).defaults()
	start := time.Unix(1000, 0)
	l := &Link{ctx: context.Background(), options: o, control: make(chan []byte, 8), pending: map[uint64]time.Time{}}
	l.heartbeat(start)
	l.recordPong(l.nextPing, start.Add(time.Millisecond))
	l.heartbeat(start.Add(o.Heartbeat))
	late := l.probeSince.Add(o.Timeout)
	l.recordPong(l.nextPing, late)
	if l.healthyLocked(late) || l.heartbeat(late) {
		t.Fatal("a reply after the deadline revived the Link")
	}

	a := (Options{Accepted: true}).defaults()
	acceptor := &Link{ctx: context.Background(), options: a, control: make(chan []byte, 8), pending: map[uint64]time.Time{}, started: start, peerPing: start}
	if !acceptor.expiredLocked(start.Add(a.Timeout)) || acceptor.expiredLocked(start.Add(a.Timeout-time.Millisecond)) {
		t.Fatal("accepted deadline is not one timeout after the last ping")
	}
}

// The health loop closes a Link at its deadline instead of the next heartbeat.
func TestLinkClosesAtHealthDeadline(t *testing.T) {
	options := Options{Heartbeat: 300 * time.Millisecond, Timeout: 700 * time.Millisecond}
	a, b := pipePair()
	var mute sync.Mutex
	muted := false
	// Answer pings until muted, like a peer whose path then goes silent.
	go func() {
		for {
			raw, err := b.Receive(context.Background())
			if err != nil {
				return
			}
			mute.Lock()
			silent := muted
			mute.Unlock()
			if raw[0] == pingMessage && !silent {
				reply := append([]byte{}, raw[:9]...)
				reply[0] = pongMessage
				b.Send(context.Background(), reply)
			}
		}
	}()
	l := newCompactTestLink(t, a, options)
	deadline := time.Now().Add(3 * time.Second)
	for !l.Healthy() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !l.Healthy() {
		t.Fatal("link did not become healthy")
	}
	mute.Lock()
	muted = true
	mute.Unlock()
	// Let a reply already in flight land first.
	time.Sleep(50 * time.Millisecond)
	var since time.Time
	for since.IsZero() {
		l.mu.Lock()
		since = l.probeSince
		l.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	select {
	case <-l.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("silent link was not closed")
	}
	// Closing on the following heartbeat would take up to Timeout+Heartbeat.
	if elapsed := time.Since(since); elapsed > options.Timeout+options.Heartbeat/2 {
		t.Fatalf("link closed %v after its first unanswered probe, want about %v", elapsed, options.Timeout)
	}
}

// A dialer and an accepted Link over one channel keep each other healthy for
// many timeouts: each ping confirms the pong for the one before.
func TestAcceptedLinkConfirmedByDialer(t *testing.T) {
	options := Options{Heartbeat: 100 * time.Millisecond, Timeout: 300 * time.Millisecond}
	a, b := pipePair()
	dialer := newCompactTestLink(t, a, options)
	accepted := options
	accepted.Accepted = true
	acceptor := newCompactTestLink(t, b, accepted)
	deadline := time.Now().Add(3 * time.Second)
	for !(dialer.Healthy() && acceptor.Healthy()) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	for end := time.Now().Add(5 * options.Timeout); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if !dialer.Healthy() || !acceptor.Healthy() {
			acceptor.mu.Lock()
			heard, ping, started, answered := acceptor.peerHeard, acceptor.peerPing, acceptor.started, acceptor.confirmed
			acceptor.mu.Unlock()
			dialer.mu.Lock()
			echo := dialer.lastPongNonce
			dialer.mu.Unlock()
			t.Fatalf("dialer healthy %v, acceptor healthy %v; heard %v ago, ping %v ago, started %v ago, confirmed %d, dialer echo %d", dialer.Healthy(), acceptor.Healthy(), time.Since(heard), time.Since(ping), time.Since(started), answered, echo)
		}
	}
}

// A busy Link's probes wait behind its stream bytes: while those keep
// arriving it stays up without an answer, and once they stop it fails one
// timeout later, on either side.
func TestStreamBytesKeepABusyLinkUp(t *testing.T) {
	o := (Options{}).defaults()
	h := o.Heartbeat
	start := time.Unix(1000, 0)
	for _, accepted := range []bool{false, true} {
		options := o
		options.Accepted = accepted
		l := &Link{ctx: context.Background(), options: options, started: start, control: make(chan []byte, 64), pending: map[uint64]time.Time{}}
		if accepted {
			l.receivePing(1, 0, start)
		} else {
			l.heartbeat(start)
			raw := <-l.control
			l.recordPong(binary.BigEndian.Uint64(raw[1:]), start.Add(time.Millisecond))
		}
		ticks := 4 * int(o.Timeout/h)
		now := start
		for tick := 1; tick <= ticks; tick++ {
			now = start.Add(time.Duration(tick) * h)
			l.sawStream(now)
			if !l.heartbeat(now) || !l.healthyLocked(now) {
				t.Fatalf("accepted=%v: a Link receiving stream bytes failed after %v without a probe answer", accepted, now.Sub(start))
			}
		}
		if at := now.Add(o.Timeout - time.Millisecond); !l.healthyLocked(at) {
			t.Fatalf("accepted=%v: failed before a timeout after its last stream bytes", accepted)
		}
		if at := now.Add(o.Timeout); l.heartbeat(at) || l.healthyLocked(at) {
			t.Fatalf("accepted=%v: still up a timeout after its last stream bytes", accepted)
		}
	}
}
