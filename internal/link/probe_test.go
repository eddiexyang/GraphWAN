package link

import (
	"context"
	"encoding/binary"
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
		l.peerPing = now
		if !l.heartbeat(now) || !l.healthyLocked(now.Add(time.Millisecond)) {
			t.Fatalf("pinged accepted link unhealthy at tick %d", tick)
		}
		answer(l, now)
	}
	if want := uint64(60 * h / acceptedProbe); l.sent != want || l.rtt == 0 {
		t.Fatalf("accepted probes = %d, rtt = %v; want %d RTT samples", l.sent, l.rtt, want)
	}
	// Liveness ends one timeout after the dialer's last ping.
	silent := now
	if !l.heartbeat(silent.Add(o.Timeout-time.Millisecond)) || l.heartbeat(silent.Add(o.Timeout)) || l.healthyLocked(silent.Add(o.Timeout)) {
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
