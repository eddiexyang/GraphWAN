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
	newLink := func() *Link {
		return &Link{ctx: context.Background(), options: (Options{}).defaults(), control: make(chan []byte, 8), pending: map[uint64]time.Time{}}
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
	// An idle Link is probed every second, like a busy one.
	l := newLink()
	for second := 0; second < 60; second++ {
		now := start.Add(time.Duration(second) * time.Second)
		if !l.heartbeat(now) {
			t.Fatal("healthy idle link expired")
		}
		reply(l, now)
		if !l.healthyLocked(now.Add(2 * time.Millisecond)) {
			t.Fatal("healthy link marked offline between probes")
		}
	}
	if l.sent != 60 {
		t.Fatalf("probes = %d, want 60 per minute", l.sent)
	}
	// A valid retry response restores health after a lost probe.
	l = newLink()
	l.heartbeat(start)
	reply(l, start)
	l.heartbeat(start.Add(time.Second))
	l.heartbeat(start.Add(2 * time.Second))
	l.recordPong(l.nextPing, start.Add(2*time.Second+time.Millisecond))
	if !l.heartbeat(start.Add(7*time.Second)) || !l.healthyLocked(start.Add(7*time.Second)) {
		t.Fatal("lost probe caused failure despite a valid retry reply")
	}
	// An unrecognized pong cannot prevent failure, which comes five seconds
	// after the first unanswered probe.
	l = newLink()
	l.heartbeat(start)
	reply(l, start)
	var now time.Time
	for second := 1; second <= 6; second++ {
		now = start.Add(time.Duration(second) * time.Second)
		l.recordPong(999, now)
		alive := l.heartbeat(now)
		if alive != (second < 6) {
			t.Fatalf("liveness at second %d = %v", second, alive)
		}
	}
	if l.healthyLocked(now) || l.sent != 6 {
		t.Fatal("failed link remained healthy or was not probed every second")
	}
	// Initial admission must still require a reply and expire after five seconds.
	l = newLink()
	l.heartbeat(start)
	if l.healthyLocked(start) || l.heartbeat(start.Add(5*time.Second)) {
		t.Fatal("unresponsive initial link survived")
	}
}
