package link

import (
	"context"
	"encoding/binary"
	"testing"
	"time"
)

// takeKind drains the control queue and returns the first message of kind.
func takeKind(l *Link, kind byte) []byte {
	var found []byte
	for {
		select {
		case raw := <-l.control:
			if found == nil && raw[0] == kind {
				found = raw
			}
		default:
			return found
		}
	}
}

func TestSizeProbeGatesHealth(t *testing.T) {
	o := (Options{SizeProbe: true, SizeProbeHello: true}).defaults()
	start := time.Unix(1000, 0)
	newLink := func() *Link {
		l := &Link{ctx: context.Background(), options: o, control: make(chan []byte, 8), pending: map[uint64]time.Time{}}
		l.initSizeProbe()
		if hello := takeKind(l, sizeProbeHelloMessage); len(hello) != 2 {
			t.Fatal("acceptor did not announce size probes")
		}
		l.lastPong = start // liveness itself is satisfied
		return l
	}

	// Unverified until its own full-size probe is answered.
	l := newLink()
	if !l.heartbeat(start) || l.healthyLocked(start) {
		t.Fatal("link healthy before its size probe was answered")
	}
	probe := takeKind(l, sizeProbeMessage)
	if len(probe) != sizeProbeBytes {
		t.Fatalf("probe length = %d, want %d", len(probe), sizeProbeBytes)
	}
	reply := append([]byte{}, probe...)
	reply[0] = sizeProbeReplyMessage
	stale := append([]byte{}, reply...)
	binary.BigEndian.PutUint64(stale[1:9], 999)
	if !l.receiveSizeProbeReply(stale, start) || l.healthyLocked(start) {
		t.Fatal("a reply to another probe verified the link")
	}
	if !l.receiveSizeProbeReply(reply, start.Add(time.Millisecond)) || !l.healthyLocked(start.Add(time.Millisecond)) {
		t.Fatal("answered size probe did not verify the link")
	}

	// Re-verified every interval; an unanswered re-probe fails the link.
	// Pings are answered throughout, so only the size probe can fail it.
	beat := func(now time.Time) bool {
		l.lastPong, l.probeSince, l.pending = now, time.Time{}, map[uint64]time.Time{}
		return l.heartbeat(now)
	}
	now := start.Add(time.Millisecond + sizeProbeInterval - time.Second)
	if !beat(now) || takeKind(l, sizeProbeMessage) != nil {
		t.Fatal("re-probed before the interval")
	}
	now = start.Add(time.Millisecond + sizeProbeInterval)
	if !beat(now) || takeKind(l, sizeProbeMessage) == nil {
		t.Fatal("verified link was not re-probed")
	}
	if !beat(now.Add(o.Timeout - time.Millisecond)) {
		t.Fatal("re-probe failed before its timeout")
	}
	if beat(now.Add(o.Timeout)) || l.failureReason() != "probe" {
		t.Fatal("unanswered re-probe did not fail the link with reason probe")
	}

	// An initial probe that is never answered fails after one timeout.
	l = newLink()
	beat(start)
	if beat(start.Add(o.Timeout)) || l.failureReason() != "probe" {
		t.Fatal("unanswered initial probe did not fail the link")
	}
}

func TestSizeProbeDialerNegotiation(t *testing.T) {
	o := (Options{SizeProbe: true}).defaults()
	newLink := func() *Link {
		l := &Link{ctx: context.Background(), options: o, control: make(chan []byte, 8), pending: map[uint64]time.Time{}}
		l.initSizeProbe()
		return l
	}
	start := time.Unix(1000, 0)

	// An acceptor that answers without the hello predates size probes.
	l := newLink()
	if takeKind(l, sizeProbeHelloMessage) != nil {
		t.Fatal("dialer announced size probes")
	}
	l.lastPong = start
	if l.healthyLocked(start) {
		t.Fatal("dialer healthy before the acceptor answered")
	}
	l.sizeProbeUnsupported()
	if !l.healthyLocked(start) || !l.heartbeat(start) || takeKind(l, sizeProbeMessage) != nil {
		t.Fatal("link to an older acceptor was held back or probed")
	}
	if l.receiveSizeProbeHello([]byte{sizeProbeHelloMessage, 1}) {
		t.Fatal("late size-probe hello accepted after settling")
	}

	// The hello switches probing on; a second one is a protocol error.
	l = newLink()
	if !l.receiveSizeProbeHello([]byte{sizeProbeHelloMessage, 1}) || l.receiveSizeProbeHello([]byte{sizeProbeHelloMessage, 1}) {
		t.Fatal("size-probe hello handling")
	}
	l.sizeProbeUnsupported() // later hellos and pongs do not undo it
	l.lastPong = start
	if !l.heartbeat(start) || takeKind(l, sizeProbeMessage) == nil || l.healthyLocked(start) {
		t.Fatal("dialer did not probe after the hello")
	}

	// Probes are answered with a full-size reply; malformed probes are refused.
	if l.answerSizeProbe(make([]byte, 100)) {
		t.Fatal("short probe answered")
	}
	probe := make([]byte, sizeProbeBytes)
	probe[0] = sizeProbeMessage
	if !l.answerSizeProbe(probe) {
		t.Fatal("probe not answered")
	}
	if reply := takeKind(l, sizeProbeReplyMessage); len(reply) != sizeProbeBytes {
		t.Fatal("probe reply is not full size")
	}
}

// dropLarge forwards only messages up to limit bytes, as a path that loses
// full-size segments while small ones get through.
type dropLarge struct {
	*pipeChannel
	limit int
}

func (c dropLarge) Send(ctx context.Context, b []byte) error {
	if len(b) > c.limit {
		return nil
	}
	return c.pipeChannel.Send(ctx, b)
}

func TestSizeProbeEndToEnd(t *testing.T) {
	fast := Options{Heartbeat: 20 * time.Millisecond, Timeout: 200 * time.Millisecond}
	healthy := func(links ...*Link) bool {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			ok := true
			for _, l := range links {
				ok = ok && l.Healthy()
			}
			if ok {
				return true
			}
			time.Sleep(10 * time.Millisecond)
		}
		return false
	}
	sentKind := func(c *pipeChannel, kind byte) int {
		c.mu.Lock()
		defer c.mu.Unlock()
		n := 0
		for _, b := range c.sent {
			if b[0] == kind {
				n++
			}
		}
		return n
	}
	dialerOptions, acceptorOptions := fast, fast
	dialerOptions.SizeProbe = true
	acceptorOptions.Accepted, acceptorOptions.SizeProbe, acceptorOptions.SizeProbeHello = true, true, true

	t.Run("both support probes", func(t *testing.T) {
		a, b := pipePair()
		dialer := newCompactTestLink(t, a, dialerOptions)
		acceptor := newCompactTestLink(t, b, acceptorOptions)
		if !healthy(dialer, acceptor) {
			t.Fatal("verified links did not become healthy")
		}
		if sentKind(a, sizeProbeMessage) == 0 || sentKind(b, sizeProbeMessage) == 0 {
			t.Fatal("each side must probe on its own")
		}
	})

	t.Run("older acceptor", func(t *testing.T) {
		a, b := pipePair()
		older := fast
		older.Accepted = true
		dialer := newCompactTestLink(t, a, dialerOptions)
		acceptor := newCompactTestLink(t, b, older)
		if !healthy(dialer, acceptor) {
			t.Fatal("link to an older acceptor did not become healthy")
		}
		if sentKind(a, sizeProbeMessage) != 0 {
			t.Fatal("dialer probed an acceptor without support")
		}
	})

	t.Run("full-size segments lost", func(t *testing.T) {
		a, b := pipePair()
		dialer := newCompactTestLink(t, dropLarge{a, 1000}, dialerOptions)
		acceptor := newCompactTestLink(t, b, acceptorOptions)
		for _, l := range []*Link{dialer, acceptor} {
			select {
			case <-l.Done():
			case <-time.After(3 * time.Second):
				t.Fatal("link that loses full-size messages stayed open")
			}
			if l.Healthy() {
				t.Fatal("link that loses full-size messages reported healthy")
			}
		}
	})
}
