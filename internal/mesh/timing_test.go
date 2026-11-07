package mesh

import (
	"testing"
	"time"
)

func TestLinkTiming(t *testing.T) {
	for _, tc := range []struct {
		name               string
		detection, peer    time.Duration
		accepted           bool
		heartbeat, timeout time.Duration
	}{
		{"default", 6 * time.Second, 0, false, 2 * time.Second, 6 * time.Second},
		{"fast dialer", 750 * time.Millisecond, 0, false, 250 * time.Millisecond, 750 * time.Millisecond},
		{"fast acceptor, fast dialer", 750 * time.Millisecond, 250 * time.Millisecond, true, 250 * time.Millisecond, 750 * time.Millisecond},
		{"fast acceptor, older dialer", 750 * time.Millisecond, 0, true, 2 * time.Second, 6 * time.Second},
		{"fast acceptor, slow dialer", 750 * time.Millisecond, 20 * time.Second, true, 20 * time.Second, 60 * time.Second},
		{"slow acceptor, fast dialer", 60 * time.Second, 250 * time.Millisecond, true, 20 * time.Second, 60 * time.Second},
		{"implausible dialer", 750 * time.Millisecond, time.Hour, true, 40 * time.Second, 120 * time.Second},
	} {
		heartbeat, timeout := linkTiming(tc.detection, linkCaps{accepted: tc.accepted, peerHeartbeat: tc.peer})
		if heartbeat != tc.heartbeat || timeout != tc.timeout {
			t.Errorf("%s: heartbeat %v timeout %v, want %v %v", tc.name, heartbeat, timeout, tc.heartbeat, tc.timeout)
		}
	}
}
