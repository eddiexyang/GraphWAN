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
		{"default", 6 * time.Second, 0, false, time.Second, 3 * time.Second},
		{"fast dialer", time.Second, 0, false, 500 * time.Millisecond / 3, 500 * time.Millisecond},
		{"fast acceptor, fast dialer", time.Second, 500 * time.Millisecond / 3, true, 500 * time.Millisecond / 3, 500 * time.Millisecond},
		{"fast acceptor, default dialer", time.Second, time.Second, true, time.Second, 3 * time.Second},
		{"fast acceptor, slow dialer", time.Second, 20 * time.Second, true, 20 * time.Second, 60 * time.Second},
		{"slow acceptor, fast dialer", 60 * time.Second, 500 * time.Millisecond / 3, true, 10 * time.Second, 30 * time.Second},
		{"implausible dialer", time.Second, time.Hour, true, 40 * time.Second, 120 * time.Second},
	} {
		heartbeat, timeout := linkTiming(tc.detection, linkCaps{accepted: tc.accepted, peerHeartbeat: tc.peer})
		if heartbeat != tc.heartbeat || timeout != tc.timeout {
			t.Errorf("%s: heartbeat %v timeout %v, want %v %v", tc.name, heartbeat, timeout, tc.heartbeat, tc.timeout)
		}
	}
}
