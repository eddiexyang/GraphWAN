package link

import (
	"encoding/binary"
	"time"
)

// Size probes keep a stream Link from carrying traffic until full-size
// segments cross it in both directions. Small pings alone can pass a path that
// drops every full segment, which then stalls the byte stream behind them.
//
// Each side probes on its own and counts a Link as verified only when its own
// probe is answered. The dialer offers the capability in its introduction; the
// acceptor announces it with a hello sent before any other message, so a
// dialer that hears anything else first knows the acceptor predates probes.
const (
	sizeProbeHelloMessage = 17
	sizeProbeMessage      = 18
	sizeProbeReplyMessage = 19
	// sizeProbeBytes spans more than one full TCP segment on common paths.
	sizeProbeBytes = 2048
	// sizeProbeInterval re-verifies a Link that is already in use.
	sizeProbeInterval = time.Minute
)

type sizeProbeMode uint8

const (
	sizeProbeOff      sizeProbeMode = iota // not offered, or the peer lacks it
	sizeProbeAwaiting                      // dialer: waiting for the acceptor's first message
	sizeProbeOn
)

// initSizeProbe runs in New before any other hello is queued.
func (l *Link) initSizeProbe() {
	if !l.options.SizeProbe {
		return
	}
	l.unverified = true
	if l.options.SizeProbeHello {
		l.control <- []byte{sizeProbeHelloMessage, 1}
		l.sizeMode = sizeProbeOn
		return
	}
	l.sizeMode = sizeProbeAwaiting
}

// sizeProbeUnsupported settles the dialer's offer when the acceptor's first
// message is not the size-probe hello: that peer predates size probes.
func (l *Link) sizeProbeUnsupported() {
	l.mu.Lock()
	if l.sizeMode == sizeProbeAwaiting {
		l.sizeMode, l.unverified = sizeProbeOff, false
	}
	l.mu.Unlock()
}

func (l *Link) receiveSizeProbeHello(raw []byte) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(raw) != 2 || l.sizeMode != sizeProbeAwaiting {
		return false
	}
	l.sizeMode = sizeProbeOn
	return true
}

func (l *Link) answerSizeProbe(raw []byte) bool {
	l.mu.Lock()
	on := l.sizeMode == sizeProbeOn
	l.mu.Unlock()
	if !on || len(raw) != sizeProbeBytes {
		return false
	}
	reply := append([]byte{}, raw...)
	reply[0] = sizeProbeReplyMessage
	select {
	case l.control <- reply:
		return true
	case <-l.ctx.Done():
		return false
	}
}

func (l *Link) receiveSizeProbeReply(raw []byte, now time.Time) bool {
	if len(raw) != sizeProbeBytes {
		return false
	}
	nonce := binary.BigEndian.Uint64(raw[1:9])
	l.mu.Lock()
	if l.sizeMode != sizeProbeOn {
		l.mu.Unlock()
		return false
	}
	if l.sizeSent.IsZero() || nonce != l.sizeNonce {
		l.mu.Unlock()
		return true // a late reply to an expired probe
	}
	// Log the Link up here if its ping exchange already completed.
	alive := l.peerPing
	if !l.options.Accepted {
		alive = l.lastPong
	}
	first := l.unverified && !alive.IsZero()
	rtt := l.rtt
	l.unverified, l.sizeSent, l.sizeVerified = false, time.Time{}, now
	l.mu.Unlock()
	if first {
		l.logUp("rtt_ms", rtt.Milliseconds(), "probe_bytes", sizeProbeBytes)
	}
	return true
}

// sizeProbeLocked runs on every heartbeat. It sends a probe while the Link is
// unverified or due for re-verification, and fails the Link once a probe has
// gone unanswered for a timeout.
func (l *Link) sizeProbeLocked(now time.Time) bool {
	if l.sizeMode != sizeProbeOn {
		return true
	}
	if !l.sizeSent.IsZero() {
		if now.Sub(l.sizeSent) >= l.options.Timeout {
			l.sizeFailed = true
			return false
		}
		return true
	}
	if !l.unverified && now.Sub(l.sizeVerified) < sizeProbeInterval {
		return true
	}
	raw := make([]byte, sizeProbeBytes)
	raw[0] = sizeProbeMessage
	binary.BigEndian.PutUint64(raw[1:9], l.sizeNonce+1)
	select {
	case l.control <- raw:
		l.sizeNonce++
		l.sizeSent = now
	default: // retried on the next heartbeat
	}
	return true
}

func (l *Link) failureReason() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sizeFailed {
		return "probe"
	}
	return "timeout"
}
