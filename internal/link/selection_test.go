package link

import (
	"context"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
)

// A follower that does not answer, for example one still waiting for the
// previous leader's Links to leave, receives at most about one selection
// message per heartbeat instead of one per Edge tick.
func TestSelectionResendsBackOff(t *testing.T) {
	now := time.Now()
	l := &Link{channel: selectionTestChannel{id: "only", created: now}, ctx: context.Background(), options: (Options{}).defaults(), info: Info{CandidateID: "only"}, lastPong: now, control: make(chan []byte, 8)}
	e := NewCoordinatedEdge(model.ID("a"), model.ID("b"), "")
	e.Add(l)
	sent := 0
	tick := 250 * time.Millisecond
	duration := time.Minute
	var first, last time.Time
	for at := time.Duration(0); at < duration; at += tick {
		// Keep the Link healthy without depending on wall-clock time.
		l.mu.Lock()
		l.lastPong = time.Now()
		l.mu.Unlock()
		e.mu.Lock()
		e.advanceLocked(now.Add(at))
		e.mu.Unlock()
		select {
		case raw := <-l.control:
			if raw[0] != prepareMessage {
				t.Fatalf("unexpected message kind %d", raw[0])
			}
			if first.IsZero() {
				first = now.Add(at)
			}
			last = now.Add(at)
			sent++
		default:
		}
	}
	if first != now {
		t.Fatal("the first prepare was not sent at once")
	}
	if limit := int(duration/selectionRetryMax) + 8; sent > limit {
		t.Fatalf("sent %d prepares in %v, want at most %d", sent, duration, limit)
	}
	if last.Before(now.Add(duration - 2*selectionRetryMax)) {
		t.Fatal("selection stopped retrying an unanswered follower")
	}

	// An acceptance starts the commit phase with prompt resends again.
	e.mu.Lock()
	term, sequence := e.selection.term, e.selection.sequence
	e.mu.Unlock()
	e.HandleSelection(l, Selection{kind: acceptMessage, term: term, sequence: sequence})
	e.mu.Lock()
	backoff := e.selection.backoff
	active := e.active
	e.mu.Unlock()
	if backoff != selectionRetry || active != "only" {
		t.Fatalf("after acceptance: backoff %v, active %q", backoff, active)
	}
}

// Reporting status leaves coordinated selection untouched: no new sequence,
// no message, and the reported active Link is the selected one.
func TestReportDoesNotAdvanceSelection(t *testing.T) {
	now := time.Now()
	makeLink := func(id string, rtt time.Duration) *Link {
		return &Link{channel: selectionTestChannel{id: id, created: now}, ctx: context.Background(), options: (Options{}).defaults(), info: Info{CandidateID: id}, lastPong: now, rtt: rtt, control: make(chan []byte, 8)}
	}
	current, faster := makeLink("current", 100*time.Millisecond), makeLink("faster", 10*time.Millisecond)
	e := NewCoordinatedEdge(model.ID("a"), model.ID("b"), "")
	e.Add(current)
	e.Add(faster)
	e.activateLocked(current, now)
	e.selection.target, e.selection.confirmed = "current", true
	sequence := e.selection.sequence
	for range 10 {
		for _, status := range e.Report() {
			if status.Active != (status.LinkID == "current") {
				t.Fatalf("reported %s active=%v", status.LinkID, status.Active)
			}
		}
	}
	if e.selection.sequence != sequence || e.selection.target != "current" || len(faster.control) != 0 {
		t.Fatal("reporting advanced selection")
	}
}
