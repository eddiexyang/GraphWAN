package link

import (
	"context"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
)

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

// The selector proposes a new Link as soon as it becomes healthy, whether that
// happens before or after the Edge learns of it, without waiting for a Tick.
func TestPrepareWhenLinkBecomesHealthy(t *testing.T) {
	now := time.Now()
	makeLink := func(id string) *Link {
		return &Link{channel: selectionTestChannel{id: id, created: now}, ctx: context.Background(), options: (Options{}).defaults(), info: Info{CandidateID: id}, pending: map[uint64]time.Time{1: now}, control: make(chan []byte, 8)}
	}
	prepared := func(l *Link) bool {
		select {
		case raw := <-l.control:
			return raw[0] == prepareMessage
		default:
			return false
		}
	}

	later := makeLink("later")
	e := NewCoordinatedEdge(model.ID("a"), model.ID("b"), "")
	e.Add(later)
	if prepared(later) {
		t.Fatal("prepare on an unhealthy Link")
	}
	later.recordPong(1, time.Now())
	if !prepared(later) {
		t.Fatal("no prepare when the Link became healthy")
	}

	earlier := makeLink("earlier")
	earlier.recordPong(1, time.Now())
	e = NewCoordinatedEdge(model.ID("a"), model.ID("b"), "")
	e.Add(earlier)
	if !prepared(earlier) {
		t.Fatal("no prepare for a Link healthy before it was added")
	}
}

// A selected Link that misses its health checks for a while is deselected and,
// once healthy again, selected again at each end, though it stays the target
// and no new round starts.
func TestSelectedLinkResumesAfterRecovering(t *testing.T) {
	now := time.Now()
	for _, leader := range []bool{true, false} {
		local, remote := model.ID("a"), model.ID("b")
		if !leader {
			local, remote = remote, local
		}
		l := &Link{channel: selectionTestChannel{id: "only", created: now}, ctx: context.Background(), options: (Options{}).defaults(), info: Info{CandidateID: "only"}, lastPong: now, control: make(chan []byte, 8)}
		e := NewCoordinatedEdge(local, remote, "")
		e.Add(l)
		e.activateLocked(l, now)
		e.selection.target, e.selection.accepted, e.selection.confirmed = "only", true, true
		l.mu.Lock()
		l.probeSince = now.Add(-time.Minute)
		l.mu.Unlock()
		e.Tick()
		if e.Active() != nil || e.active != "" {
			t.Fatalf("leader %v: an unhealthy Link stayed selected", leader)
		}
		l.mu.Lock()
		l.probeSince = time.Time{}
		l.mu.Unlock()
		e.Tick()
		if e.Active() != l {
			t.Fatalf("leader %v: the recovered Link was not selected again", leader)
		}
	}
}
