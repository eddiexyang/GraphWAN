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
