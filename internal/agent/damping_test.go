package agent

import (
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
)

func TestEdgeDamping(t *testing.T) {
	const network, edge = model.ID("n"), model.ID("e")
	up := map[model.ID]map[model.ID]bool{network: {edge: true}}
	down := map[model.ID]map[model.ID]bool{}
	d := newEdgeDamper()
	now := time.Unix(1000, 0)
	reported := func(raw map[model.ID]map[model.ID]bool) bool {
		return d.filter(raw, now)[network][edge]
	}
	step := func(by time.Duration) { now = now.Add(by) }

	// The first up after start is not held.
	if !reported(up) {
		t.Fatal("first up after start was held")
	}
	// After a failure the edge must stay up for 30s.
	reported(down)
	step(time.Second)
	if reported(up) {
		t.Fatal("edge reported up right after a failure")
	}
	if held := d.held(now); len(held) != 1 || held[0].Failures != 1 || held[0].RemainingMS != dampHold.Milliseconds() {
		t.Fatalf("held = %+v", held)
	}
	step(dampHold - time.Millisecond)
	if reported(up) {
		t.Fatal("edge released before its hold")
	}
	step(time.Millisecond)
	if !reported(up) || len(d.held(now)) != 0 {
		t.Fatal("edge not released after its hold")
	}

	// Failing during a hold doubles it, up to the cap.
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, dampMax, dampMax}
	reported(down)
	for i, hold := range want {
		step(time.Second)
		reported(up)
		if got := d.edges[dampKey{network, edge}].hold; got != hold {
			t.Fatalf("failure %d: hold = %v, want %v", i+2, got, hold)
		}
		step(time.Second)
		reported(down) // fails again while held
	}

	// A released edge that stays up for dampStable forgets its failures.
	step(time.Second)
	reported(up)
	step(dampMax)
	if !reported(up) {
		t.Fatal("edge not released after the maximum hold")
	}
	step(dampStable)
	reported(up)
	reported(down)
	step(time.Second)
	reported(up)
	if got := d.edges[dampKey{network, edge}].hold; got != dampHold {
		t.Fatalf("hold after a stable period = %v, want %v", got, dampHold)
	}

	// Edges are independent, and an edge that never came up keeps no state.
	other := map[model.ID]map[model.ID]bool{network: {edge: true, "f": true}}
	if !d.filter(other, now)[network]["f"] {
		t.Fatal("another edge's first up was held")
	}
	d.filter(map[model.ID]map[model.ID]bool{network: {"g": false}}, now)
	if d.edges[dampKey{network, "g"}] != nil {
		t.Fatal("state kept for an edge that never came up")
	}
}

func TestHoldFor(t *testing.T) {
	for failures, want := range map[int]time.Duration{0: dampHold, 1: dampHold, 2: time.Minute, 5: 8 * time.Minute, 6: dampMax, 60: dampMax} {
		if got := holdFor(failures); got != want {
			t.Fatalf("holdFor(%d) = %v, want %v", failures, got, want)
		}
	}
}
