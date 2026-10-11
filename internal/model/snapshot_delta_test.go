package model_test

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/routing"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
)

func deltaFixture(t *testing.T) model.Snapshot {
	t.Helper()
	s := testutil.Topology()
	snapshot, err := routing.Compile(s, s.Agents[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestEndpointDeltaRoundTrip(t *testing.T) {
	base := deltaFixture(t)
	for name, edit := range map[string]func(*model.Snapshot){
		"revision": func(*model.Snapshot) {},
		"lease":    func(s *model.Snapshot) { s.Networks[0].Peers[0].Endpoints[0].ExpiresAt = time.Now().UTC() },
		"address":  func(s *model.Snapshot) { s.Endpoints[0].URL = "udp://192.0.2.99:24752" },
		"removal":  func(s *model.Snapshot) { s.Networks[0].Peers[0].Endpoints = nil },
		"addition": func(s *model.Snapshot) {
			s.Endpoints = append(s.Endpoints, model.Endpoint{ID: testutil.ID(100), Transport: model.TCP, Source: model.Manual, URL: "tcp://192.0.2.99:24752"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			next := base.Clone()
			next.Revision++
			edit(&next)
			delta := model.EndpointDeltaFrom(base, next)
			if delta == nil {
				t.Fatal("endpoint edit required full configuration")
			}
			raw, _ := json.Marshal(delta)
			var wire model.SnapshotDelta
			if err := json.Unmarshal(raw, &wire); err != nil {
				t.Fatal(err)
			}
			got, err := wire.Apply(base)
			if err != nil {
				t.Fatal(err)
			}
			// Clone normalizes nil endpoint slices just as the runtime does.
			if !reflect.DeepEqual(got.Clone(), next.Clone()) {
				t.Fatalf("delta mismatch: %+v", got)
			}
			if _, err := wire.Apply(got); err == nil {
				t.Fatal("replayed delta accepted")
			}
			if !reflect.DeepEqual(base, deltaFixture(t)) {
				t.Fatal("delta mutated base")
			}
		})
	}
}

func TestEndpointDeltaRejectsStructuralEditsAndMalformedTargets(t *testing.T) {
	base := deltaFixture(t)
	next := base.Clone()
	next.Revision++
	next.Networks[0].MTU++
	if model.EndpointDeltaFrom(base, next) != nil {
		t.Fatal("MTU edit encoded as endpoint change")
	}
	for _, patch := range []model.EndpointDelta{
		{Network: testutil.ID(999), Node: testutil.ID(20)},
		{Leases: []model.EndpointLease{{ID: testutil.ID(999), ExpiresAt: time.Now()}}},
		{Remove: []model.ID{base.Endpoints[0].ID, base.Endpoints[0].ID}},
		{Reorder: true, Order: []model.ID{}},
	} {
		d := model.SnapshotDelta{BaseRevision: base.Revision, Revision: base.Revision + 1, Endpoints: []model.EndpointDelta{patch}}
		if _, err := d.Apply(base); err == nil {
			t.Fatalf("malformed patch accepted: %+v", patch)
		}
	}
}

func TestLeaseDeltaWireSize(t *testing.T) {
	base := deltaFixture(t)
	next := base.Clone()
	next.Revision++
	next.Networks[0].Peers[0].Endpoints[0].ExpiresAt = time.Now().UTC()
	delta := model.EndpointDeltaFrom(base, next)
	if delta == nil {
		t.Fatal("missing delta")
	}
	raw, _ := json.Marshal(model.ControlMessage{Type: "config_delta", Delta: delta})
	full, _ := json.Marshal(model.ControlMessage{Type: "config", Snapshot: &next})
	t.Logf("single lease update: %d bytes; full snapshot: %d bytes", len(raw), len(full))
	if len(raw) > 400 || len(raw)*5 > len(full) {
		t.Fatal("lease delta repeats configuration")
	}
}
