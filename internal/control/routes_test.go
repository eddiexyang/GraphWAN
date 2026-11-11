package control

import (
	"testing"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/routing"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
)

// The controller keeps an Agent's routes while its reports describe the same
// ones without carrying them, and admits only routes over the Agent's own
// Networks and their members.
func TestReportedRoutes(t *testing.T) {
	state := testutil.Topology()
	snapshot, err := routing.Compile(state, state.Agents[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	n := snapshot.Networks[0]
	other := n.Directory[len(n.Directory)-1].NodeID
	routes := map[model.ID][]model.Route{n.ID: {{Destination: other, NextHop: other, Cost: 1}}}
	old := &model.LinkStateReport{RouteHash: "h1", Routes: routes}
	if got := keepRoutes(old, &model.LinkStateReport{RouteHash: "h1"}); got.Routes == nil {
		t.Fatal("unchanged routes were dropped")
	}
	if got := keepRoutes(old, &model.LinkStateReport{RouteHash: "h2"}); got.Routes != nil {
		t.Fatal("routes of another hash were kept")
	}
	if got := keepRoutes(nil, &model.LinkStateReport{RouteHash: "h1"}); got.Routes != nil {
		t.Fatal("routes appeared from nothing")
	}
	if err := validateRoutes(snapshot, old); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]map[model.ID][]model.Route{
		"unknown network":   {model.ID("ffffffffffffffffffffffffffffffff"): routes[n.ID]},
		"unknown node":      {n.ID: {{Destination: "ffffffffffffffffffffffffffffffff", NextHop: other}}},
		"unknown next hop":  {n.ID: {{Destination: other, NextHop: "ffffffffffffffffffffffffffffffff"}}},
		"unknown alternate": {n.ID: {{Destination: other, NextHop: other, Alternates: []model.ID{"ffffffffffffffffffffffffffffffff"}}}},
	} {
		if validateRoutes(snapshot, &model.LinkStateReport{Routes: bad}) == nil {
			t.Fatalf("%s was admitted", name)
		}
	}
}
