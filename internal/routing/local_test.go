package routing

import (
	"reflect"
	"testing"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
)

func TestLocalRoutesMatchCompileAndReroute(t *testing.T) {
	state := testutil.Topology()
	for _, agent := range state.Agents {
		snapshot, err := Compile(state, agent.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range snapshot.Networks {
			if len(n.Topology) != len(state.Networks[0].Edges) {
				t.Fatalf("topology has %d edges", len(n.Topology))
			}
			all := LocalRoutes(n, func(model.TopologyEdge) bool { return true })
			if !reflect.DeepEqual(all, n.Routes) {
				t.Fatalf("agent %s: local routes %v, compiled %v", agent.ID, all, n.Routes)
			}
		}
	}
	// A (20) reaches C (22) through B (21) at cost 20; without A-B it uses
	// A-D-C at cost 31.
	snapshot, _ := Compile(state, state.Agents[0].ID)
	n := snapshot.Networks[0]
	routes := LocalRoutes(n, func(e model.TopologyEdge) bool { return e.ID != testutil.ID(40) })
	for _, r := range routes {
		if r.Destination == testutil.ID(22) && (r.NextHop != testutil.ID(23) || r.Cost != 31) {
			t.Fatalf("route to C: %+v", r)
		}
	}
	next := snapshot.Clone()
	next.Networks[0].Routes = routes
	if err := next.Validate(snapshot.AgentID); err != nil {
		t.Fatal(err)
	}
}
