package routing

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
)

// A client node originates and receives its own traffic but never carries
// others'. With A-B made expensive, A-D-C would be the shortest path to C;
// with D a client it is not, while D itself still routes through its edges.
func TestClientNodesAreNeverTransit(t *testing.T) {
	state := testutil.Topology()
	state.Networks[0].Edges[0].Weight = 100 // A-B
	state.Networks[0].Nodes[3].Client = true
	if err := state.Validate(); err != nil {
		t.Fatal(err)
	}
	route := func(agent int, destination int) model.Route {
		t.Helper()
		snapshot, err := Compile(state, state.Agents[agent].ID)
		if err != nil {
			t.Fatal(err)
		}
		n := snapshot.Networks[0]
		local := LocalRoutes(n, func(model.TopologyEdge) bool { return true })
		for i, r := range n.Routes {
			if !reflect.DeepEqual(r, local[i]) {
				t.Fatalf("agent %d: local route %+v, compiled %+v", agent, local[i], r)
			}
		}
		for _, r := range n.Routes {
			if r.Destination == testutil.ID(20+destination) {
				return r
			}
		}
		t.Fatalf("agent %d has no route to node %d", agent, destination)
		return model.Route{}
	}
	if r := route(0, 2); r.NextHop != testutil.ID(21) || r.Cost != 110 {
		t.Fatalf("A to C transited the client: %+v", r)
	}
	if r := route(2, 0); r.NextHop != testutil.ID(21) {
		t.Fatalf("C to A transited the client: %+v", r)
	}
	if r := route(0, 3); r.NextHop != testutil.ID(23) || r.Cost != 1 {
		t.Fatalf("A to the client: %+v", r)
	}
	if r := route(3, 1); r.NextHop != testutil.ID(22) || r.Cost != 40 {
		t.Fatalf("client to B: %+v", r)
	}
}

func TestClientNodeValidation(t *testing.T) {
	for name, change := range map[string]func(*model.State){
		"advertised subnet": func(s *model.State) {
			s.Networks[0].Nodes[3].AdvertisedSubnets = []model.AdvertisedSubnet{{Prefix: mustPrefix("192.168.9.0/24"), GatewayMode: model.GatewayRoute}}
		},
		"client to client": func(s *model.State) { s.Networks[0].Nodes[0].Client = true },
	} {
		state := testutil.Topology()
		state.Networks[0].Nodes[3].Client = true
		change(&state)
		if state.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }
