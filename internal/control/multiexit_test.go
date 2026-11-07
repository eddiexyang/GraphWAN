package control

import (
	"net/netip"
	"testing"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
)

func TestMultiExitNeedsCapableAgents(t *testing.T) {
	share := func(s *model.State) {
		for i := 0; i < 2; i++ {
			s.Networks[0].Nodes[i].AdvertisedSubnets = []model.AdvertisedSubnet{{Prefix: netip.MustParsePrefix("192.168.0.0/24"), GatewayMode: model.GatewayOff}}
		}
	}
	status := func(s model.State, capable ...int) []model.AgentStatus {
		var out []model.AgentStatus
		for _, i := range capable {
			out = append(out, model.AgentStatus{AgentID: s.Agents[i].ID, AgentReport: model.AgentReport{Capabilities: []string{model.CapabilityMultiExit}}})
		}
		return out
	}
	before := testutil.Topology()
	after := before.Clone()
	share(&after)
	if err := multiExitReady(before, after, status(before, 0, 1, 2, 3)); err == nil {
		t.Fatal("shared a prefix before Agent E reported support")
	}
	if err := multiExitReady(before, after, status(before, 0, 1, 2, 3, 4)); err != nil {
		t.Fatal(err)
	}
	// Once shared, an Agent that stops reporting does not block other changes.
	changed := after.Clone()
	changed.Networks[0].Edges[0].Weight = 20
	if err := multiExitReady(after, changed, status(after, 0)); err != nil {
		t.Fatal(err)
	}
	// An Agent joining the Network must support it.
	joined := changed.Clone()
	joined.Agents = append(joined.Agents, model.Agent{ID: testutil.ID(15)})
	joined.Networks[0].Nodes = append(joined.Networks[0].Nodes, model.Node{ID: testutil.ID(25), AgentID: testutil.ID(15), Address: netip.MustParseAddr("10.42.0.6")})
	if err := multiExitReady(changed, joined, status(changed, 0, 1, 2, 3, 4)); err == nil {
		t.Fatal("an Agent without support joined a Network that shares a prefix")
	}
	// Revoked Agents receive no configuration.
	after.Agents[4].Revoked = true
	if err := multiExitReady(before, after, status(before, 0, 1, 2, 3)); err != nil {
		t.Fatal(err)
	}
}
