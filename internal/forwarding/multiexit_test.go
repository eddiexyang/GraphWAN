package forwarding_test

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/eWloYW8/GraphWAN/internal/forwarding"
	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/routing"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
)

// exitNetwork runs one Router per Node; deliveries record the exit Node.
type exitNetwork struct {
	t        *testing.T
	state    model.State
	routers  map[model.ID]*forwarding.Router
	exitNode model.ID
}

func newExitNetwork(t *testing.T, state model.State) *exitNetwork {
	x := &exitNetwork{t: t, state: state, routers: map[model.ID]*forwarding.Router{}}
	for _, node := range state.Networks[0].Nodes {
		snapshot, err := routing.Compile(state, node.AgentID)
		if err != nil {
			t.Fatal(err)
		}
		r, err := forwarding.New(snapshot, func(ctx context.Context, network, next model.ID, frame []byte) error {
			return x.routers[next].FromPeer(ctx, node.ID, frame)
		}, func(context.Context, model.ID, []byte) error { x.exitNode = node.ID; return nil })
		if err != nil {
			t.Fatal(err)
		}
		x.routers[node.ID] = r
	}
	return x
}

// update recompiles every Router that is still part of the Network.
func (x *exitNetwork) update(change func(*model.State)) {
	x.t.Helper()
	change(&x.state)
	x.state.Revision++
	for _, node := range x.state.Networks[0].Nodes {
		snapshot, err := routing.Compile(x.state, node.AgentID)
		if err != nil {
			continue // revoked
		}
		if err := x.routers[node.ID].Configure(snapshot); err != nil {
			x.t.Fatal(err)
		}
	}
}

// send sends a UDP packet from A and returns the Node that delivered it.
func (x *exitNetwork) send(destination string, sourcePort uint16) model.ID {
	x.t.Helper()
	raw := ipv4("10.42.0.1", destination)
	binary.BigEndian.PutUint16(raw[20:22], sourcePort)
	binary.BigEndian.PutUint16(raw[22:24], 53)
	x.exitNode = ""
	n := x.state.Networks[0]
	if err := x.routers[n.Nodes[0].ID].FromTunnel(context.Background(), n.ID, raw); err != nil {
		x.t.Fatalf("send to %s: %v", destination, err)
	}
	return x.exitNode
}

func advertise(n *model.Network, node int, prefix string, metric uint32) {
	n.Nodes[node].AdvertisedSubnets = append(n.Nodes[node].AdvertisedSubnets, model.AdvertisedSubnet{Prefix: netip.MustParsePrefix(prefix), GatewayMode: model.GatewayOff, Metric: metric})
}

// exitTopology adds an A-C edge to the test topology. 192.168.0.0/24 has
// three exits from A: D (cost 1 + metric 9), B (10 + 10) and C (25 + 10).
func exitTopology() model.State {
	state := testutil.Topology()
	n := &state.Networks[0]
	n.Edges = append(n.Edges, model.Edge{ID: testutil.ID(45), A: n.Nodes[0].ID, B: n.Nodes[2].ID, Weight: 25, Enabled: true, Transports: []model.Transport{model.UDP}, Methods: model.ConnectionMethods{IPv4Direct: true}})
	advertise(n, 3, "192.168.0.0/24", 9)
	advertise(n, 1, "192.168.0.0/24", 10)
	advertise(n, 2, "192.168.0.0/24", 10)
	return state
}

// Traffic uses the exit with the lowest path cost plus metric and moves to
// the next one as exits fail.
func TestLowestCostExit(t *testing.T) {
	x := newExitNetwork(t, exitTopology())
	n := x.state.Networks[0]
	b, c, d := n.Nodes[1].ID, n.Nodes[2].ID, n.Nodes[3].ID
	if got := x.send("192.168.0.7", 1000); got != d {
		t.Fatalf("exit %s, want D", got)
	}
	x.update(func(s *model.State) { s.Agents[3].Revoked = true })
	if got := x.send("192.168.0.7", 1001); got != b {
		t.Fatalf("after D failed: exit %s, want B", got)
	}
	x.update(func(s *model.State) { s.Agents[1].Revoked = true })
	if got := x.send("192.168.0.7", 1002); got != c {
		t.Fatalf("after B failed: exit %s, want C", got)
	}
}

// A UDP flow keeps its exit when another exit becomes cheaper, and moves only
// when its exit becomes unreachable. New flows use the cheaper exit.
func TestUDPFlowKeepsExit(t *testing.T) {
	x := newExitNetwork(t, exitTopology())
	n := x.state.Networks[0]
	b, d := n.Nodes[1].ID, n.Nodes[3].ID
	if got := x.send("192.168.0.7", 2000); got != d {
		t.Fatalf("exit %s, want D", got)
	}
	x.update(func(s *model.State) { s.Networks[0].Nodes[1].AdvertisedSubnets[0].Metric = 0 }) // B: 10, ties D and wins on Node ID
	if got := x.send("192.168.0.7", 2000); got != d {
		t.Fatalf("existing flow moved to %s", got)
	}
	if got := x.send("192.168.0.7", 2001); got != b {
		t.Fatalf("new flow exit %s, want B", got)
	}
	x.update(func(s *model.State) { s.Agents[3].Revoked = true })
	if got := x.send("192.168.0.7", 2000); got != b {
		t.Fatalf("flow did not leave the failed exit: %s", got)
	}
}

// Equal-cost exits: lowest-id always uses the lowest Node ID; ECMP keeps each
// flow on one exit and spreads flows over both.
func TestEqualCostExits(t *testing.T) {
	state := exitTopology()
	n := &state.Networks[0]
	n.Nodes[3].AdvertisedSubnets[0].Metric = 19 // D: 1 + 19, B: 10 + 10
	b := n.Nodes[1].ID
	x := newExitNetwork(t, state)
	for port := uint16(3000); port < 3032; port++ {
		if got := x.send("192.168.0.9", port); got != b {
			t.Fatalf("lowest-id: flow %d exit %s, want B", port, got)
		}
	}
	state.Networks[0].EqualCostPaths = model.EqualCostECMP
	x = newExitNetwork(t, state)
	used := map[model.ID]int{}
	for port := uint16(3000); port < 3032; port++ {
		first := x.send("192.168.0.9", port)
		for range 3 {
			if got := x.send("192.168.0.9", port); got != first {
				t.Fatalf("ecmp: flow %d moved from %s to %s", port, first, got)
			}
		}
		used[first]++
	}
	if len(used) != 2 {
		t.Fatalf("ecmp used exits %v", used)
	}
}
