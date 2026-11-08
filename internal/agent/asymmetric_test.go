package agent

import (
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
)

// asymmetricPaths makes A-B-E-C and A-D-C cost 30 each. Equal-cost routes
// pick the lowest first hop of their own source, so A reaches C through B
// and C reaches A through D: the two directions of one connection take
// different paths without any route change.
func asymmetricPaths(transports func(edge int) model.Transport) func(*model.State) {
	return func(s *model.State) {
		n := &s.Networks[0]
		var edges []model.Edge
		for i, e := range [][3]int{{0, 1, 10}, {1, 4, 10}, {4, 2, 10}, {0, 3, 15}, {3, 2, 15}} {
			edges = append(edges, model.Edge{ID: testutil.ID(60 + i), A: n.Nodes[e[0]].ID, B: n.Nodes[e[1]].ID, Weight: uint32(e[2]), Enabled: true, Transports: []model.Transport{transports(i)}, Methods: model.ConnectionMethods{IPv4Direct: true}})
		}
		n.Edges = edges
	}
}

// Pure TCP and pure UDP paths carry the connection. A mixed path (A-B
// streams, the rest packets) does not connect, on a0556b7 as on this code: the
// segment end dials with the original tuple and its replies return through D
// to A. Mixed paths may break (T3); they still send no TCP over TCP.
func TestTCPOnAsymmetricEqualCostPaths(t *testing.T) {
	for _, carrier := range []model.Transport{model.TCP, model.UDP} {
		t.Run(string(carrier), func(t *testing.T) {
			agents, devices, state := graphAgents(t, carrier, streamOptions{}, 5, 0, asymmetricPaths(func(int) model.Transport { return carrier }))
			n := state.Networks[0]
			// Link-state routes settle after the Links come up.
			waitFor(t, 10*time.Second, "A to reach C through B and C to reach A through D", func() bool {
				forward, _, _ := agents[0].state.Load().router.NextHop(n.ID, n.Nodes[2].Address)
				back, _, _ := agents[2].state.Load().router.NextHop(n.ID, n.Nodes[0].Address)
				return forward == n.Nodes[1].ID && back == n.Nodes[3].ID
			})
			transferApplication(t, devices[0], devices[2], n.Nodes[2].Address)
			assertNoTCPOverTCP(t, agents)
		})
	}
}
