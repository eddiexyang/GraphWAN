package agent

import (
	"testing"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/streamproxy"
)

func outgoingE2E(r *DataPlane, network, node model.ID) *e2eSession {
	r.e2e.mu.Lock()
	defer r.e2e.mu.Unlock()
	if out := r.e2e.outgoing[e2ePeer{network, node}]; out != nil {
		return out.current
	}
	return nil
}

// A session through a relay is sealed by its ends: the egress opens records
// of the ingress's session toward it, which the relay does not hold, and it
// refuses a request that would have it send unsealed.
func TestTCPSessionIsSealedEndToEnd(t *testing.T) {
	agents, devices, state := graphAgents(t, model.TCP, streamOptions{}, 3, 2)
	sessionExchange(t, devices, state, 2, 1<<20, 4<<20, func() {
		if relaying(agents[1]) != 1 {
			t.Errorf("relayed chains %d", relaying(agents[1]))
		}
	})
	network, nodes := state.Networks[0].ID, state.Networks[0].Nodes
	sealed := outgoingE2E(agents[0], network, nodes[2].ID)
	if sealed == nil || agents[2].e2eAccepted(network, nodes[0].ID, sealed.id) == nil {
		t.Fatal("no end-to-end session between the ends")
	}
	if agents[1].e2eAccepted(network, nodes[0].ID, sealed.id) != nil {
		t.Fatal("the relay holds the session")
	}
	request := streamproxy.Request{Network: network, Source: nodes[0].ID, Destination: nodes[2].ID, Conn: streamproxy.NewSessionID()}
	if _, ok := agents[2].egressRecords(network, request); ok {
		t.Fatal("the egress accepted an unsealed session")
	}
	request.Sealer, request.E2E, request.Channel = nodes[0].ID, streamproxy.E2EID{1}, 1
	if _, ok := agents[2].egressRecords(network, request); ok {
		t.Fatal("the egress accepted an unknown end-to-end session")
	}
	request.Sealer, request.E2E = nodes[1].ID, sealed.id
	if _, ok := agents[2].egressRecords(network, request); ok {
		t.Fatal("the egress accepted another Node's seal for the Source")
	}
}

// An egress that lost its end-to-end sessions, as by a restart, refuses the
// next connection's first chain; the ingress waits for a new session and the
// connection opens.
func TestTCPSessionAfterEgressLostItsKeys(t *testing.T) {
	agents, devices, state := graphAgents(t, model.TCP, streamOptions{}, 3, 2)
	sessionExchange(t, devices, state, 2, 64<<10, 4<<20, nil)
	network, nodes := state.Networks[0].ID, state.Networks[0].Nodes
	before := outgoingE2E(agents[0], network, nodes[2].ID)
	agents[2].e2e.mu.Lock()
	clear(agents[2].e2e.incoming)
	agents[2].e2e.mu.Unlock()
	transferApplication(t, devices[0], devices[2], nodes[2].Address)
	if after := outgoingE2E(agents[0], network, nodes[2].ID); after == nil || after == before {
		t.Fatal("the ingress kept the lost session")
	}
}
