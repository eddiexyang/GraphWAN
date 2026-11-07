package control

import (
	"fmt"
	"slices"

	"github.com/eWloYW8/GraphWAN/internal/model"
)

// multiExitReady admits a prefix advertised by several Nodes only once every
// Agent in that Network has reported that it accepts one; older Agents reject
// the whole configuration. A Network checks its Agents when it starts sharing
// a prefix, and an Agent when it joins a Network that shares one, so an Agent
// that later goes offline does not block unrelated changes.
func multiExitReady(before, after model.State, statuses []model.AgentStatus) error {
	capable := map[model.ID]bool{}
	for _, status := range statuses {
		capable[status.AgentID] = slices.Contains(status.Capabilities, model.CapabilityMultiExit)
	}
	revoked := map[model.ID]bool{}
	for _, agent := range after.Agents {
		revoked[agent.ID] = agent.Revoked
	}
	previous := map[model.ID]model.Network{}
	for _, n := range before.Networks {
		previous[n.ID] = n
	}
	for _, n := range after.Networks {
		if !model.SharedPrefixes(n.Nodes) {
			continue
		}
		old, existed := previous[n.ID]
		shared := existed && model.SharedPrefixes(old.Nodes)
		members := map[model.ID]bool{}
		for _, node := range old.Nodes {
			members[node.AgentID] = true
		}
		for _, node := range n.Nodes {
			if node.AgentID == "" || revoked[node.AgentID] || capable[node.AgentID] || shared && members[node.AgentID] {
				continue
			}
			return fmt.Errorf("network %s: several nodes advertise one prefix, but agent %s has not reported support for it; upgrade every agent in the network first", n.Name, node.AgentID)
		}
	}
	return nil
}
