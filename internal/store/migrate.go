package store

import (
	"slices"

	"github.com/eddiexyang/graphnet/internal/model"
)

// oldDefaultMTU is the default before packets were masked; networks on it
// move to the current one.
const oldDefaultMTU = 1280

// migrate brings a stored state to the current schema and indexes its new
// Nodes.
func migrate(state *model.State) {
	if state.Schema == 1 {
		dropRemoved(state)
		state.Schema = model.SchemaVersion
	}
}

// dropRemoved removes what GraphNet no longer carries from a stored state:
// WebSocket and gRPC endpoints and transports, and WireGuard nodes,
// which decode without an Agent, with their edges. A transport list left
// empty falls back to UDP, and an override left empty inherits.
func dropRemoved(state *model.State) {
	removed := func(t model.Transport) bool { return !t.Valid() }
	required := func(transports []model.Transport) []model.Transport {
		if !slices.ContainsFunc(transports, removed) {
			return transports
		}
		if transports = slices.DeleteFunc(transports, removed); len(transports) == 0 {
			transports = []model.Transport{model.UDP}
		}
		return transports
	}
	overrides := func(list []model.EdgeOverride) {
		for i := range list {
			if list[i].Transports = slices.DeleteFunc(list[i].Transports, removed); len(list[i].Transports) == 0 {
				list[i].Transports = nil
			}
		}
	}
	for i := range state.Agents {
		state.Agents[i].Endpoints = slices.DeleteFunc(state.Agents[i].Endpoints, func(e model.Endpoint) bool { return removed(e.Transport) })
	}
	for i := range state.Networks {
		n := &state.Networks[i]
		if n.MTU == oldDefaultMTU {
			n.MTU = model.DefaultMTU
		}
		leaves := map[model.ID]bool{}
		n.Nodes = slices.DeleteFunc(n.Nodes, func(node model.Node) bool {
			leaves[node.ID] = node.AgentID == ""
			return leaves[node.ID]
		})
		n.Edges = slices.DeleteFunc(n.Edges, func(e model.Edge) bool { return leaves[e.A] || leaves[e.B] })
		for j := range n.Edges {
			n.Edges[j].Transports = required(n.Edges[j].Transports)
		}
		for j := range n.Groups {
			n.Groups[j].Transports = required(n.Groups[j].Transports)
			overrides(n.Groups[j].Overrides)
		}
		for j := range n.GroupLinks {
			n.GroupLinks[j].Transports = required(n.GroupLinks[j].Transports)
			overrides(n.GroupLinks[j].Overrides)
		}
		if len(leaves) != len(n.Nodes) {
			n.PruneGroups()
		}
	}
}

// assignIndexes gives every new Node its wire index.
func assignIndexes(state *model.State) error {
	for i := range state.Networks {
		if err := state.Networks[i].AssignIndexes(); err != nil {
			return err
		}
	}
	return nil
}
