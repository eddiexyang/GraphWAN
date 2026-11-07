// Package routing compiles controller topology into per-agent forwarding tables.
package routing

import (
	"cmp"
	"container/heap"
	"encoding/base64"
	"fmt"
	"slices"

	"github.com/eWloYW8/GraphWAN/internal/model"
)

type arc struct {
	to     model.ID
	weight uint32
}
type item struct {
	node model.ID
	cost uint64
}
type queue []item

func (q queue) Len() int { return len(q) }
func (q queue) Less(i, j int) bool {
	if q[i].cost != q[j].cost {
		return q[i].cost < q[j].cost
	}
	return q[i].node < q[j].node
}
func (q queue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *queue) Push(v any)   { *q = append(*q, v.(item)) }
func (q *queue) Pop() any     { a := *q; v := a[len(a)-1]; *q = a[:len(a)-1]; return v }

// shortest assumes a validated graph. Positive weights keep independently
// compiled routes loop free: every next hop, including the alternates, is on a
// shortest path, so the remaining cost falls at each hop. NextHop is the
// lowest-ID first hop, as before alternates existed. Client nodes are
// destinations or the source, never transit hops.
func shortest(n model.Network, source model.ID, excluded map[model.ID]bool, clients map[model.ID]bool) []model.Route {
	adjacency := map[model.ID][]arc{}
	for _, e := range n.EffectiveEdges() {
		if !e.Enabled || excluded[e.A] || excluded[e.B] {
			continue
		}
		adjacency[e.A] = append(adjacency[e.A], arc{e.B, e.Weight})
		adjacency[e.B] = append(adjacency[e.B], arc{e.A, e.Weight})
	}
	cost := map[model.ID]uint64{source: 0}
	q := &queue{{node: source}}
	for q.Len() > 0 {
		current := heap.Pop(q).(item)
		if cost[current.node] != current.cost {
			continue
		}
		if current.node != source && clients[current.node] {
			continue
		}
		for _, a := range adjacency[current.node] {
			next := current.cost + uint64(a.weight)
			if prev, ok := cost[a.to]; !ok || next < prev {
				cost[a.to] = next
				heap.Push(q, item{node: a.to, cost: next})
			}
		}
	}
	order := make([]model.ID, 0, len(cost))
	for id := range cost {
		if id != source {
			order = append(order, id)
		}
	}
	slices.SortFunc(order, func(a, b model.ID) int { return cmp.Or(cmp.Compare(cost[a], cost[b]), cmp.Compare(a, b)) })
	firsts := map[model.ID][]model.ID{}
	routes := make([]model.Route, 0, len(order))
	for _, id := range order {
		var hops []model.ID
		for _, a := range adjacency[id] {
			previous, ok := cost[a.to]
			if !ok || previous+uint64(a.weight) != cost[id] {
				continue
			}
			switch {
			case a.to == source:
				hops = append(hops, id)
			case !clients[a.to]:
				hops = append(hops, firsts[a.to]...)
			}
		}
		slices.Sort(hops)
		hops = slices.Compact(hops)
		firsts[id] = hops
		route := model.Route{Destination: id, NextHop: hops[0], Cost: cost[id]}
		if len(hops) > 1 {
			route.Alternates = append([]model.ID(nil), hops[1:]...)
		}
		routes = append(routes, route)
	}
	slices.SortFunc(routes, func(a, b model.Route) int { return cmp.Compare(a.Destination, b.Destination) })
	return routes
}

// ClientNodes lists a Network's client nodes, which routes never transit.
func ClientNodes(n model.Network) map[model.ID]bool {
	clients := map[model.ID]bool{}
	for _, node := range n.Nodes {
		if node.Client {
			clients[node.ID] = true
		}
	}
	return clients
}

// LocalRoutes computes an Agent's forwarding table over the edges usable
// reports, with the same metric and tie breaking as the controller.
func LocalRoutes(config model.NetworkConfig, usable func(model.TopologyEdge) bool) []model.Route {
	var n model.Network
	for _, e := range config.Topology {
		if usable(e) {
			n.Edges = append(n.Edges, model.Edge{ID: e.ID, A: e.A, B: e.B, Weight: e.Weight, Enabled: true})
		}
	}
	clients := map[model.ID]bool{}
	for _, d := range config.Directory {
		clients[d.NodeID] = d.Client
	}
	return shortest(n, config.Self.ID, nil, clients)
}

func Compile(state model.State, agentID model.ID) (model.Snapshot, error) {
	if err := state.Validate(); err != nil {
		return model.Snapshot{}, err
	}
	agents := map[model.ID]model.Agent{}
	for _, a := range state.Agents {
		agents[a.ID] = a
	}
	self, ok := agents[agentID]
	if !ok {
		return model.Snapshot{}, fmt.Errorf("unknown agent %s", agentID)
	}
	if self.Revoked {
		return model.Snapshot{}, fmt.Errorf("agent is revoked")
	}
	out := model.Snapshot{Schema: model.SchemaVersion, Revision: state.Revision, AgentID: agentID, ListenPort: self.ListenPort, Endpoints: append([]model.Endpoint{}, self.Endpoints...), Networks: []model.NetworkConfig{}}
	out.STUNServers = append([]string(nil), self.STUNServers...)
	out.ExcludeContainerIPs = self.ExcludeContainerIPs
	out.Servers = state.ServerDirectory()
	for _, network := range state.Networks {
		var me model.Node
		nodes := map[model.ID]model.Node{}
		excluded := map[model.ID]bool{}
		for _, node := range network.Nodes {
			node = node.Clone()
			nodes[node.ID] = node
			if node.AgentID == agentID {
				me = node
			}
			if agents[node.AgentID].Revoked {
				excluded[node.ID] = true
			}
		}
		if me.ID == "" {
			continue
		}
		config := model.NetworkConfig{ID: network.ID, Name: network.Name, CIDR: network.CIDR, MTU: network.MTU, Cipher: network.Cipher, EqualCostPaths: network.EqualCostPaths, Self: me, Directory: []model.Destination{}, Peers: []model.Peer{}, Routes: shortest(network, me.ID, excluded, ClientNodes(network))}
		for _, e := range network.EffectiveEdges() {
			if e.Enabled && !excluded[e.A] && !excluded[e.B] {
				config.Topology = append(config.Topology, model.TopologyEdge{ID: e.ID, A: e.A, B: e.B, Weight: e.Weight})
			}
		}
		slices.SortFunc(config.Topology, func(a, b model.TopologyEdge) int { return cmp.Compare(a.ID, b.ID) })
		for _, node := range network.Nodes {
			if !excluded[node.ID] {
				config.Directory = append(config.Directory, model.Destination{NodeID: node.ID, Address: node.Address, AdvertisedSubnets: append([]model.AdvertisedSubnet(nil), node.AdvertisedSubnets...), Client: node.Client})
			}
		}
		for _, edge := range network.EffectiveEdges() {
			if !edge.Enabled || excluded[edge.A] || excluded[edge.B] {
				continue
			}
			var peerID model.ID
			switch me.ID {
			case edge.A:
				peerID = edge.B
			case edge.B:
				peerID = edge.A
			default:
				continue
			}
			node := nodes[peerID]
			agent := agents[node.AgentID]
			if node.WireGuard != nil {
				agent.PublicKey, _ = base64.StdEncoding.DecodeString(node.WireGuard.PublicKey)
			}
			edge.Transports = append([]model.Transport{}, edge.Transports...)
			config.Peers = append(config.Peers, model.Peer{Node: node, PublicKey: append([]byte{}, agent.PublicKey...), Endpoints: append([]model.Endpoint{}, agent.Endpoints...), Edge: edge})
		}
		slices.SortFunc(config.Directory, func(a, b model.Destination) int { return cmp.Compare(a.NodeID, b.NodeID) })
		slices.SortFunc(config.Peers, func(a, b model.Peer) int { return cmp.Compare(a.Node.ID, b.Node.ID) })
		out.Networks = append(out.Networks, config)
	}
	slices.SortFunc(out.Networks, func(a, b model.NetworkConfig) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}
