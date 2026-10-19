package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
)

// FullMeshGroup is a topology group, not an IP subnet. Internal edges are
// derived rather than persisted, so membership and shared policy cannot drift.
type FullMeshGroup struct {
	ID         ID                `json:"id"`
	Name       string            `json:"name"`
	Weight     *uint32           `json:"weight,omitempty"`
	Members    []ID              `json:"members"`
	Transports []Transport       `json:"transports"`
	Methods    ConnectionMethods `json:"methods"`
	Overrides  []EdgeOverride    `json:"overrides,omitempty"`
}

// EdgeOverride replaces shared settings on one expanded pair. Unset fields
// inherit from the owner so later shared changes still reach the pair.
type EdgeOverride struct {
	A                  ID                 `json:"a"`
	B                  ID                 `json:"b"`
	Weight             *uint32            `json:"weight,omitempty"`
	Enabled            *bool              `json:"enabled,omitempty"`
	Transports         []Transport        `json:"transports,omitempty"`
	Methods            *ConnectionMethods `json:"methods,omitempty"`
	PreferredCandidate string             `json:"preferred_candidate,omitempty"`
}

func (o EdgeOverride) apply(e Edge) Edge {
	if o.Weight != nil {
		e.Weight = *o.Weight
	}
	if o.Enabled != nil {
		e.Enabled = *o.Enabled
	}
	if o.Transports != nil {
		e.Transports = slices.Clone(o.Transports)
	}
	if o.Methods != nil {
		e.Methods = *o.Methods
	}
	e.PreferredCandidate = o.PreferredCandidate
	return e
}

func (o EdgeOverride) Clone() EdgeOverride {
	if o.Weight != nil {
		weight := *o.Weight
		o.Weight = &weight
	}
	if o.Enabled != nil {
		enabled := *o.Enabled
		o.Enabled = &enabled
	}
	if o.Methods != nil {
		methods := *o.Methods
		o.Methods = &methods
	}
	o.Transports = slices.Clone(o.Transports)
	return o
}

func cloneOverrides(overrides []EdgeOverride) []EdgeOverride {
	if overrides == nil {
		return nil
	}
	out := make([]EdgeOverride, len(overrides))
	for i, o := range overrides {
		out[i] = o.Clone()
	}
	return out
}

func pairKey(a, b ID) [2]ID {
	if a > b {
		a, b = b, a
	}
	return [2]ID{a, b}
}

type overrideSet map[[2]ID]EdgeOverride

func newOverrideSet(overrides []EdgeOverride) overrideSet {
	set := make(overrideSet, len(overrides))
	for _, o := range overrides {
		set[pairKey(o.A, o.B)] = o
	}
	return set
}

func (s overrideSet) apply(e Edge) Edge {
	if o, ok := s[pairKey(e.A, e.B)]; ok {
		return o.apply(e)
	}
	return e
}

// RoutingWeight preserves weight 1 for groups saved before weight was configurable.
func (g FullMeshGroup) RoutingWeight() uint32 {
	if g.Weight == nil {
		return 1
	}
	return *g.Weight
}

// GroupLink expands one node-to-group or group-to-group connection into
// independently routed edges. Exactly one of Node and SourceGroup is set.
type GroupLink struct {
	ID          ID                `json:"id"`
	Node        ID                `json:"node,omitempty"`
	SourceGroup ID                `json:"source_group,omitempty"`
	Group       ID                `json:"group"`
	Weight      uint32            `json:"weight"`
	Enabled     bool              `json:"enabled"`
	Transports  []Transport       `json:"transports"`
	Methods     ConnectionMethods `json:"methods"`
	Overrides   []EdgeOverride    `json:"overrides,omitempty"`
}

func (n Network) group(id ID) (FullMeshGroup, bool) {
	for _, g := range n.Groups {
		if g.ID == id {
			return g, true
		}
	}
	return FullMeshGroup{}, false
}

// sources returns the near end of a link: its node, or every source group member.
func (n Network) sources(link GroupLink) []ID {
	if link.SourceGroup == "" {
		return []ID{link.Node}
	}
	g, _ := n.group(link.SourceGroup)
	return g.Members
}

func (n Network) groupEdges(g FullMeshGroup) []Edge {
	members := slices.Clone(g.Members)
	slices.Sort(members)
	overrides := newOverrideSet(g.Overrides)
	edges := []Edge{}
	for i, a := range members {
		for _, b := range members[i+1:] {
			edges = append(edges, overrides.apply(Edge{ID: GroupEdgeID(g.ID, a, b), A: a, B: b, Weight: g.RoutingWeight(), Enabled: true, Transports: slices.Clone(g.Transports), Methods: g.Methods}))
		}
	}
	return edges
}

func (n Network) linkEdges(link GroupLink) []Edge {
	g, ok := n.group(link.Group)
	if !ok {
		return nil
	}
	overrides := newOverrideSet(link.Overrides)
	edges := []Edge{}
	for _, a := range n.sources(link) {
		for _, b := range g.Members {
			edges = append(edges, overrides.apply(Edge{ID: GroupEdgeID(link.ID, a, b), A: a, B: b, Weight: link.Weight, Enabled: link.Enabled, Transports: slices.Clone(link.Transports), Methods: link.Methods}))
		}
	}
	return edges
}

func GroupEdgeID(group, a, b ID) ID {
	if a > b {
		a, b = b, a
	}
	sum := sha256.Sum256([]byte("graphwan/full-mesh/" + string(group) + "/" + string(a) + "/" + string(b)))
	return ID(hex.EncodeToString(sum[:16]))
}

// EffectiveEdges must only be called on validated/bounded groups.
func (n Network) EffectiveEdges() []Edge {
	if len(n.Groups) == 0 && len(n.GroupLinks) == 0 {
		return n.Edges
	}
	edges := slices.Clone(n.Edges)
	for _, g := range n.Groups {
		edges = append(edges, n.groupEdges(g)...)
	}
	for _, link := range n.GroupLinks {
		edges = append(edges, n.linkEdges(link)...)
	}
	return edges
}

func (n Network) validateGroups(addID func(ID) error) error {
	nodes := make(map[ID]Node, len(n.Nodes))
	for _, node := range n.Nodes {
		nodes[node.ID] = node
	}
	used := map[ID]bool{}
	count := int64(len(n.Edges))
	for _, g := range n.Groups {
		if err := addID(g.ID); err != nil {
			return err
		}
		if err := validateName(g.Name); err != nil {
			return err
		}
		if len(g.Members) < 2 || len(g.Members) > MaxNodes {
			return fmt.Errorf("full mesh group requires 2–%d members", MaxNodes)
		}
		size := int64(len(g.Members))
		count += size * (size - 1) / 2
		if count > MaxEdges {
			return fmt.Errorf("full mesh topology exceeds %d edges", MaxEdges)
		}
		for _, id := range g.Members {
			node, ok := nodes[id]
			if !ok || node.WireGuard != nil {
				return fmt.Errorf("full mesh members must be regular nodes in this network")
			}
			if used[id] {
				return fmt.Errorf("node belongs to a full mesh group more than once")
			}
			used[id] = true
		}
	}
	groups := map[ID]FullMeshGroup{}
	for _, g := range n.Groups {
		groups[g.ID] = g
	}
	for _, g := range n.Groups {
		if err := validateOverrides(g.Overrides, func(a, b ID) bool {
			return a != b && slices.Contains(g.Members, a) && slices.Contains(g.Members, b)
		}); err != nil {
			return err
		}
	}
	pairs := map[[2]ID]bool{}
	for _, link := range n.GroupLinks {
		if err := addID(link.ID); err != nil {
			return err
		}
		g, exists := groups[link.Group]
		if !exists {
			return fmt.Errorf("group link requires an existing target group")
		}
		var key [2]ID
		size := int64(len(g.Members))
		if link.SourceGroup != "" {
			source, ok := groups[link.SourceGroup]
			if link.Node != "" || !ok || link.SourceGroup == link.Group {
				return fmt.Errorf("group-to-group link requires two distinct groups and no node")
			}
			key = pairKey(link.SourceGroup, link.Group)
			size *= int64(len(source.Members))
		} else {
			node, ok := nodes[link.Node]
			if !ok || node.WireGuard != nil || slices.Contains(g.Members, link.Node) {
				return fmt.Errorf("group link requires a regular node outside its target group")
			}
			key = [2]ID{link.Node, link.Group}
		}
		if pairs[key] {
			return fmt.Errorf("duplicate group link")
		}
		pairs[key] = true
		count += size
		if count > MaxEdges {
			return fmt.Errorf("expanded topology exceeds %d edges", MaxEdges)
		}
		near := n.sources(link)
		if err := validateOverrides(link.Overrides, func(a, b ID) bool {
			return slices.Contains(near, a) && slices.Contains(g.Members, b) || slices.Contains(near, b) && slices.Contains(g.Members, a)
		}); err != nil {
			return err
		}
	}
	return nil
}

// validateOverrides only checks ownership; overridden values are validated on
// the expanded edge like any explicit edge.
func validateOverrides(overrides []EdgeOverride, expanded func(a, b ID) bool) error {
	seen := map[[2]ID]bool{}
	for _, o := range overrides {
		key := pairKey(o.A, o.B)
		if !expanded(o.A, o.B) {
			return fmt.Errorf("edge override %s–%s is not an expanded pair of its owner", o.A, o.B)
		}
		if seen[key] {
			return fmt.Errorf("duplicate edge override %s–%s", o.A, o.B)
		}
		seen[key] = true
	}
	return nil
}

// PruneGroups removes deleted nodes and groups which no longer have a pair.
func (n *Network) PruneGroups() {
	nodes := map[ID]bool{}
	for _, node := range n.Nodes {
		nodes[node.ID] = true
	}
	stale := func(o EdgeOverride) bool { return !nodes[o.A] || !nodes[o.B] }
	groups := []FullMeshGroup{}
	for _, g := range n.Groups {
		g.Members = slices.DeleteFunc(slices.Clone(g.Members), func(id ID) bool { return !nodes[id] })
		g.Overrides = slices.DeleteFunc(slices.Clone(g.Overrides), stale)
		if len(g.Members) >= 2 {
			groups = append(groups, g)
		}
	}
	n.Groups = groups
	groupIDs := map[ID]bool{}
	for _, g := range groups {
		groupIDs[g.ID] = true
	}
	n.GroupLinks = slices.DeleteFunc(slices.Clone(n.GroupLinks), func(l GroupLink) bool {
		if l.SourceGroup != "" {
			return !groupIDs[l.SourceGroup] || !groupIDs[l.Group]
		}
		return !nodes[l.Node] || !groupIDs[l.Group]
	})
	for i := range n.GroupLinks {
		n.GroupLinks[i].Overrides = slices.DeleteFunc(slices.Clone(n.GroupLinks[i].Overrides), stale)
	}
}
