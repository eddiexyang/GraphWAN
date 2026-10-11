package model

import (
	"errors"
	"reflect"
	"slices"
	"time"
)

const DeltaSubprotocol = "graphwan.control.delta.v1"

func SupportsRoutes(protocol string) bool {
	return protocol == RoutingSubprotocol || protocol == DeltaSubprotocol
}

// SnapshotDelta is relative to the last snapshot received on this connection,
// not the last snapshot applied by the runtime. Reconnects always start full.
type SnapshotDelta struct {
	BaseRevision   uint64          `json:"base_revision"`
	Revision       uint64          `json:"revision"`
	ServerRevision uint64          `json:"server_revision,omitempty"`
	Endpoints      []EndpointDelta `json:"endpoints,omitempty"`
}

type EndpointLease struct {
	ID        ID        `json:"id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Empty Network/Node targets the Agent's own discovered/manual endpoint set.
type EndpointDelta struct {
	Network ID              `json:"network,omitempty"`
	Node    ID              `json:"node,omitempty"`
	Upsert  []Endpoint      `json:"upsert,omitempty"`
	Remove  []ID            `json:"remove,omitempty"`
	Leases  []EndpointLease `json:"leases,omitempty"`
	Reorder bool            `json:"reorder,omitempty"`
	Order   []ID            `json:"order,omitempty"`
}

// EndpointDeltaFrom declines structural changes so membership, trust, policy
// and route edits continue to use the complete, validated snapshot contract.
func EndpointDeltaFrom(previous, next Snapshot) *SnapshotDelta {
	if next.Revision <= previous.Revision {
		return nil
	}
	a, b := previous.Clone(), next.Clone()
	d := &SnapshotDelta{BaseRevision: a.Revision, Revision: b.Revision}
	a.Revision, b.Revision = 0, 0
	if a.Servers != nil && b.Servers != nil {
		d.ServerRevision = b.Servers.Revision
		a.Servers.Revision, b.Servers.Revision = 0, 0
	}
	add := func(network, node ID, old, fresh []Endpoint) {
		if !slices.Equal(old, fresh) {
			d.Endpoints = append(d.Endpoints, endpointDelta(network, node, old, fresh))
		}
	}
	add("", "", a.Endpoints, b.Endpoints)
	a.Endpoints, b.Endpoints = nil, nil
	if len(a.Networks) != len(b.Networks) {
		return nil
	}
	for i := range a.Networks {
		x, y := &a.Networks[i], &b.Networks[i]
		if x.ID != y.ID || len(x.Peers) != len(y.Peers) {
			return nil
		}
		for j := range x.Peers {
			p, q := &x.Peers[j], &y.Peers[j]
			if p.Node.ID != q.Node.ID {
				return nil
			}
			add(x.ID, p.Node.ID, p.Endpoints, q.Endpoints)
			p.Endpoints, q.Endpoints = nil, nil
		}
	}
	if !reflect.DeepEqual(a, b) {
		return nil
	}
	return d
}

func endpointDelta(network, node ID, previous, next []Endpoint) EndpointDelta {
	d := EndpointDelta{Network: network, Node: node}
	old := make(map[ID]Endpoint, len(previous))
	var oldOrder, newOrder []ID
	for _, e := range previous {
		old[e.ID] = e
		oldOrder = append(oldOrder, e.ID)
	}
	for _, e := range next {
		newOrder = append(newOrder, e.ID)
		prior, ok := old[e.ID]
		delete(old, e.ID)
		if ok && prior == e {
			continue
		}
		lease := e.ExpiresAt
		e.ExpiresAt = prior.ExpiresAt
		if ok && e == prior {
			d.Leases = append(d.Leases, EndpointLease{ID: e.ID, ExpiresAt: lease})
		} else {
			e.ExpiresAt = lease
			d.Upsert = append(d.Upsert, e)
		}
	}
	for _, e := range previous {
		if _, ok := old[e.ID]; ok {
			d.Remove = append(d.Remove, e.ID)
		}
	}
	if !slices.Equal(oldOrder, newOrder) {
		d.Reorder, d.Order = true, newOrder
	}
	return d
}

func (d SnapshotDelta) Apply(base Snapshot) (Snapshot, error) {
	if d.BaseRevision != base.Revision || d.Revision <= base.Revision {
		return Snapshot{}, errors.New("configuration delta base mismatch")
	}
	next := base.Clone()
	next.Revision = d.Revision
	if next.Servers != nil {
		next.Servers.Revision = d.ServerRevision
	} else if d.ServerRevision != 0 {
		return Snapshot{}, errors.New("delta cannot add a server directory")
	}
	seen := map[[2]ID]bool{}
	for _, patch := range d.Endpoints {
		key := [2]ID{patch.Network, patch.Node}
		if seen[key] {
			return Snapshot{}, errors.New("duplicate endpoint delta target")
		}
		seen[key] = true
		var target *[]Endpoint
		if patch.Network == "" && patch.Node == "" {
			target = &next.Endpoints
		} else {
			for i := range next.Networks {
				n := &next.Networks[i]
				if n.ID != patch.Network {
					continue
				}
				for j := range n.Peers {
					if n.Peers[j].Node.ID == patch.Node {
						target = &n.Peers[j].Endpoints
					}
				}
			}
		}
		if target == nil {
			return Snapshot{}, errors.New("unknown endpoint delta target")
		}
		endpoints, err := patch.apply(*target)
		if err != nil {
			return Snapshot{}, err
		}
		*target = endpoints
	}
	if err := next.Validate(base.AgentID); err != nil {
		return Snapshot{}, err
	}
	return next, nil
}

func (d EndpointDelta) apply(previous []Endpoint) ([]Endpoint, error) {
	if len(d.Upsert)+len(d.Leases)+len(d.Remove) > 2*MaxEndpoints || len(d.Order) > MaxEndpoints {
		return nil, errors.New("endpoint delta too large")
	}
	entries := make(map[ID]Endpoint, len(previous))
	order := make([]ID, 0, len(previous))
	for _, e := range previous {
		entries[e.ID] = e
		order = append(order, e.ID)
	}
	touched := map[ID]bool{}
	touch := func(id ID) bool {
		if touched[id] {
			return false
		}
		touched[id] = true
		return true
	}
	for _, id := range d.Remove {
		if _, ok := entries[id]; !ok || !touch(id) {
			return nil, errors.New("invalid endpoint removal")
		}
		delete(entries, id)
	}
	for _, e := range d.Upsert {
		if !touch(e.ID) {
			return nil, errors.New("duplicate endpoint change")
		}
		if _, ok := entries[e.ID]; !ok {
			order = append(order, e.ID)
		}
		entries[e.ID] = e
	}
	for _, lease := range d.Leases {
		e, ok := entries[lease.ID]
		if !ok || !touch(lease.ID) {
			return nil, errors.New("invalid endpoint lease")
		}
		e.ExpiresAt = lease.ExpiresAt
		entries[lease.ID] = e
	}
	if d.Reorder {
		order = d.Order
	} else if len(d.Order) != 0 {
		return nil, errors.New("unexpected endpoint order")
	}
	out := make([]Endpoint, 0, len(entries))
	for _, id := range order {
		if e, ok := entries[id]; ok {
			out = append(out, e)
			delete(entries, id)
		} else if d.Reorder {
			return nil, errors.New("invalid endpoint order")
		}
	}
	if len(entries) != 0 || len(out) > MaxEndpoints {
		return nil, errors.New("incomplete endpoint order")
	}
	return out, nil
}

type RevisionAck struct {
	AppliedRevision uint64 `json:"applied_revision"`
}
