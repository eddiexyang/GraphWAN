// Package linkstate lets Agents converge routes from link-state advertisements
// flooded over their peer Links, so forwarding never depends on the controller.
package linkstate

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/routing"
)

const (
	// RefreshInterval re-originates an unchanged LSA, which also repairs a
	// lost one: with link failure detection (up to 6 s) routes converge
	// within 30 s. MaxAge expires the LSA of an origin that stopped refreshing.
	RefreshInterval = 10 * time.Second
	MaxAge          = 40 * time.Second
	// SPFDelay batches the LSAs of one event; MinOriginateInterval bounds
	// the origination rate of a flapping link.
	SPFDelay             = 50 * time.Millisecond
	MinOriginateInterval = 100 * time.Millisecond
	tick                 = 100 * time.Millisecond
	maxLSA               = 64 * 1024
)

// LSA is one origin's report of the edges it can use in one network.
type LSA struct {
	Network  model.ID   `json:"network"`
	Origin   model.ID   `json:"origin"`
	Revision uint64     `json:"revision"`
	Sequence uint64     `json:"sequence"`
	Up       []model.ID `json:"up"`
}

// Callbacks connect the engine to an Agent. Send is best effort: periodic
// refresh repairs a lost advertisement.
type Callbacks struct {
	Send  func(network, peer model.ID, raw []byte)
	Local func() map[model.ID]map[model.ID]bool // network -> edge -> usable here
	Apply func(model.RouteUpdate) error
	Now   func() time.Time
}

type entry struct {
	lsa     LSA
	up      map[model.ID]bool
	arrived time.Time
}

type network struct {
	config    model.NetworkConfig
	neighbors map[model.ID]bool // peer node IDs
	local     map[model.ID]bool
	db        map[model.ID]entry
	sequence  uint64
	sent      time.Time
	dirty     bool // local state changed since the last origination
}

type Engine struct {
	cb       Callbacks
	mu       sync.Mutex
	snapshot *model.Snapshot
	networks map[model.ID]*network
	spfAt    time.Time
	applied  string
	stats    Stats
	events   []Event
}

func New(cb Callbacks) *Engine {
	if cb.Now == nil {
		cb.Now = time.Now
	}
	return &Engine{cb: cb, networks: map[model.ID]*network{}}
}

// Active reports whether the configuration carries topology, in which case
// the Agent routes locally and ignores controller route updates.
func Active(s model.Snapshot) bool {
	if len(s.Networks) == 0 {
		return false
	}
	for _, n := range s.Networks {
		if len(n.Topology) == 0 && len(n.Peers) > 0 {
			return false
		}
	}
	return true
}

// Configure installs a new configuration. Databases of networks that remain
// are kept; their entries are evaluated against the new topology.
func (e *Engine) Configure(s model.Snapshot) {
	e.mu.Lock()
	defer e.mu.Unlock()
	clone := s.Clone()
	e.snapshot = &clone
	next := map[model.ID]*network{}
	for _, c := range clone.Networks {
		n := e.networks[c.ID]
		if n == nil {
			n = &network{db: map[model.ID]entry{}, local: map[model.ID]bool{}}
		}
		n.config = c
		n.neighbors = map[model.ID]bool{}
		for _, p := range c.Peers {
			n.neighbors[p.Node.ID] = true
		}
		n.dirty = true
		next[c.ID] = n
	}
	e.networks = next
	e.scheduleSPFLocked()
}

// PeerReady sends the whole database to a neighbour that can now exchange
// advertisements, as a new adjacency does in OSPF.
func (e *Engine) PeerReady(networkID, peer model.ID) {
	e.mu.Lock()
	n := e.networks[networkID]
	var out [][]byte
	if n != nil && n.neighbors[peer] {
		for _, en := range n.db {
			if raw, err := json.Marshal(en.lsa); err == nil {
				out = append(out, raw)
			}
		}
	}
	e.mu.Unlock()
	for _, raw := range out {
		e.stats.Sent.Add(1)
		e.cb.Send(networkID, peer, raw)
	}
}

// Receive handles an advertisement from an authenticated neighbour.
func (e *Engine) Receive(networkID, peer model.ID, raw []byte) error {
	if len(raw) > maxLSA {
		return errors.New("link-state advertisement too large")
	}
	var lsa LSA
	if err := json.Unmarshal(raw, &lsa); err != nil {
		return err
	}
	e.stats.Received.Add(1)
	e.mu.Lock()
	n := e.networks[networkID]
	if n == nil || lsa.Network != networkID || !n.neighbors[peer] || !n.known(lsa.Origin) {
		e.mu.Unlock()
		e.stats.Rejected.Add(1)
		return errors.New("link-state advertisement for an unknown network or node")
	}
	if lsa.Origin == n.config.Self.ID {
		// Our own advertisement from before a restart: continue above it.
		if lsa.Sequence >= n.sequence {
			n.sequence = lsa.Sequence
			n.dirty = true
		}
		e.mu.Unlock()
		return nil
	}
	if old, ok := n.db[lsa.Origin]; ok && old.lsa.Sequence >= lsa.Sequence {
		e.mu.Unlock()
		e.stats.Duplicate.Add(1)
		return nil
	}
	up := map[model.ID]bool{}
	for _, id := range lsa.Up {
		up[id] = true
	}
	n.db[lsa.Origin] = entry{lsa: lsa, up: up, arrived: e.cb.Now()}
	e.eventLocked("received", networkID, lsa.Origin, lsa.Sequence)
	e.scheduleSPFLocked()
	targets := n.floodTargets(peer)
	e.mu.Unlock()
	for _, t := range targets {
		e.stats.Sent.Add(1)
		e.cb.Send(networkID, t, raw)
	}
	return nil
}

func (n *network) known(node model.ID) bool {
	if node == n.config.Self.ID {
		return true
	}
	for _, d := range n.config.Directory {
		if d.NodeID == node {
			return true
		}
	}
	return false
}

func (n *network) floodTargets(except model.ID) []model.ID {
	var out []model.ID
	for p := range n.neighbors {
		if p != except {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out
}

// Run polls local link state, originates, ages out and recomputes routes
// until ctx ends.
func (e *Engine) Run(ctx context.Context) {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.Step()
		}
	}
}

// Step performs one round of the engine's periodic work.
func (e *Engine) Step() {
	local := e.cb.Local()
	now := e.cb.Now()
	type send struct {
		network model.ID
		peers   []model.ID
		raw     []byte
	}
	var sends []send
	var update *model.RouteUpdate
	e.mu.Lock()
	for id, n := range e.networks {
		if !maps(n.local, local[id]) {
			n.local = copyMap(local[id])
			n.dirty = true
		}
		for origin, en := range n.db {
			if now.Sub(en.arrived) > MaxAge {
				delete(n.db, origin)
				e.stats.Expired.Add(1)
				e.eventLocked("expired", id, origin, en.lsa.Sequence)
				e.scheduleSPFLocked()
			}
		}
		if (n.dirty && now.Sub(n.sent) >= MinOriginateInterval) || now.Sub(n.sent) >= RefreshInterval {
			lsa := n.originate(e.snapshot.Revision, now)
			if raw, err := json.Marshal(lsa); err == nil {
				sends = append(sends, send{id, n.floodTargets(""), raw})
			}
			e.eventLocked("originated", id, lsa.Origin, lsa.Sequence)
			e.scheduleSPFLocked()
		}
	}
	if !e.spfAt.IsZero() && !now.Before(e.spfAt) {
		e.spfAt = time.Time{}
		update = e.spfLocked()
	}
	e.mu.Unlock()
	for _, s := range sends {
		for _, p := range s.peers {
			e.stats.Sent.Add(1)
			e.cb.Send(s.network, p, s.raw)
		}
	}
	if update != nil {
		start := e.cb.Now()
		err := e.cb.Apply(*update)
		e.mu.Lock()
		e.stats.SPFRuns.Add(1)
		if err == nil {
			e.applied = update.Hash()
			e.eventLocked("routes", "", "", uint64(e.cb.Now().Sub(start).Microseconds()))
		} else {
			e.stats.ApplyErrors.Add(1)
		}
		e.mu.Unlock()
	}
}

func (n *network) originate(revision uint64, now time.Time) LSA {
	n.sequence = max(n.sequence+1, uint64(now.UnixNano()))
	n.sent, n.dirty = now, false
	up := []model.ID{}
	for id, ok := range n.local {
		if ok {
			up = append(up, id)
		}
	}
	slices.Sort(up)
	return LSA{Network: n.config.ID, Origin: n.config.Self.ID, Revision: revision, Sequence: n.sequence, Up: up}
}

func (e *Engine) scheduleSPFLocked() {
	if e.spfAt.IsZero() {
		e.spfAt = e.cb.Now().Add(SPFDelay)
	}
}

// spfLocked returns the new forwarding tables, or nil when unchanged.
func (e *Engine) spfLocked() *model.RouteUpdate {
	if e.snapshot == nil {
		return nil
	}
	update := model.RouteUpdate{Revision: e.snapshot.Revision, Networks: []model.NetworkRoutes{}}
	for _, c := range e.snapshot.Networks {
		n := e.networks[c.ID]
		update.Networks = append(update.Networks, model.NetworkRoutes{ID: c.ID, Routes: routing.LocalRoutes(c, n.usable)})
	}
	if update.Hash() == e.applied {
		return nil
	}
	return &update
}

// usable applies the two-way check. An endpoint that has not advertised
// (an Agent without link-state, or a WireGuard leaf) defers to the other end;
// with no report from either end the edge keeps its configured state.
func (n *network) usable(edge model.TopologyEdge) bool {
	report := func(node model.ID) (known, up bool) {
		if node == n.config.Self.ID {
			return true, n.local[edge.ID]
		}
		en, ok := n.db[node]
		return ok, ok && en.up[edge.ID]
	}
	aKnown, aUp := report(edge.A)
	bKnown, bUp := report(edge.B)
	switch {
	case aKnown && bKnown:
		return aUp && bUp
	case aKnown:
		return aUp
	case bKnown:
		return bUp
	default:
		return true
	}
}

func maps(a, b map[model.ID]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func copyMap(m map[model.ID]bool) map[model.ID]bool {
	out := map[model.ID]bool{}
	for k, v := range m {
		out[k] = v
	}
	return out
}
