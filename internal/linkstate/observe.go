package linkstate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sync/atomic"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/routing"
)

const maxEvents = 512

type Stats struct {
	Sent, Received, Duplicate, Rejected, Expired, SPFRuns, Superseded, ApplyErrors atomic.Uint64
}

// Event records changes for diagnosis: local edge-up/edge-down, advertisements
// whose edge set changed (originated, received), expiry, and route installs.
// Value is the sequence for LSA events, the apply duration in microseconds for
// routes and the revision for route-error.
type Event struct {
	At      time.Time `json:"at"`
	Kind    string    `json:"kind"`
	Network model.ID  `json:"network,omitempty"`
	Origin  model.ID  `json:"origin,omitempty"`
	Edge    model.ID  `json:"edge,omitempty"`
	Value   uint64    `json:"value"`
}

func (e *Engine) eventLocked(kind string, network, origin, edge model.ID, value uint64) {
	if len(e.events) == maxEvents {
		copy(e.events, e.events[1:])
		e.events = e.events[:maxEvents-1]
	}
	e.events = append(e.events, Event{At: e.cb.Now(), Kind: kind, Network: network, Origin: origin, Edge: edge, Value: value})
}

type View struct {
	Revision uint64            `json:"revision"`
	Networks []NetworkView     `json:"networks"`
	Counters map[string]uint64 `json:"counters"`
	Events   []Event           `json:"events"`
}

type NetworkView struct {
	ID       model.ID      `json:"id"`
	Self     model.ID      `json:"self"`
	Sequence uint64        `json:"sequence"`
	Local    []model.ID    `json:"local_up"`
	Database []OriginView  `json:"database"`
	Edges    []EdgeView    `json:"edges"`
	Routes   []model.Route `json:"routes"`
}

type OriginView struct {
	Origin   model.ID   `json:"origin"`
	Sequence uint64     `json:"sequence"`
	Revision uint64     `json:"revision"`
	AgeMS    int64      `json:"age_ms"`
	Up       []model.ID `json:"up"`
}

// EdgeView shows each end's report ("up", "down" or "none") and the outcome
// of the two-way check.
type EdgeView struct {
	ID      model.ID `json:"id"`
	A       model.ID `json:"a"`
	B       model.ID `json:"b"`
	ReportA string   `json:"report_a"`
	ReportB string   `json:"report_b"`
	Usable  bool     `json:"usable"`
}

// View returns the engine's state for the local status command and metrics.
func (e *Engine) View() View {
	e.mu.Lock()
	defer e.mu.Unlock()
	v := View{Counters: e.counters(), Events: slices.Clone(e.events)}
	if e.snapshot == nil {
		return v
	}
	v.Revision = e.snapshot.Revision
	now := e.cb.Now()
	for _, c := range e.snapshot.Networks {
		n := e.networks[c.ID]
		nv := NetworkView{ID: c.ID, Self: c.Self.ID, Sequence: n.sequence, Local: []model.ID{}, Database: []OriginView{}, Edges: []EdgeView{}}
		for id, ok := range n.local {
			if ok {
				nv.Local = append(nv.Local, id)
			}
		}
		slices.Sort(nv.Local)
		for origin, en := range n.db {
			nv.Database = append(nv.Database, OriginView{Origin: origin, Sequence: en.lsa.Sequence, Revision: en.lsa.Revision, AgeMS: now.Sub(en.arrived).Milliseconds(), Up: en.lsa.Up})
		}
		slices.SortFunc(nv.Database, func(a, b OriginView) int { return compare(a.Origin, b.Origin) })
		for _, edge := range c.Topology {
			nv.Edges = append(nv.Edges, EdgeView{ID: edge.ID, A: edge.A, B: edge.B, ReportA: n.reportString(edge.A, edge.ID), ReportB: n.reportString(edge.B, edge.ID), Usable: n.usable(edge)})
		}
		nv.Routes = routing.LocalRoutes(c, n.usable)
		v.Networks = append(v.Networks, nv)
	}
	return v
}

func (n *network) reportString(node, edge model.ID) string {
	if node == n.config.Self.ID {
		if n.local[edge] {
			return "up"
		}
		return "down"
	}
	en, ok := n.db[node]
	switch {
	case !ok:
		return "none"
	case en.up[edge]:
		return "up"
	default:
		return "down"
	}
}

func (e *Engine) counters() map[string]uint64 {
	return map[string]uint64{
		"lsa_sent": e.stats.Sent.Load(), "lsa_received": e.stats.Received.Load(),
		"lsa_duplicate": e.stats.Duplicate.Load(), "lsa_rejected": e.stats.Rejected.Load(),
		"lsa_expired": e.stats.Expired.Load(), "spf_runs": e.stats.SPFRuns.Load(),
		"routes_superseded": e.stats.Superseded.Load(), "route_apply_errors": e.stats.ApplyErrors.Load(),
	}
}

// Report summarises the database and routes for the controller.
func (e *Engine) Report() model.LinkStateReport {
	v := e.View()
	r := model.LinkStateReport{Revision: v.Revision, Origins: map[model.ID]map[model.ID]uint64{}, Counters: v.Counters}
	routes := map[model.ID][]model.Route{}
	for _, n := range v.Networks {
		r.Origins[n.ID] = map[model.ID]uint64{n.Self: n.Sequence}
		for _, o := range n.Database {
			r.Origins[n.ID][o.Origin] = o.Sequence
		}
		routes[n.ID] = n.Routes
	}
	raw, _ := json.Marshal(routes)
	sum := sha256.Sum256(raw)
	r.RouteHash = hex.EncodeToString(sum[:8])
	return r
}

func compare(a, b model.ID) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
