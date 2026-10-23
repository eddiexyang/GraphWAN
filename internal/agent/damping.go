package agent

import (
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/linkstate"
	"github.com/eWloYW8/GraphWAN/internal/model"
)

// Edge damping keeps a flapping edge out of link-state. After an edge has
// gone down, it must stay up for a hold time before it is reported up again.
// The hold doubles with every further failure, including one during the hold,
// and resets once the edge has been reported up for dampStable. The first up
// after the Agent starts is not held, so a restart does not cost a hold.
const (
	dampHold   = 30 * time.Second
	dampMax    = 10 * time.Minute
	dampStable = 10 * time.Minute
)

type dampKey struct{ network, edge model.ID }

type dampEdge struct {
	reported  bool      // currently reported up to link-state
	seen      bool      // reported up at least once since start
	upSince   time.Time // raw up since; zero while raw down
	reportAt  time.Time // when reporting began
	downAt    time.Time // last reported or raw failure
	failures  int
	hold      time.Duration
	announced bool // the current hold has been logged
}

type edgeDamper struct {
	mu    sync.Mutex
	edges map[dampKey]*dampEdge
}

func newEdgeDamper() *edgeDamper { return &edgeDamper{edges: map[dampKey]*dampEdge{}} }

func holdFor(failures int) time.Duration {
	hold := dampHold
	for i := 1; i < failures && hold < dampMax; i++ {
		hold *= 2
	}
	return min(hold, dampMax)
}

// filter returns the edges to report up, given the edges with a healthy Link.
func (d *edgeDamper) filter(raw map[model.ID]map[model.ID]bool, now time.Time) map[model.ID]map[model.ID]bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for network, edges := range raw {
		for edge, up := range edges {
			if up && d.edges[dampKey{network, edge}] == nil {
				d.edges[dampKey{network, edge}] = &dampEdge{}
			}
		}
	}
	out := map[model.ID]map[model.ID]bool{}
	for key, e := range d.edges {
		if raw[key.network][key.edge] {
			if e.upSince.IsZero() {
				e.upSince = now
			}
			if !e.reported && (!e.seen || now.Sub(e.upSince) >= e.hold) {
				if e.seen {
					slog.Info("edge released", "network", key.network, "edge", key.edge, "hold", e.hold.String(), "failures", e.failures)
				}
				e.reported, e.seen, e.reportAt, e.announced = true, true, now, false
			}
			if e.reported && e.failures > 0 && now.Sub(e.reportAt) >= dampStable {
				e.failures, e.hold = 0, 0
			}
			if e.reported {
				if out[key.network] == nil {
					out[key.network] = map[model.ID]bool{}
				}
				out[key.network][key.edge] = true
			} else if !e.announced {
				slog.Info("edge held down", "network", key.network, "edge", key.edge, "hold", e.hold.String(), "failures", e.failures)
				e.announced = true
			}
			continue
		}
		// Raw down: a failure if the edge was reported up or was being held.
		if e.reported || !e.upSince.IsZero() && e.seen {
			e.failures++
			e.hold = holdFor(e.failures)
			e.downAt, e.announced = now, false
		}
		e.reported, e.upSince = false, time.Time{}
		if !e.seen || e.failures == 0 || now.Sub(e.downAt) >= dampStable+e.hold {
			delete(d.edges, key) // forget edges that are gone or long quiet
		}
	}
	return out
}

// held lists edges with a healthy Link that are not yet reported up.
func (d *edgeDamper) held(now time.Time) []linkstate.HeldEdge {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []linkstate.HeldEdge
	for key, e := range d.edges {
		if e.reported || e.upSince.IsZero() {
			continue
		}
		out = append(out, linkstate.HeldEdge{Network: key.network, Edge: key.edge, Failures: e.failures, RemainingMS: max(0, (e.hold - now.Sub(e.upSince)).Milliseconds())})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Network != out[j].Network {
			return out[i].Network < out[j].Network
		}
		return out[i].Edge < out[j].Edge
	})
	return out
}
