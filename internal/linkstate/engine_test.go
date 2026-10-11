package linkstate

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/routing"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
)

type message struct {
	network, from, to model.ID
	raw               []byte
}

// lab runs one engine per Agent of the test topology over an in-memory,
// lossless network with a shared fake clock.
type lab struct {
	t       *testing.T
	state   model.State
	now     time.Time
	engines map[model.ID]*Engine // node ID -> engine
	routes  map[model.ID]model.RouteUpdate
	down    map[model.ID]bool // edge ID -> failed
	queue   []message
	legacyD bool
	// apply, when set, can fail route installs before they reach the table.
	apply     func(node model.ID, u model.RouteUpdate) error
	snapshots map[model.ID]model.Snapshot
}

// configure installs a configuration and its routes as the Agent does.
func (l *lab) configure(node model.ID, e *Engine, s model.Snapshot) {
	if u := e.Configure(s); u != nil {
		err := e.cb.Apply(*u)
		e.Applied(*u, err, 0)
	}
}

func newLab(t *testing.T, without ...model.ID) *lab {
	l := &lab{t: t, state: testutil.Topology(), now: time.Unix(1_800_000_000, 0), engines: map[model.ID]*Engine{}, routes: map[model.ID]model.RouteUpdate{}, down: map[model.ID]bool{}, snapshots: map[model.ID]model.Snapshot{}}
	skip := map[model.ID]bool{}
	for _, id := range without {
		skip[id] = true
	}
	for _, node := range l.state.Networks[0].Nodes {
		if !skip[node.ID] {
			l.start(node)
		}
	}
	return l
}

func (l *lab) start(node model.Node) {
	snapshot, err := routing.Compile(l.state, node.AgentID)
	if err != nil {
		l.t.Fatal(err)
	}
	self := node.ID
	var e *Engine
	e = New(Callbacks{
		Now: func() time.Time { return l.now },
		Send: func(network, peer model.ID, raw []byte) {
			l.queue = append(l.queue, message{network, self, peer, append([]byte(nil), raw...)})
		},
		Local: func() map[model.ID]map[model.ID]bool {
			up := map[model.ID]bool{}
			for _, p := range snapshot.Networks[0].Peers {
				// A link is healthy only if both Agents run and the edge works.
				if _, running := l.engines[p.Node.ID]; !l.down[p.Edge.ID] && (running || l.legacy(p.Node.ID)) {
					up[p.Edge.ID] = true
				}
			}
			return map[model.ID]map[model.ID]bool{snapshot.Networks[0].ID: up}
		},
		Apply: func(u model.RouteUpdate) error {
			if l.apply != nil {
				if err := l.apply(self, u); err != nil {
					return err
				}
			}
			if _, err := u.Apply(*e.snapshot); err != nil {
				return err
			}
			l.routes[self] = u
			return nil
		},
	})
	l.snapshots[self] = snapshot
	l.configure(self, e, snapshot)
	l.engines[self] = e
	for _, p := range snapshot.Networks[0].Peers {
		e.PeerReady(snapshot.Networks[0].ID, p.Node.ID)
		if other := l.engines[p.Node.ID]; other != nil {
			other.PeerReady(snapshot.Networks[0].ID, self)
		}
	}
}

// legacy marks nodes deliberately run without the engine but still forwarding.
func (l *lab) legacy(node model.ID) bool { return node == testutil.ID(23) && l.legacyD }

// run advances the clock in engine ticks, delivering messages, until quiet.
func (l *lab) run(d time.Duration) {
	for end := l.now.Add(d); l.now.Before(end); l.now = l.now.Add(tick) {
		for _, e := range l.engines {
			e.Step()
		}
		for len(l.queue) > 0 {
			m := l.queue[0]
			l.queue = l.queue[1:]
			if dst := l.engines[m.to]; dst != nil && !l.down[l.edge(m.from, m.to)] {
				dst.Receive(m.network, m.from, m.raw)
			}
		}
	}
}

func (l *lab) edge(a, b model.ID) model.ID {
	for _, e := range l.state.Networks[0].Edges {
		if e.A == a && e.B == b || e.A == b && e.B == a {
			return e.ID
		}
	}
	return ""
}

func (l *lab) route(from, to model.ID) model.Route {
	for _, r := range l.routes[from].Networks[0].Routes {
		if r.Destination == to {
			return r
		}
	}
	return model.Route{}
}

var (
	nodeA, nodeB, nodeC, nodeD = testutil.ID(20), testutil.ID(21), testutil.ID(22), testutil.ID(23)
	edgeAB                     = testutil.ID(40)
)

func TestConvergesToCompiledRoutes(t *testing.T) {
	l := newLab(t)
	l.run(time.Second)
	for node, e := range l.engines {
		snapshot := e.snapshot
		if !reflect.DeepEqual(l.routes[node].Networks[0].Routes, snapshot.Networks[0].Routes) {
			t.Fatalf("%s: %v, compiled %v", node, l.routes[node].Networks[0].Routes, snapshot.Networks[0].Routes)
		}
	}
}

func TestLinkFailureReroutesWithoutController(t *testing.T) {
	l := newLab(t)
	l.run(time.Second)
	if r := l.route(nodeA, nodeC); r.NextHop != nodeB {
		t.Fatalf("initial A->C %+v", r)
	}
	l.down[edgeAB] = true
	l.run(time.Second)
	if r := l.route(nodeA, nodeC); r.NextHop != nodeD || r.Cost != 31 {
		t.Fatalf("A->C after A-B failure %+v", r)
	}
	// B learns it as well, through C.
	if r := l.route(nodeB, nodeA); r.NextHop != nodeC {
		t.Fatalf("B->A after A-B failure %+v", r)
	}
	delete(l.down, edgeAB)
	l.run(time.Second)
	if r := l.route(nodeA, nodeC); r.NextHop != nodeB {
		t.Fatalf("A->C after recovery %+v", r)
	}
}

func TestEndpointWithoutLinkStateDefersToNeighbour(t *testing.T) {
	l := newLab(t, nodeD)
	l.legacyD = true
	l.run(time.Second)
	if r := l.route(nodeA, nodeD); r.NextHop != nodeD {
		t.Fatalf("A->D through a legacy D %+v", r)
	}
	l.down[testutil.ID(42)] = true // A-D
	l.run(time.Second)
	if r := l.route(nodeA, nodeD); r.NextHop != nodeB {
		t.Fatalf("A->D after A-D failure reported by A alone %+v", r)
	}
}

func TestSilentOriginExpires(t *testing.T) {
	l := newLab(t)
	l.run(time.Second)
	delete(l.engines, nodeC) // C stops: no refresh, links to it fail
	l.run(time.Second)
	if _, ok := l.route(nodeA, nodeC), true; !ok {
		t.Fatal()
	}
	view := l.engines[nodeA].View()
	if !hasOrigin(view, nodeC) {
		t.Fatal("C's LSA vanished before MaxAge")
	}
	l.run(MaxAge + time.Second)
	if hasOrigin(l.engines[nodeA].View(), nodeC) {
		t.Fatal("C's LSA did not expire")
	}
	if r := l.route(nodeA, nodeC); r.NextHop != "" {
		t.Fatalf("route to a failed node %+v", r)
	}
}

func TestRestartContinuesAboveOwnSequence(t *testing.T) {
	l := newLab(t)
	l.run(time.Second)
	before := l.engines[nodeA].View().Networks[0].Sequence
	l.now = l.now.Add(-time.Hour) // a restarted Agent with a clock behind
	delete(l.engines, nodeA)
	l.start(l.state.Networks[0].Nodes[0])
	l.run(time.Second)
	after := l.engines[nodeB].View()
	for _, o := range after.Networks[0].Database {
		if o.Origin == nodeA && o.Sequence <= before {
			t.Fatalf("B still holds A's pre-restart sequence %d <= %d", o.Sequence, before)
		}
	}
}

// An origin's current advertisement can return through the flood when a
// neighbour receives it first along a longer path; the echo must not trigger
// another origination, or every origin re-advertises on each tick.
func TestOwnAdvertisementEchoIsIgnored(t *testing.T) {
	l := newLab(t)
	l.run(time.Second)
	a := l.engines[nodeA]
	network := l.state.Networks[0].ID
	var echo []byte
	for _, o := range l.engines[nodeB].View().Networks[0].Database {
		if o.Origin == nodeA {
			echo, _ = json.Marshal(LSA{Network: network, Origin: nodeA, Revision: o.Revision, Sequence: o.Sequence, Up: o.Up})
		}
	}
	before := a.View().Networks[0].Sequence
	if err := a.Receive(network, nodeB, echo); err != nil {
		t.Fatal(err)
	}
	l.run(time.Second)
	if after := a.View().Networks[0].Sequence; after != before {
		t.Fatalf("echo of the current advertisement re-originated it: %d -> %d", before, after)
	}
}

// A new revision that leaves the topology alone gets routes for that revision
// at once but is not advertised again.
func TestRevisionWithoutTopologyChangeIsNotAdvertised(t *testing.T) {
	l := newLab(t)
	l.run(time.Second)
	a := l.engines[nodeA]
	before := a.View().Networks[0].Sequence
	next := l.snapshots[nodeA]
	next.Revision++
	l.configure(nodeA, a, next)
	if got := l.routes[nodeA].Revision; got != next.Revision {
		t.Fatalf("routes for revision %d after configuring %d", got, next.Revision)
	}
	l.run(time.Second)
	if after := a.View().Networks[0].Sequence; after != before {
		t.Fatalf("unchanged topology re-advertised: %d -> %d", before, after)
	}
}

// Routes computed for a configuration that was replaced before they were
// installed are superseded, not failures; a real failure is retried.
func TestSupersededAndFailedRouteInstalls(t *testing.T) {
	l := newLab(t)
	l.run(time.Second)
	a := l.engines[nodeA]
	// While A's routes for the failed edge wait to be installed, the Agent
	// applies a newer configuration with its own routes, then rejects them.
	next := l.snapshots[nodeA]
	next.Revision++
	l.apply = func(node model.ID, u model.RouteUpdate) error {
		if node == nodeA && u.Revision < next.Revision {
			l.apply = nil
			l.snapshots[nodeA] = next
			l.configure(nodeA, a, next)
			return ErrSuperseded
		}
		return nil
	}
	l.down[edgeAB] = true
	l.run(time.Second)
	c := a.View().Counters
	if c["routes_superseded"] != 1 || c["route_apply_errors"] != 0 {
		t.Fatalf("counters %v", c)
	}
	if r := l.route(nodeA, nodeC); r.NextHop != nodeD || l.routes[nodeA].Revision != next.Revision {
		t.Fatalf("A->C %+v at revision %d", r, l.routes[nodeA].Revision)
	}
	failures := 1
	l.apply = func(node model.ID, u model.RouteUpdate) error {
		if node == nodeA && failures > 0 {
			failures--
			return errors.New("router busy")
		}
		return nil
	}
	delete(l.down, edgeAB)
	l.run(time.Second)
	if c := a.View().Counters; c["route_apply_errors"] != 1 {
		t.Fatalf("counters %v", c)
	}
	if r := l.route(nodeA, nodeC); r.NextHop != nodeB {
		t.Fatalf("failed install was not retried: A->C %+v", r)
	}
	var kinds []string
	for _, ev := range a.View().Events {
		if ev.Edge == edgeAB {
			kinds = append(kinds, ev.Kind)
		}
	}
	// The first edge-up is the Link coming up at start.
	if !slices.Equal(kinds, []string{"edge-up", "edge-down", "edge-up"}) {
		t.Fatalf("A-B edge events %v", kinds)
	}
}

// Until local Links have been polled, a configuration keeps its compiled
// routes: link-state would otherwise report every local edge down.
func TestFirstConfigurationKeepsCompiledRoutesUntilObserved(t *testing.T) {
	state := testutil.Topology()
	snapshot, err := routing.Compile(state, state.Agents[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	e := New(Callbacks{
		Send:  func(model.ID, model.ID, []byte) {},
		Local: func() map[model.ID]map[model.ID]bool { return nil },
		Apply: func(model.RouteUpdate) error { return nil },
	})
	if u := e.Configure(snapshot); u != nil {
		t.Fatalf("routes before observing local Links: %+v", u)
	}
	e.Step()
	snapshot.Revision++
	if u := e.Configure(snapshot); u == nil || u.Revision != snapshot.Revision {
		t.Fatalf("routes for an observed configuration: %+v", u)
	}
}

func hasOrigin(v View, origin model.ID) bool {
	for _, o := range v.Networks[0].Database {
		if o.Origin == origin {
			return true
		}
	}
	return false
}
