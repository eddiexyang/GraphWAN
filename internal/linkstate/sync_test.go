package linkstate

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/packet"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
)

func TestSyncRepairsLostChangeBeforeFullRefresh(t *testing.T) {
	l := newLab(t)
	l.run(time.Second)
	// Lose both endpoints' event advertisements, leaving C with the old A-B
	// adjacency. Digest/inventory reconciliation must repair it in one round.
	for _, id := range []model.ID{nodeA, nodeB} {
		e := l.engines[id]
		send := e.cb.Send
		e.cb.Send = func(network, peer model.ID, raw []byte) {
			var msg syncMessage
			json.Unmarshal(raw, &msg)
			if msg.Kind != "" {
				send(network, peer, raw)
			}
		}
	}
	l.down[edgeAB] = true
	l.run(time.Second)
	for _, id := range []model.ID{nodeA, nodeB} {
		self := id
		l.engines[id].cb.Send = func(network, peer model.ID, raw []byte) {
			l.queue = append(l.queue, message{network, self, peer, append([]byte(nil), raw...)})
		}
	}
	l.run(SyncInterval + time.Second)
	if r := l.route(nodeC, nodeA); r.NextHop != nodeD || r.Cost != 31 {
		t.Fatalf("lost failure was not repaired: %+v", r)
	}
}

func TestSyncDoesNotRenewSilentOrigins(t *testing.T) {
	l := newLab(t)
	l.run(time.Second)
	n := l.engines[nodeA].networks[l.state.Networks[0].ID]
	before := n.db[nodeC].arrived
	// Force anti-entropy to resend C's record from B, then exchange matching
	// digests. Receiving a cached record must preserve its original age.
	delete(n.db, nodeC)
	l.run(SyncInterval + time.Second)
	if got := n.db[nodeC].arrived; !got.Equal(before) {
		t.Fatalf("resync extended lease: %s -> %s", before, got)
	}
	l.run(SyncInterval)
	if got := n.db[nodeC].arrived; !got.Equal(before) {
		t.Fatal("digest renewed an origin")
	}
}

func TestLegacyOriginRetainsShortRefresh(t *testing.T) {
	l := newLab(t)
	l.run(time.Second)
	a := l.engines[nodeA]
	n := a.networks[l.state.Networks[0].ID]
	legacy := n.db[nodeB].lsa
	legacy.Sync = false
	legacy.Sequence++
	raw, _ := json.Marshal(legacy)
	if err := a.Receive(n.config.ID, nodeB, raw); err != nil {
		t.Fatal(err)
	}
	before := n.sequence
	// Keep the injected legacy origin fixed; a running modern B would see
	// the higher reflected sequence and publish its real capability again.
	for end := l.now.Add(LegacyRefreshInterval + time.Second); l.now.Before(end); l.now = l.now.Add(tick) {
		a.Step()
	}
	if n.sequence == before || n.syncReady {
		t.Fatal("legacy peer lost refresh compatibility")
	}
}

func TestSyncInventoryChunks(t *testing.T) {
	now := time.Now()
	n := &network{config: model.NetworkConfig{ID: testutil.ID(1)}, db: map[model.ID]entry{}}
	for i := 0; i < 1000; i++ {
		id := testutil.ID(100 + i)
		n.db[id] = entry{lsa: LSA{Origin: id, Sequence: ^uint64(0), Sync: true}, arrived: now}
	}
	chunks := n.inventory(now, false)
	seen := map[model.ID]bool{}
	var previous model.ID
	for i, raw := range chunks {
		if len(raw)+1 > packet.MaxFrame {
			t.Fatalf("oversized inventory: %d", len(raw))
		}
		var m syncMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		if m.After != previous || (m.Through == "") != (i == len(chunks)-1) {
			t.Fatal("broken inventory ranges")
		}
		for id := range m.Sequences {
			if seen[id] || id <= m.After || m.Through != "" && id > m.Through {
				t.Fatal("duplicate/out-of-range origin")
			}
			seen[id] = true
		}
		previous = m.Through
	}
	if len(seen) != len(n.db) {
		t.Fatal("inventory omitted origins")
	}
}

// This has the observed 13-node/39-edge size and a seven-neighbour node.
// Count both directions, framing, encryption, IP/TCP/Ethernet headers and a
// separate TCP ACK for every message. Heartbeat/other traffic is excluded.
func TestStableThirteenNodeTrafficBudget(t *testing.T) {
	s := model.EmptyState()
	s.Revision = 1
	n := model.Network{ID: testutil.ID(1), Name: "traffic lab", CIDR: netip.MustParsePrefix("10.50.0.0/24"), MTU: model.DefaultMTU, Cipher: model.ChaCha20Poly1305}
	for i := 0; i < 13; i++ {
		seed := make([]byte, 32)
		seed[0] = byte(i + 1)
		s.Agents = append(s.Agents, model.Agent{ID: testutil.ID(100 + i), Name: fmt.Sprint("agent", i), PublicKey: ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), ListenPort: model.DefaultPort})
		n.Nodes = append(n.Nodes, model.Node{ID: testutil.ID(200 + i), AgentID: testutil.ID(100 + i), Name: fmt.Sprint("node", i), Address: netip.MustParseAddr(fmt.Sprintf("10.50.0.%d", i+1))})
		for step := 1; step <= 3; step++ {
			a, b := i, (i+step)%13
			if i == 1 && step == 3 {
				a = 0
			}
			n.Edges = append(n.Edges, model.Edge{ID: testutil.ID(300 + len(n.Edges)), A: testutil.ID(200 + a), B: testutil.ID(200 + b), Enabled: true, Weight: 1, Transports: []model.Transport{model.TCP}, Methods: model.ConnectionMethods{IPv4Direct: true}})
		}
	}
	s.Networks = []model.Network{n}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	l := &lab{t: t, state: s, now: time.Unix(1800000000, 0), engines: map[model.ID]*Engine{}, routes: map[model.ID]model.RouteUpdate{}, down: map[model.ID]bool{}, snapshots: map[model.ID]model.Snapshot{}}
	for _, node := range n.Nodes {
		l.start(node)
	}
	l.run(2 * time.Second)
	bytes := map[model.ID]int{}
	for id, engine := range l.engines {
		self, send := id, engine.cb.Send
		engine.cb.Send = func(network, peer model.ID, raw []byte) {
			cost := len(raw) + 30 + 66 + 66
			bytes[self] += cost
			bytes[peer] += cost
			send(network, peer, raw)
		}
	}
	window := 10 * time.Minute
	l.run(window)
	for node, count := range bytes {
		rate := float64(count) * 8 / window.Seconds()
		t.Logf("node %s: %.0f bit/s LSA+sync incl headers/ACK", node, rate)
		if rate > 8000 {
			t.Fatalf("stable routing overhead exceeds 8 kbit/s: %.0f", rate)
		}
	}
}
