package mesh

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/link"
	"github.com/eWloYW8/GraphWAN/internal/model"
)

// A transport change keeps the healthy Link it disallows until an allowed
// Link is healthy or drainLimit passes; disabling the edge closes it at once.
func TestTransportChangeDrains(t *testing.T) {
	id := func(n int) model.ID { return model.ID(fmt.Sprintf("%032x", n)) }
	for _, tc := range []struct {
		name     string
		enabled  bool
		replace  bool
		wantKept bool
	}{
		{"replaced", true, true, true},
		{"limit", true, false, true},
		{"disabled", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var dropped atomic.Bool
				var all []*link.Link
				defer func() {
					for _, l := range all {
						l.Close()
					}
				}()
				// pair returns the local end of a healthy in-memory Link.
				pair := func(n int, transport model.Transport) *link.Link {
					channels := [2]*memoryChannel{}
					for i := range channels {
						cctx, stop := context.WithCancel(ctx)
						channels[i] = &memoryChannel{id: fmt.Sprintf("%064x", n), local: &net.UDPAddr{IP: net.IPv4zero, Port: 24752}, remote: &net.UDPAddr{IP: net.IPv4(192, 0, 2, byte(i+1)), Port: 24752}, created: time.Now(), ctx: cctx, cancel: stop, in: make(chan []byte, 256), dropACK: &dropped}
					}
					channels[0].peer, channels[1].peer = channels[1], channels[0]
					var local *link.Link
					for i, c := range channels {
						l, err := link.New(ctx, c, link.Info{NetworkID: id(3), EdgeID: id(4), PeerID: id(2 - i), CandidateID: string(id(100 + n)), Transport: transport}, link.Options{Heartbeat: 100 * time.Millisecond, Timeout: 500 * time.Millisecond})
						if err != nil {
							t.Fatal(err)
						}
						all = append(all, l)
						if i == 0 {
							local = l
						}
					}
					time.Sleep(300 * time.Millisecond)
					synctest.Wait()
					if !local.Healthy() {
						t.Fatal("link not healthy")
					}
					return local
				}
				peer := model.Peer{Node: model.Node{ID: id(2)}, Edge: model.Edge{ID: id(4), Enabled: true, Transports: []model.Transport{model.TCP}}}
				g := &group{ctx: ctx, links: map[string]*link.Link{}, linkCandidates: map[string]link.Candidate{}, attempts: map[string]*attempt{}, suppressed: map[string]string{}, retiring: map[string]*retirement{}, keepers: map[link.Path]string{}, draining: map[string]time.Time{}}
				g.policy.Store(&policy{self: id(1), peer: peer})
				g.edge = link.NewCoordinatedEdge(id(1), id(2), "")
				old := pair(1, model.TCP)
				g.links[old.ID()] = old
				g.linkCandidates[old.ID()] = link.Candidate{ID: string(id(101)), Endpoint: model.Endpoint{Transport: model.TCP}}
				g.edge.Add(old)

				peer.Edge.Enabled, peer.Edge.Transports = tc.enabled, []model.Transport{model.UDP}
				for _, l := range g.updatePolicy(&policy{self: id(1), peer: peer}) {
					l.Close()
				}
				if kept := g.links[old.ID()] != nil; kept != tc.wantKept {
					t.Fatalf("old link kept = %v, want %v", kept, tc.wantKept)
				}
				if !tc.wantKept {
					return
				}
				// Repeated configurations do not extend the limit.
				deadline := g.draining[old.ID()]
				time.Sleep(time.Second)
				g.updatePolicy(&policy{self: id(1), peer: peer})
				if g.draining[old.ID()] != deadline {
					t.Fatal("drain deadline moved")
				}
				g.drain()
				if g.links[old.ID()] == nil {
					t.Fatal("old link closed before a replacement")
				}
				if tc.replace {
					replacement := pair(2, model.UDP)
					g.links[replacement.ID()] = replacement
					g.edge.Add(replacement)
				} else {
					time.Sleep(drainLimit)
				}
				g.drain()
				if g.links[old.ID()] != nil || len(g.draining) != 0 {
					t.Fatal("old link not closed")
				}
				select {
				case <-old.Done():
				case <-time.After(time.Second):
					t.Fatal("old link still running")
				}
			})
		})
	}
}
