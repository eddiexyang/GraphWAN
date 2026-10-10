package agent

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/routing"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
	"github.com/eWloYW8/GraphWAN/internal/tunnel"
)

// Four Agents in a ring (A-B-C and A-D-C) run without any controller: routes
// converge from advertisements alone, and A reroutes to C when B fails.
func TestLinkStateRoutesWithoutController(t *testing.T) {
	state := testutil.Topology()
	state.Agents = state.Agents[:4]
	state.Networks[0].Nodes = state.Networks[0].Nodes[:4]
	for i := range state.Agents {
		listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := listener.LocalAddr().(*net.UDPAddr).Port
		listener.Close()
		state.Agents[i].ListenPort = uint16(port)
		state.Agents[i].Endpoints = []model.Endpoint{{ID: testutil.ID(30 + i), Transport: model.UDP, Source: model.Manual, URL: fmt.Sprintf("udp://127.0.0.1:%d", port)}}
	}
	for i := range state.Networks[0].Edges {
		state.Networks[0].Edges[i].Transports = []model.Transport{model.UDP}
		state.Networks[0].Edges[i].Methods = model.ConnectionMethods{IPv4Direct: true}
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var agents [4]*DataPlane
	for i := range agents {
		seed := make([]byte, ed25519.SeedSize)
		seed[0] = byte(i + 1)
		agent, err := NewDataPlane(ctx, ed25519.NewKeyFromSeed(seed), DataPlaneOptions{
			BindHost: "127.0.0.1",
			TunnelFactory: func(config tunnel.Config) (tunnel.Device, error) {
				return &packetTestTUN{config: config, in: make(chan []byte, 16), out: make(chan []byte, 16), done: make(chan struct{})}, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		agents[i] = agent
		t.Cleanup(func() { agent.Close() })
		snapshot, err := routing.Compile(state, state.Agents[i].ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := agent.Apply(ctx, snapshot); err != nil {
			t.Fatal(err)
		}
	}
	a, b, c, d := state.Networks[0].Nodes[0].ID, state.Networks[0].Nodes[1].ID, state.Networks[0].Nodes[2].ID, state.Networks[0].Nodes[3].ID
	waitFor(t, 15*time.Second, "A learns B, C and D and routes to C through B", func() bool {
		v := agents[0].LinkState()
		if len(v.Networks) != 1 || len(v.Networks[0].Database) != 3 {
			return false
		}
		r := installedRoute(agents[0], c)
		return r.NextHop == b && r.Cost == 20
	})
	if !agents[0].LocalRouting() {
		t.Fatal("topology-carrying configuration did not enable local routing")
	}
	failed := time.Now()
	agents[1].Close()
	waitFor(t, 20*time.Second, "A reroutes to C through D after B fails", func() bool {
		r := installedRoute(agents[0], c)
		return r.NextHop == d && r.Cost == 31
	})
	t.Logf("rerouted %v after B failed", time.Since(failed).Round(10*time.Millisecond))
	for _, e := range agents[0].LinkState().Networks[0].Edges {
		if e.A == a && e.B == b || e.A == b && e.B == a {
			if e.Usable {
				t.Fatalf("A-B still usable: %+v", e)
			}
		}
	}
}

// installedRoute reads the forwarding table the router actually uses.
func installedRoute(agent *DataPlane, to model.ID) model.Route {
	agent.applyMu.Lock()
	defer agent.applyMu.Unlock()
	if agent.lastRoutes == nil {
		return model.Route{}
	}
	for _, n := range agent.lastRoutes.Networks {
		for _, r := range n.Routes {
			if r.Destination == to {
				return r
			}
		}
	}
	return model.Route{}
}

func waitFor(t *testing.T, timeout time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out: %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
