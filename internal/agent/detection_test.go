package agent

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/routing"
)

// nextHopToC is Agent A's next hop toward C.
func nextHopToC(agent *DataPlane, state model.State) model.ID {
	next, _, err := agent.state.Load().router.NextHop(state.Networks[0].ID, state.Networks[0].Nodes[2].Address)
	if err != nil {
		return ""
	}
	return next
}

// failover stops B, which carries A's traffic to C, without a word to its
// peers, and returns how long A takes to route to C through D instead.
func failover(t *testing.T, detection uint32, limit time.Duration) (time.Duration, bool) {
	t.Helper()
	agents, _, state := graphAgents(t, model.UDP, streamOptions{}, 4, 4, func(s *model.State) {
		s.Networks[0].FailureDetection = detection
	})
	b, d := state.Networks[0].Nodes[1].ID, state.Networks[0].Nodes[3].ID
	waitFor(t, 10*time.Second, "a route to C through B", func() bool { return nextHopToC(agents[0], state) == b })
	start := time.Now()
	agents[1].Close()
	for time.Since(start) < limit {
		if nextHopToC(agents[0], state) == d {
			return time.Since(start), true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return time.Since(start), false
}

// A Network's failure detection time bounds how long traffic keeps going to
// a silent neighbor: the timeout after the first unanswered heartbeat, which
// follows the last answer within one heartbeat.
func TestFailureDetectionTime(t *testing.T) {
	elapsed, moved := failover(t, 750, 3*time.Second)
	t.Logf("750 ms: rerouted after %v", elapsed.Round(time.Millisecond))
	if !moved || elapsed > 1500*time.Millisecond {
		t.Fatalf("750 ms: rerouted %v after %v", moved, elapsed)
	}
	elapsed, moved = failover(t, 0, 10*time.Second)
	t.Logf("default: rerouted after %v", elapsed.Round(time.Millisecond))
	if !moved || elapsed < 6*time.Second || elapsed > 9*time.Second {
		t.Fatalf("default: rerouted %v after %v", moved, elapsed)
	}
	if elapsed, moved = failover(t, 60_000, 3*time.Second); moved {
		t.Fatalf("60 s: rerouted after %v", elapsed)
	}
}

// countingRelay forwards UDP to target and counts the bytes in both
// directions, so a test sees everything two Agents exchange.
type countingRelay struct {
	listener *net.UDPConn
	target   *net.UDPAddr
	bytes    atomic.Uint64
	mu       sync.Mutex
	upstream map[string]*net.UDPConn
}

func newCountingRelay(t *testing.T, target int) *countingRelay {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r := &countingRelay{listener: listener, target: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: target}, upstream: map[string]*net.UDPConn{}}
	t.Cleanup(func() {
		listener.Close()
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, conn := range r.upstream {
			conn.Close()
		}
	})
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := listener.ReadFromUDP(buf)
			if err != nil {
				return
			}
			r.bytes.Add(uint64(n))
			r.mu.Lock()
			conn := r.upstream[from.String()]
			if conn == nil {
				if conn, err = net.DialUDP("udp4", nil, r.target); err != nil {
					r.mu.Unlock()
					continue
				}
				r.upstream[from.String()] = conn
				go func() {
					back := make([]byte, 65536)
					for {
						n, err := conn.Read(back)
						if err != nil {
							return
						}
						r.bytes.Add(uint64(n))
						listener.WriteToUDP(back[:n], from)
					}
				}()
			}
			r.mu.Unlock()
			conn.Write(buf[:n])
		}
	}()
	return r
}

func (r *countingRelay) port() int { return r.listener.LocalAddr().(*net.UDPAddr).Port }

// idleBytes measures what two idle Agents on one UDP Edge exchange per second.
// Only B dials, through a relay in front of A, so the Edge has one Link.
func idleBytes(t *testing.T, detection uint32) float64 {
	t.Helper()
	var relays []*countingRelay
	agents, _, _ := graphAgents(t, model.UDP, streamOptions{}, 2, 1, func(s *model.State) {
		s.Networks[0].FailureDetection = detection
		relay := newCountingRelay(t, int(s.Agents[0].ListenPort))
		relays = append(relays, relay)
		s.Agents[0].Endpoints[0].URL = fmt.Sprintf("udp://127.0.0.1:%d", relay.port())
		s.Agents[1].Endpoints = []model.Endpoint{}
	})
	waitFor(t, 10*time.Second, "a healthy Link", func() bool {
		for _, l := range agents[0].Report() {
			if l.Healthy {
				return true
			}
		}
		return false
	})
	time.Sleep(3 * time.Second) // let Link setup and selection finish
	var before uint64
	for _, r := range relays {
		before += r.bytes.Load()
	}
	const window = 10 * time.Second
	time.Sleep(window)
	var after uint64
	for _, r := range relays {
		after += r.bytes.Load()
	}
	return float64(after-before) / window.Seconds()
}

// Heartbeats every third of the detection time; the test reports the bytes
// an idle Edge carries in UDP payloads.
func TestFailureDetectionHeartbeatBytes(t *testing.T) {
	fast, slow := idleBytes(t, 750), idleBytes(t, 0)
	t.Logf("idle UDP payload bytes per second on one Edge: 750 ms %.0f, default %.0f", fast, slow)
	if fast <= slow {
		t.Fatalf("a shorter detection time did not send more heartbeats: %.0f <= %.0f", fast, slow)
	}
}

// An acceptor allows three of the dialer's heartbeats, so Agents whose
// Networks have different detection times keep their Links up. B has no
// endpoint, so its only Link is B's, at a 2 s heartbeat, to A with 750 ms.
func TestFailureDetectionMixedSettings(t *testing.T) {
	agents, _, state := graphAgents(t, model.UDP, streamOptions{}, 2, 1, func(s *model.State) {
		s.Agents[1].Endpoints = []model.Endpoint{}
	})
	fast := state
	fast.Revision++
	fast.Networks = append([]model.Network(nil), state.Networks...)
	fast.Networks[0].FailureDetection = 750
	snapshot, err := routing.Compile(fast, fast.Agents[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := agents[0].Apply(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	edgeUp := func(agent *DataPlane) bool {
		for _, l := range agent.Report() {
			if l.Healthy {
				return true
			}
		}
		return false
	}
	waitFor(t, 10*time.Second, "healthy Links both ways", func() bool { return edgeUp(agents[0]) && edgeUp(agents[1]) })
	// Duplicate Links may be retired; the Edge itself must never go down.
	for deadline := time.Now().Add(8 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		for i, agent := range agents {
			if !edgeUp(agent) {
				t.Fatalf("agent %d: the Edge went down", i)
			}
		}
	}
}
