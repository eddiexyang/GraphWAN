package agent

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
)

// pausingProxy forwards TCP to target; while paused it moves no bytes in
// either direction and keeps every connection open, as a hop whose host
// stopped scheduling the Agent would.
type pausingProxy struct {
	listener net.Listener
	paused   atomic.Bool
	mu       sync.Mutex
	conns    []net.Conn
}

func newPausingProxy(t *testing.T, target string) *pausingProxy {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &pausingProxy{listener: listener}
	t.Cleanup(func() {
		listener.Close()
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, conn := range p.conns {
			conn.Close()
		}
	})
	go func() {
		for {
			in, err := listener.Accept()
			if err != nil {
				return
			}
			out, err := net.Dial("tcp4", target)
			if err != nil {
				in.Close()
				continue
			}
			p.mu.Lock()
			p.conns = append(p.conns, in, out)
			p.mu.Unlock()
			go p.copy(out, in)
			go p.copy(in, out)
		}
	}()
	return p
}

func (p *pausingProxy) copy(dst, src net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		for p.paused.Load() {
			time.Sleep(time.Millisecond)
		}
		n, err := src.Read(buf)
		for p.paused.Load() {
			time.Sleep(time.Millisecond)
		}
		if n > 0 {
			if _, err := dst.Write(buf[:n]); err != nil {
				return
			}
		}
		if err != nil {
			dst.Close()
			return
		}
	}
}

func (p *pausingProxy) port() string { return p.listener.Addr().(*net.TCPAddr).AddrPort().String() }

// A hop that stops moving bytes without closing anything, both ways at once,
// is reset by the ingress within a second of no acknowledgement progress; the
// connection moves to the other path once the stalled Link times out, and no
// byte is lost or changed.
func TestTCPSessionSurvivesStalledHop(t *testing.T) {
	var proxy *pausingProxy
	agents, devices, state := graphAgents(t, model.TCP, streamOptions{}, 4, 4, func(s *model.State) {
		s.Networks[0].FailureDetection = 750
		// Only A dials, and it reaches B through the proxy, so the A-B
		// Link has one path to stall.
		target := strings.TrimPrefix(s.Agents[1].Endpoints[0].URL, "tcp://")
		proxy = newPausingProxy(t, target)
		s.Agents[1].Endpoints[0].URL = "tcp://" + proxy.port()
		s.Agents[0].Endpoints = []model.Endpoint{}
	})
	var resetsBefore uint64
	sessionExchange(t, devices, state, 2, 16<<20, 4<<20, func() {
		waitFor(t, 5*time.Second, "a chain through B", func() bool { return relaying(agents[1]) > 0 })
		resetsBefore = agents[0].Counters()["session_stall_resets"] + agents[0].Counters()["session_rebuilds"]
		proxy.paused.Store(true)
		waitFor(t, 10*time.Second, "the chain to move to D", func() bool { return relaying(agents[3]) > 0 })
	})
	if agents[0].Counters()["session_rebuilds"]+agents[0].Counters()["session_stall_resets"] <= resetsBefore {
		t.Fatal("the stalled hop was neither reset nor rebuilt")
	}
	assertNoTCPOverTCP(t, agents)
}
