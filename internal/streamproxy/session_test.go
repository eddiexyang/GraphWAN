package streamproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
)

// memHalf is one direction of an in-memory hop with a bounded buffer.
type memHalf struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    []byte
	limit  int
	eof    bool
	err    error
	frozen bool // stops delivering, like a hop through a failed node
}

func newMemHalf(limit int) *memHalf {
	h := &memHalf{limit: limit}
	h.cond = sync.NewCond(&h.mu)
	return h
}

func (h *memHalf) write(p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	written := 0
	for len(p) > 0 {
		for h.err == nil && !h.eof && len(h.buf) >= h.limit {
			h.cond.Wait()
		}
		if h.err != nil {
			return written, h.err
		}
		if h.eof {
			return written, io.ErrClosedPipe
		}
		n := min(len(p), h.limit-len(h.buf))
		h.buf = append(h.buf, p[:n]...)
		p = p[n:]
		written += n
		h.cond.Broadcast()
	}
	return written, nil
}

func (h *memHalf) read(p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for h.err == nil && (h.frozen || len(h.buf) == 0 && !h.eof) {
		h.cond.Wait()
	}
	if h.err != nil {
		return 0, h.err
	}
	if len(h.buf) == 0 {
		return 0, io.EOF
	}
	n := copy(p, h.buf)
	h.buf = h.buf[n:]
	h.cond.Broadcast()
	return n, nil
}

func (h *memHalf) close(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err == nil {
		h.eof = true
	} else if h.err == nil {
		h.err = err
	}
	h.cond.Broadcast()
}

func (h *memHalf) freeze() {
	h.mu.Lock()
	h.frozen = true
	h.mu.Unlock()
}

type memConn struct {
	in, out *memHalf
}

func memPipe(limit int) (*memConn, *memConn) {
	a, b := newMemHalf(limit), newMemHalf(limit)
	return &memConn{in: a, out: b}, &memConn{in: b, out: a}
}

var errMemReset = errors.New("memory hop reset")

func (c *memConn) Read(p []byte) (int, error)  { return c.in.read(p) }
func (c *memConn) Write(p []byte) (int, error) { return c.out.write(p) }
func (c *memConn) CloseWrite() error           { c.out.close(nil); return nil }
func (c *memConn) Close() error {
	c.in.close(errMemClosed)
	c.out.close(nil)
	return nil
}
func (c *memConn) Abort() {
	c.in.close(errMemReset)
	c.out.close(errMemReset)
}

var errMemClosed = errors.New("memory hop closed")

// testGraph builds chains ingress-relay-egress with fresh relays, as the
// Agents do along the current routes.
type testGraph struct {
	t       *testing.T
	ctx     context.Context
	ingress *Ingress
	mu      sync.Mutex
	egress  *Egress
	server  *memConn
	relays  []*SessionRelay
	hops    [][2]*memConn // each relay's (up, down)
	opened  int
	ready   chan struct{}
	fail    int // fail this many opens
}

func (g *testGraph) open(ctx context.Context, epoch uint32, up, down uint64) (Conn, model.ID, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.fail > 0 {
		g.fail--
		return nil, "", errors.New("no route")
	}
	ingressHop, relayUp := memPipe(64 << 10)
	relayDown, egressHop := memPipe(64 << 10)
	relay := NewSessionRelay(relayUp, relayDown)
	go relay.Run(g.ctx)
	g.relays = append(g.relays, relay)
	g.hops = append(g.hops, [2]*memConn{relayUp, relayDown})
	request := Request{Epoch: epoch, Up: up, Down: down}
	if g.egress == nil {
		local, server := memPipe(256 << 10)
		g.server = server
		g.egress = NewEgress(g.ctx, local)
		go func() {
			g.egress.Run()
		}()
		close(g.ready)
	}
	if _, ok := g.egress.Add(egressHop, request); !ok {
		return nil, "", ErrUnknownSession
	}
	g.opened++
	return ingressHop, testutil.ID(int(epoch) + 1), nil
}

func newTestGraph(t *testing.T) (*testGraph, *memConn) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	g := &testGraph{t: t, ctx: ctx, ready: make(chan struct{})}
	ingress, err := StartIngress(ctx, g.open)
	if err != nil {
		t.Fatal(err)
	}
	client, local := memPipe(256 << 10)
	g.ingress = ingress
	go ingress.Serve(ctx, local)
	return g, client
}

func (g *testGraph) lastHops() [2]*memConn {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.hops[len(g.hops)-1]
}

// exchange sends request from the client and response from the server at
// once, then checks both arrive intact and both directions end.
func exchange(t *testing.T, g *testGraph, client *memConn, size int, during func()) {
	t.Helper()
	request, response := make([]byte, size), make([]byte, size)
	rand.Read(request)
	rand.Read(response)
	<-g.ready
	server := g.server
	errs := make(chan error, 4)
	go func() {
		_, err := client.Write(request)
		client.CloseWrite()
		errs <- err
	}()
	go func() {
		_, err := server.Write(response)
		server.CloseWrite()
		errs <- err
	}()
	got := make(chan []byte, 2)
	go func() {
		raw, err := io.ReadAll(server)
		errs <- err
		got <- raw
	}()
	go func() {
		raw, err := io.ReadAll(client)
		errs <- err
		got <- raw
	}()
	if during != nil {
		during()
	}
	for range 4 {
		select {
		case err := <-errs:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("exchange timed out")
		}
	}
	a, b := <-got, <-got
	want := map[[32]byte]bool{sha256.Sum256(request): true, sha256.Sum256(response): true}
	if !want[sha256.Sum256(a)] || !want[sha256.Sum256(b)] || bytes.Equal(a, b) {
		t.Fatalf("bytes changed: %d and %d bytes", len(a), len(b))
	}
}

func TestSessionTransfer(t *testing.T) {
	g, client := newTestGraph(t)
	exchange(t, g, client, 4<<20, nil)
}

// Route changes move the connection to new chains while both directions are
// busy; the old chains finish what they carry.
func TestSessionReroute(t *testing.T) {
	g, client := newTestGraph(t)
	exchange(t, g, client, 8<<20, func() {
		for range 6 {
			time.Sleep(15 * time.Millisecond)
			g.ingress.Reroute()
		}
	})
	if g.opened < 2 {
		t.Fatalf("opened %d chains", g.opened)
	}
}

// A failed relay resets its hops and loses what it buffered. Both ends resend
// from the other's delivered offset on a new chain.
func TestSessionRelayFailure(t *testing.T) {
	g, client := newTestGraph(t)
	g.fail = 2 // the first replacements find no route
	exchange(t, g, client, 8<<20, func() {
		time.Sleep(30 * time.Millisecond)
		hops := g.lastHops()
		hops[0].Abort()
		hops[1].Abort()
	})
}

// A relay that stops forwarding without resetting, like one behind a failed
// node, is left by its route-change notification.
func TestSessionStalledRelay(t *testing.T) {
	g, client := newTestGraph(t)
	exchange(t, g, client, 8<<20, func() {
		time.Sleep(30 * time.Millisecond)
		g.mu.Lock()
		hops, relay := g.hops[len(g.hops)-1], g.relays[len(g.relays)-1]
		g.mu.Unlock()
		hops[0].in.freeze()
		hops[1].in.freeze()
		relay.Notify()
	})
}

func TestSessionAbortReachesServer(t *testing.T) {
	g, client := newTestGraph(t)
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	<-g.ready
	buf := make([]byte, 5)
	if _, err := io.ReadFull(g.server, buf); err != nil {
		t.Fatal(err)
	}
	client.Abort()
	if _, err := io.ReadAll(g.server); err == nil {
		t.Fatal("server saw a clean end after the client reset")
	}
}
