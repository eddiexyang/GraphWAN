package streamproxy

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
)

const (
	rebuildMin = 200 * time.Millisecond
	rebuildMax = 2 * time.Second
)

// OpenChain opens a session's chain along the current routes. Its directions
// start at up (sent by the ingress) and down (sent by the egress). next is the
// first hop's node.
type OpenChain func(ctx context.Context, epoch uint32, up, down uint64) (hop Conn, next model.ID, err error)

// Ingress serves an access connection as a session. Its first chain is open
// before the connection is accepted, as a connected stream would be.
type Ingress struct {
	open  OpenChain
	first *chain
	e     atomic.Pointer[endpoint]

	// Guarded by e.mu.
	epoch      uint32
	rebuilding bool
	again      bool
}

func StartIngress(ctx context.Context, open OpenChain) (*Ingress, error) {
	hop, next, err := open(ctx, 0, 0, 0)
	if err != nil {
		return nil, err
	}
	return &Ingress{open: open, first: &chain{next: next, hop: hop, writing: true}}, nil
}

func (s *Ingress) Serve(ctx context.Context, local Conn) error {
	e := newEndpoint(ctx, local)
	e.onChainFailed = func(c *chain) {
		if c.writing && !c.superseded {
			s.rerouteLocked()
		}
	}
	e.onNotify = func(c *chain) {
		e.mu.Lock()
		defer e.mu.Unlock()
		if c == e.writingLocked() {
			s.rerouteLocked()
		}
	}
	e.mu.Lock()
	s.e.Store(e)
	e.addChainLocked(s.first)
	e.mu.Unlock()
	return e.run()
}

// Close releases a first chain that never served a connection.
func (s *Ingress) Close() error {
	if s.e.Load() == nil {
		s.first.hop.Close()
	}
	return nil
}

// Next returns the first hop of the chain carrying the connection, if any.
func (s *Ingress) Next() (model.ID, Conn, bool) {
	e := s.e.Load()
	if e == nil {
		return s.first.next, s.first.hop, true
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if c := e.writingLocked(); c != nil && !s.rebuilding {
		return c.next, c.hop, true
	}
	return "", nil, false
}

// Reroute moves the connection to a chain along the current routes.
func (s *Ingress) Reroute() {
	e := s.e.Load()
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	s.rerouteLocked()
}

func (s *Ingress) rerouteLocked() {
	if s.e.Load().done {
		return
	}
	if s.rebuilding {
		s.again = true
		return
	}
	s.rebuilding = true
	go s.rebuild()
}

// rebuild opens chains until one succeeds after the latest request. The new
// chain resends what the egress has not confirmed; it merges what it has.
func (s *Ingress) rebuild() {
	e := s.e.Load()
	delay := rebuildMin
	for {
		e.mu.Lock()
		if e.done {
			s.rebuilding = false
			e.mu.Unlock()
			return
		}
		s.again = false
		s.epoch++
		epoch, up, down := s.epoch, min(e.acked, e.end), e.next
		e.mu.Unlock()
		hop, next, err := s.open(e.ctx, epoch, up, down)
		e.mu.Lock()
		switch {
		case err == nil && e.done:
			hop.Close()
		case err == nil:
			e.addChainLocked(&chain{epoch: epoch, next: next, hop: hop, wpos: up, rpos: down, writing: true})
		case errors.Is(err, ErrUnknownSession):
			e.failLocked(err, false)
		}
		if e.done || err == nil && !s.again {
			s.rebuilding = false
			e.mu.Unlock()
			return
		}
		e.mu.Unlock()
		if err == nil {
			continue
		}
		select {
		case <-e.ctx.Done():
		case <-time.After(delay):
		}
		delay = min(2*delay, rebuildMax)
	}
}

// Egress serves a session's connection to its server.
type Egress struct {
	e *endpoint
}

func NewEgress(ctx context.Context, local Conn) *Egress {
	s := &Egress{e: newEndpoint(ctx, local)}
	return s
}

// Add serves a chain whose request was answered; the returned channel closes
// when the chain is released. The chain with the highest epoch carries the
// server's direction. Add reports false once the session ended or when the
// chain starts beyond the delivered bytes; the caller then closes the chain.
func (s *Egress) Add(hop Conn, request Request) (<-chan struct{}, bool) {
	e := s.e
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.done || request.Up > e.next {
		return nil, false
	}
	writing := true
	for _, c := range e.chains {
		if c.epoch >= request.Epoch {
			writing = false
		}
	}
	c := &chain{epoch: request.Epoch, hop: hop, wpos: min(request.Down, e.end), rpos: request.Up, writing: writing}
	e.addChainLocked(c)
	return c.closed, true
}

// Run serves the connection until it finishes.
func (s *Egress) Run() error { return s.e.run() }

// Done reports whether the session ended.
func (s *Egress) Done() bool {
	s.e.mu.Lock()
	defer s.e.mu.Unlock()
	return s.e.done
}

// SessionRelay forwards one chain of a session between two hops. Toward the
// egress it copies bytes; toward the ingress it copies whole records, so that
// Notify can add one between them.
type SessionRelay struct {
	up, down Conn
	w        recordWriter
	closed   bool // guarded by w.mu
}

func NewSessionRelay(up, down Conn) *SessionRelay {
	r := &SessionRelay{up: up, down: down}
	r.w.hop = up
	return r
}

// Notify tells the ingress that this hop's route changed. It does not block.
func (r *SessionRelay) Notify() {
	go func() {
		r.w.mu.Lock()
		defer r.w.mu.Unlock()
		if !r.closed {
			writeRecord(r.up, recordNotify, nil)
		}
	}()
}

func (r *SessionRelay) Run(ctx context.Context) error {
	closeBoth := sync.OnceFunc(func() { r.up.Close(); r.down.Close() })
	abortBoth := func() {
		for _, conn := range []Conn{r.up, r.down} {
			if a, ok := conn.(interface{ Abort() }); ok {
				a.Abort()
			}
		}
		closeBoth()
	}
	stop := context.AfterFunc(ctx, abortBoth)
	defer stop()
	defer closeBoth()
	errs := make(chan error, 2)
	go func() {
		_, err := io.CopyBuffer(r.down, r.up, make([]byte, 64*1024))
		if err == nil {
			err = r.down.CloseWrite()
		}
		if err != nil {
			abortBoth()
		}
		errs <- err
	}()
	go func() {
		err := r.copyRecords()
		if err != nil {
			abortBoth()
		}
		errs <- err
	}()
	err := errors.Join(<-errs, <-errs)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (r *SessionRelay) copyRecords() error {
	buf := make([]byte, maxRecord)
	for {
		kind, payload, err := readRecord(r.down, buf)
		r.w.mu.Lock()
		if err == io.EOF {
			r.closed = true
			err = r.up.CloseWrite()
			r.w.mu.Unlock()
			return err
		}
		if err == nil {
			err = writeRecord(r.up, kind, payload)
		}
		r.w.mu.Unlock()
		if err != nil {
			return err
		}
	}
}
