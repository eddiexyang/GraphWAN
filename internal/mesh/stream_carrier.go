package mesh

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/link"
	"github.com/eWloYW8/GraphWAN/internal/peer"
	"github.com/eWloYW8/GraphWAN/internal/streamproxy"
	"github.com/hashicorp/yamux"
)

// Carriers provide reverse-open capability for one-way reachable paths. Normal
// outgoing opens use dedicated connections to avoid shared TCP head-of-line waits.
type streamCarrier struct {
	session   *yamux.Session
	candidate link.Candidate
	created   time.Time
}

func (g *group) ensureCarrier(ctx context.Context, candidate link.Candidate) {
	g.mesh.mu.Lock()
	enabled := g.mesh.streamHandler != nil && !g.mesh.closed
	g.mesh.mu.Unlock()
	if !enabled {
		return
	}
	g.mu.Lock()
	if g.carrierDials[candidate.ID] {
		g.mu.Unlock()
		return
	}
	for carrier := range g.carriers {
		if carrier.candidate.ID == candidate.ID && !carrier.session.IsClosed() && time.Since(carrier.created) < 50*time.Minute {
			g.mu.Unlock()
			return
		}
	}
	if g.carrierDials == nil {
		g.carrierDials = map[string]bool{}
	}
	g.carrierDials[candidate.ID] = true
	g.mu.Unlock()
	defer func() { g.mu.Lock(); delete(g.carrierDials, candidate.ID); g.mu.Unlock() }()
	if err := g.mesh.reserveStream(); err != nil {
		return
	}
	transferred := false
	defer func() {
		if !transferred {
			<-g.mesh.streamSlots
		}
	}()
	channel, err := g.connect(ctx, candidate, true, true)
	if err != nil {
		return
	}
	s, err := peer.NewStream(g.ctx, ctx, channel, true)
	if err != nil {
		return
	}
	if !g.mesh.trackStream(s, g, candidate) {
		s.Close()
		return
	}
	transferred = true
	if err := g.mesh.startCarrier(ctx, g, candidate, s, true); err != nil {
		s.Close()
	}
}

func (m *Mesh) startCarrier(ctx context.Context, g *group, candidate link.Candidate, s *peer.Stream, initiator bool) error {
	// An explicit ready exchange starts QUIC's lazy stream and prevents a legacy
	// packet peer from being installed as a byte multiplexer.
	if err := s.During(ctx, func() error {
		var ready [1]byte
		if initiator {
			if _, err := s.Write([]byte{'M'}); err != nil {
				return err
			}
		}
		if _, err := io.ReadFull(s, ready[:]); err != nil {
			return err
		}
		if ready[0] != 'M' {
			return errors.New("stream carrier version mismatch")
		}
		if !initiator {
			_, err := s.Write([]byte{'M'})
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	config := yamux.DefaultConfig()
	config.AcceptBacklog = 8
	config.MaxStreamWindowSize = 1024 * 1024
	config.ConnectionWriteTimeout = 10 * time.Second
	config.KeepAliveInterval = 10 * time.Second
	config.StreamOpenTimeout = 3 * time.Second
	config.StreamCloseTimeout = 3 * time.Second
	config.LogOutput = io.Discard
	var session *yamux.Session
	var err error
	if initiator {
		session, err = yamux.Client(s, config)
	} else {
		session, err = yamux.Server(s, config)
	}
	if err != nil {
		return err
	}
	carrier := &streamCarrier{session: session, candidate: candidate, created: time.Now()}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		session.Close()
		return net.ErrClosed
	}
	g.mu.Lock()
	if g.ctx.Err() != nil {
		g.mu.Unlock()
		m.mu.Unlock()
		session.Close()
		return net.ErrClosed
	}
	if g.carriers == nil {
		g.carriers = map[*streamCarrier]bool{}
	}
	g.carriers[carrier] = true
	g.mu.Unlock()
	m.wg.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.wg.Done()
		defer session.Close()
		defer s.Close()
		defer func() { g.mu.Lock(); delete(g.carriers, carrier); g.mu.Unlock() }()
		for {
			stream, err := session.AcceptStreamWithContext(g.ctx)
			if err != nil {
				return
			}
			if err := m.reserveStream(); err != nil {
				stream.Close()
				continue
			}
			conn := m.wrapCarrierStream(stream)
			m.mu.Lock()
			handler := m.streamHandler
			if m.closed || handler == nil {
				m.mu.Unlock()
				conn.Close()
				return
			}
			m.wg.Add(1)
			m.mu.Unlock()
			go func() {
				defer m.wg.Done()
				defer conn.Close()
				cfg := g.policy.Load()
				handler(g.ctx, cfg.network, cfg.peer.Node.ID, conn)
			}()
		}
	}()
	return nil
}

func (m *Mesh) openCarrierStream(ctx context.Context, g *group) (streamproxy.Conn, error) {
	// Initial reconciliation may still be establishing the reachable peer's
	// carrier. Wait within the existing end-to-end setup budget.
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		g.mu.Lock()
		var selected *streamCarrier
		for c := range g.carriers {
			if !c.session.IsClosed() && (selected == nil || c.created.After(selected.created)) {
				selected = c
			}
		}
		g.mu.Unlock()
		if selected != nil {
			type result struct {
				stream *yamux.Stream
				err    error
			}
			ready := make(chan result)
			go func() {
				s, err := selected.session.OpenStream()
				select {
				case ready <- result{s, err}:
				case <-ctx.Done():
					if s != nil {
						s.Close()
					}
				}
			}()
			select {
			case r := <-ready:
				if r.err != nil {
					return nil, r.err
				}
				return m.wrapCarrierStream(r.stream), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		// UDP-only edges can never establish a reliable carrier.
		possible := false
		for _, transport := range g.policy.Load().peer.Edge.Transports {
			possible = possible || reliableTransport(transport)
		}
		if !possible {
			return nil, errors.New("edge permits no reliable stream transport")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

type carrierConn struct {
	*yamux.Stream
	once    sync.Once
	release func()
}

func (c *carrierConn) CloseWrite() error { return c.Stream.Close() }
func (c *carrierConn) Close() error {
	var err error
	c.once.Do(func() {
		c.SetReadDeadline(time.Now())
		c.SetWriteDeadline(time.Now())
		err = c.Stream.Close()
		c.release()
	})
	return err
}
func (m *Mesh) wrapCarrierStream(stream *yamux.Stream) *carrierConn {
	return &carrierConn{Stream: stream, release: func() { <-m.streamSlots }}
}
