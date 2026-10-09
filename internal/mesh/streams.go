package mesh

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/link"
	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/peer"
	"github.com/eWloYW8/GraphWAN/internal/streamproxy"
)

type StreamHandler func(context.Context, model.ID, model.ID, streamproxy.Conn)
type streamPolicy struct {
	group     *group
	candidate link.Candidate
	path      link.Path
}
type streamBytes struct{ rx, tx uint64 }

// EnableStreams is called before this Mesh is published to the dataplane.
func (m *Mesh) EnableStreams(handler StreamHandler) {
	m.mu.Lock()
	m.streamHandler = handler
	m.mu.Unlock()
}
func reliableTransport(t model.Transport) bool {
	return t == model.TCP || t == model.QUIC || t == model.WS || t == model.WSS || t == model.GRPC
}

func (m *Mesh) reserveStream() error {
	select {
	case m.streamSlots <- struct{}{}:
		return nil
	case <-m.ctx.Done():
		return net.ErrClosed
	default:
		return errors.New("peer stream connection limit reached")
	}
}
func (m *Mesh) trackStream(s *peer.Stream, g *group, candidate link.Candidate) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.groups[key{g.policy.Load().network, g.policy.Load().peer.Node.ID}] != g {
		return false
	}
	g.mu.Lock()
	allowed := g.allowsCandidateLocked(g.policy.Load(), candidate)
	g.mu.Unlock()
	if !allowed {
		return false
	}
	path := streamPath(s.LocalAddr().String(), s.RemoteAddr().String(), candidate.Endpoint.Transport)
	m.streams[s] = streamPolicy{g, candidate, path}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		<-s.Done()
		m.mu.Lock()
		rx, tx := s.Bytes()
		g.mu.Lock()
		if g.streamBytes == nil {
			g.streamBytes = map[link.Path]streamBytes{}
		}
		previous := g.streamBytes[path]
		g.streamBytes[path] = streamBytes{previous.rx + rx, previous.tx + tx}
		g.mu.Unlock()
		delete(m.streams, s)
		m.mu.Unlock()
		<-m.streamSlots
	}()
	return true
}

func (m *Mesh) acceptStream(ctx context.Context, channel *peer.Channel, g *group, candidate link.Candidate, multiplex bool) {
	m.mu.Lock()
	handler := m.streamHandler
	m.mu.Unlock()
	if handler == nil || !reliableTransport(candidate.Endpoint.Transport) {
		channel.Close()
		return
	}
	if err := m.reserveStream(); err != nil {
		channel.Close()
		return
	}
	s, err := peer.NewStream(g.ctx, ctx, channel, false)
	if err != nil {
		<-m.streamSlots
		return
	}
	if !m.trackStream(s, g, candidate) {
		s.Close()
		<-m.streamSlots
		return
	}
	if multiplex {
		if err := m.startCarrier(ctx, g, candidate, s, false); err != nil {
			s.Close()
		}
		return
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		s.Close()
		return
	}
	m.wg.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.wg.Done()
		defer s.Close()
		cfg := g.policy.Load()
		handler(g.ctx, cfg.network, cfg.peer.Node.ID, s)
	}()
}

// Called with m.mu held: archive and live stream accounting move atomically.
func (m *Mesh) streamTrafficLocked(g *group) map[string]streamBytes {
	g.mu.Lock()
	defer g.mu.Unlock()
	byPath := map[link.Path]string{}
	for id, l := range g.links {
		status := l.Stats()
		path := streamPath(status.Local, status.Remote, status.Transport)
		if previous := byPath[path]; previous == "" || id < previous {
			byPath[path] = id
		}
	}
	traffic := map[string]streamBytes{}
	add := func(path link.Path, bytes streamBytes) {
		if id := byPath[path]; id != "" {
			previous := traffic[id]
			traffic[id] = streamBytes{previous.rx + bytes.rx, previous.tx + bytes.tx}
		}
	}
	for path, bytes := range g.streamBytes {
		if byPath[path] == "" {
			delete(g.streamBytes, path)
		} else {
			add(path, bytes)
		}
	}
	for s, p := range m.streams {
		if p.group == g {
			rx, tx := s.Bytes()
			add(p.path, streamBytes{rx, tx})
		}
	}
	return traffic
}

func streamPath(local, remote string, transport model.Transport) link.Path {
	a, _ := netip.ParseAddrPort(local)
	b, _ := netip.ParseAddrPort(remote)
	return link.Path{Local: a.Addr().Unmap(), Remote: b.Addr().Unmap(), Transport: transport}
}

// OpenStream pins a fresh authenticated connection to an authorized reliable
// candidate. Packet-Link switches cannot drop, reorder or replay these bytes.
func (m *Mesh) OpenStream(parent context.Context, network, remote model.ID) (streamproxy.Conn, error) {
	if err := parent.Err(); err != nil {
		return nil, err
	}
	if err := m.reserveStream(); err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			<-m.streamSlots
		}
	}()
	m.mu.Lock()
	g := m.groups[key{network, remote}]
	m.mu.Unlock()
	if g == nil {
		return nil, link.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(parent, streamproxy.ConnectTimeout)
	defer cancel()
	stop := context.AfterFunc(g.ctx, cancel)
	defer stop()
	cfg := g.policy.Load()
	candidates := g.candidates(cfg, true)
	rtts := map[string]float64{}
	g.mu.Lock()
	for _, l := range g.links {
		if l.Healthy() {
			rtts[l.Info().CandidateID] = l.Stats().RTTMillis
		}
	}
	g.mu.Unlock()
	slices.SortStableFunc(candidates, func(a, b link.Candidate) int {
		if a.ID == b.ID {
			return 0
		}
		if a.ID == cfg.peer.Edge.PreferredCandidate {
			return -1
		}
		if b.ID == cfg.peer.Edge.PreferredCandidate {
			return 1
		}
		ar, aok := rtts[a.ID]
		br, bok := rtts[b.ID]
		if aok != bok {
			if aok {
				return -1
			}
			return 1
		}
		if aok && ar != br {
			if ar < br {
				return -1
			}
			return 1
		}
		return 0
	})
	last := errors.New("edge has no permitted reliable stream candidate")
	for _, candidate := range candidates {
		if !reliableTransport(candidate.Endpoint.Transport) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		g.mu.Lock()
		allowed := g.allowsCandidateLocked(g.policy.Load(), candidate)
		g.mu.Unlock()
		if !allowed {
			continue
		}
		// A dead candidate cannot consume the whole end-to-end setup budget.
		attempt, done := context.WithTimeout(ctx, 3*time.Second)
		channel, err := g.connect(attempt, candidate, true)
		if err != nil {
			done()
			last = err
			continue
		}
		s, err := peer.NewStream(g.ctx, attempt, channel, true)
		done()
		if err != nil {
			last = err
			continue
		}
		if !m.trackStream(s, g, candidate) {
			s.Close()
			last = net.ErrClosed
			continue
		}
		transferred = true
		return s, nil
	}
	// A carrier initiated by the reachable side permits reverse opens without
	// a second reachable endpoint. The reserved slot follows this logical stream.
	s, err := m.openCarrierStream(ctx, g)
	if err == nil {
		transferred = true
		return s, nil
	}
	return nil, errors.Join(last, err)
}
