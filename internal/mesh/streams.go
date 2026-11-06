package mesh

import (
	"context"

	"github.com/eWloYW8/GraphWAN/internal/link"
	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/streamproxy"
)

type StreamHandler func(context.Context, model.ID, model.ID, streamproxy.Conn)

// EnableStreams is called before this Mesh is published to the dataplane.
func (m *Mesh) EnableStreams(handler StreamHandler) {
	m.mu.Lock()
	m.streamHandler = handler
	m.mu.Unlock()
}

// DisableResume carries streams without TCP sessions, as Agents before them
// did. It is called before this Mesh is published to the dataplane.
func (m *Mesh) DisableResume() {
	m.mu.Lock()
	m.noResume = true
	m.mu.Unlock()
}

func (m *Mesh) resumeEnabled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.streamHandler != nil && !m.noResume
}

func (m *Mesh) streamsEnabled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.streamHandler != nil
}

// Streams need ordered, reliable delivery from the Link's transport.
func streamTransport(t model.Transport) bool {
	return t == model.TCP || t == model.WS || t == model.WSS || t == model.GRPC
}

// StreamsAvailable reports whether the Edge to remote can carry a new stream.
func (m *Mesh) StreamsAvailable(network, remote model.ID) bool {
	m.mu.Lock()
	g := m.groups[key{network, remote}]
	m.mu.Unlock()
	return g != nil && g.mux.Available()
}

// ResumeAvailable reports whether a stream to remote can carry a resumable TCP
// session: both Agents support them.
func (m *Mesh) ResumeAvailable(network, remote model.ID) bool {
	m.mu.Lock()
	g := m.groups[key{network, remote}]
	m.mu.Unlock()
	return g != nil && g.mux.Resumable()
}

// OpenStream starts a stream on the Edge's current Link. It sends nothing until
// the caller writes, and never dials, handshakes or probes candidates.
func (m *Mesh) OpenStream(ctx context.Context, network, remote model.ID) (streamproxy.Conn, error) {
	m.mu.Lock()
	g := m.groups[key{network, remote}]
	m.mu.Unlock()
	if g == nil {
		return nil, link.ErrUnavailable
	}
	return g.mux.Open(ctx)
}

func (m *Mesh) acceptMuxStream(g *group, s *muxStream) { m.acceptHop(g, s) }

// acceptHop hands a stream or carrier connection from the Edge's peer to the
// stream handler, and closes it when the handler returns.
func (m *Mesh) acceptHop(g *group, s streamproxy.Conn) {
	m.mu.Lock()
	handler := m.streamHandler
	if handler == nil || m.closed {
		m.mu.Unlock()
		if a, ok := s.(interface{ Abort() }); ok {
			a.Abort()
		}
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
