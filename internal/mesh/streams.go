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

// StreamCarrier reports whether the Edge to remote carries TCP as streams:
// its streams have a Link, or are moving between its TCP-backed Links, which
// never carry TCP as packets.
func (m *Mesh) StreamCarrier(network, remote model.ID) bool {
	m.mu.Lock()
	g := m.groups[key{network, remote}]
	m.mu.Unlock()
	return g != nil && (g.mux.Available() || g.tcpBacked())
}

// tcpBacked reports whether the Edge has a TCP-backed Link.
func (g *group) tcpBacked() bool {
	if g.edge.ActiveTCPBacked() {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, l := range g.links {
		if l.TCPBacked() {
			return true
		}
	}
	return false
}

// PacketsOnly reports whether the Edge to remote has a selected Link that
// carries no streams, such as UDP or QUIC: TCP crosses it only as packets.
func (m *Mesh) PacketsOnly(network, remote model.ID) bool {
	m.mu.Lock()
	g := m.groups[key{network, remote}]
	m.mu.Unlock()
	return g != nil && g.edge.Active() != nil && !g.mux.Available() && !g.tcpBacked()
}

// TCPCarrier reports whether the Edge to remote sends on a TCP, WS, WSS or
// gRPC Link, which carries TCP only as streams, never as packets.
func (m *Mesh) TCPCarrier(network, remote model.ID) bool {
	m.mu.Lock()
	g := m.groups[key{network, remote}]
	m.mu.Unlock()
	if g == nil {
		return false
	}
	return g.edge.ActiveTCPBacked()
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

func (m *Mesh) acceptMuxStream(g *group, s *muxStream) {
	m.mu.Lock()
	handler := m.streamHandler
	if handler == nil || m.closed {
		m.mu.Unlock()
		s.Abort()
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
