package mesh

import (
	"github.com/eWloYW8/GraphWAN/internal/link"
	"github.com/eWloYW8/GraphWAN/internal/model"
)

// LinkStateHandler receives advertisements by network and authenticated peer
// node. Receive must not retain raw.
type LinkStateHandler struct {
	Ready   func(network, peer model.ID)
	Receive func(network, peer model.ID, raw []byte)
}

// EnableLinkState is called before this Mesh is published to the dataplane.
func (m *Mesh) EnableLinkState(h LinkStateHandler) {
	m.mu.Lock()
	m.linkState = &h
	m.mu.Unlock()
}

func (m *Mesh) linkStateEnabled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.linkState != nil && !m.closed
}

func (m *Mesh) linkStateHandler() *LinkStateHandler {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.linkState
}

// LinkStateReady may run while the group lock is held during registration,
// so the handler (which sends its database) runs on its own goroutine.
func (g *group) LinkStateReady(*link.Link) {
	h := g.mesh.linkStateHandler()
	if h == nil {
		return
	}
	cfg := g.policy.Load()
	go h.Ready(cfg.network, cfg.peer.Node.ID)
}

func (g *group) ReceiveLinkState(_ *link.Link, raw []byte) {
	if h := g.mesh.linkStateHandler(); h != nil {
		cfg := g.policy.Load()
		h.Receive(cfg.network, cfg.peer.Node.ID, raw)
	}
}

// SendLinkState queues an advertisement on the healthiest Link to peer that
// carries them. It reports false when none does.
func (m *Mesh) SendLinkState(network, peer model.ID, raw []byte) bool {
	m.mu.Lock()
	g := m.groups[key{network, peer}]
	m.mu.Unlock()
	if g == nil {
		return false
	}
	g.mu.Lock()
	var best *link.Link
	for _, l := range g.links {
		if !l.LinkStateReady() || !l.Healthy() {
			continue
		}
		if best == nil || l.Stats().RTTMillis < best.Stats().RTTMillis {
			best = l
		}
	}
	g.mu.Unlock()
	return best != nil && best.SendLinkState(raw)
}
