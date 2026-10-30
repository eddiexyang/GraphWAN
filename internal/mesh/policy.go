package mesh

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/link"
	"github.com/eWloYW8/GraphWAN/internal/model"
)

// Candidate IDs describe a stable preference. Bind the introduction separately
// to the exact current endpoint URL/source so an old completed handshake cannot
// claim the replacement endpoint merely by reusing its unchanged ID.
func endpointFingerprint(endpoint model.Endpoint) string {
	sum := sha256.Sum256([]byte(string(endpoint.Source) + "\x00" + string(endpoint.Transport) + "\x00" + endpoint.URL))
	return hex.EncodeToString(sum[:16])
}

// A healthy observed path can outlive its discovery lease, but never the
// configured method. Endpoint provenance is independent of direct/punch policy.
func observedMethodAllowed(cfg *policy, candidate link.Candidate) bool {
	if candidate.Port != 0 && !cfg.peer.Edge.Methods.HolePunchExtension {
		return false
	}
	if candidate.Endpoint.Source != model.Observed || !slices.Contains(cfg.peer.Edge.Transports, candidate.Endpoint.Transport) {
		return false
	}
	switch candidate.Method {
	case link.Direct:
		return candidate.Family == 4 && cfg.peer.Edge.Methods.IPv4Direct || candidate.Family == 6 && cfg.peer.Edge.Methods.IPv6Direct
	case link.Punch:
		return cfg.peer.Edge.Methods.HolePunch && (candidate.Endpoint.Transport == model.UDP || candidate.Endpoint.Transport == model.TCP)
	default:
		return false
	}
}

// A configured endpoint authorizes its own live paths, including DNS answers
// retained across refresh. A vanished STUN lease may renew only an already
// healthy session; disabling its method/transport still revokes it.
func candidateConfigured(cfg *policy, candidate link.Candidate, healthy bool) bool {
	if !cfg.peer.Edge.Enabled || !slices.Contains(cfg.peer.Edge.Transports, candidate.Endpoint.Transport) {
		return false
	}
	if healthy && observedMethodAllowed(cfg, candidate) {
		for _, initiator := range []model.ID{cfg.self, cfg.peer.Node.ID} {
			if candidate.Identity(cfg.peer.Edge.ID, initiator) == candidate.ID {
				return true
			}
		}
	}
	for _, outgoing := range []bool{true, false} {
		initiator, peer, scopes := cfg.self, cfg.peer, cfg.endpoints
		if !outgoing {
			initiator, peer, scopes = cfg.peer.Node.ID, model.Peer{Edge: cfg.peer.Edge, Endpoints: cfg.endpoints}, cfg.peer.Endpoints
		}
		for _, base := range link.Candidates(initiator, peer, time.Now()) {
			if base.Endpoint.URL != candidate.Endpoint.URL || base.Endpoint.Source != candidate.Endpoint.Source {
				continue
			}
			if candidate.Target.IsValid() {
				var err error
				base, err = link.ResolveCandidate(base, candidate.Target)
				if err != nil {
					continue
				}
			}
			base, ok := introducedScope(base, link.ScopeIdentity(candidate.Scope), scopes)
			if ok && base.ID == candidate.ID {
				return true
			}
		}
	}
	return false
}

// Called with g.mu held, including at handshake completion, to prevent a dial
// started under old policy from reinstalling a revoked endpoint.
func (g *group) allowsCandidateLocked(cfg *policy, candidate link.Candidate) bool {
	healthy := false
	for _, l := range g.links {
		if l.Info().CandidateID == candidate.ID && l.Stats().Healthy {
			healthy = true
			break
		}
	}
	return candidateConfigured(cfg, candidate, healthy)
}

func (g *group) updatePolicy(cfg *policy) []*link.Link {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.policy.Store(cfg)
	g.edge.SetPreferred(cfg.peer.Edge.PreferredCandidate)
	var retired []*link.Link
	var stale []string
	replaced := false
	for id, l := range g.links {
		healthy := l.Stats().Healthy
		if candidateConfigured(cfg, g.linkCandidates[id], healthy) {
			delete(g.draining, id)
			replaced = replaced || healthy
			continue
		}
		stale = append(stale, id)
	}
	for _, id := range stale {
		l := g.links[id]
		// Keep carrying traffic on a healthy Link the new policy no longer
		// allows until an allowed Link is healthy, so a transport change does
		// not take the edge down. Disabling the edge still closes it at once.
		if cfg.peer.Edge.Enabled && !replaced && l.Healthy() {
			if g.draining == nil {
				g.draining = map[string]time.Time{}
			}
			if _, ok := g.draining[id]; !ok {
				g.draining[id] = time.Now().Add(drainLimit)
			}
			continue
		}
		retired = append(retired, l)
		delete(g.links, id)
		delete(g.linkCandidates, id)
		delete(g.draining, id)
		g.edge.Remove(id)
	}
	for id, state := range g.attempts {
		if g.allowsCandidateLocked(cfg, state.candidate) {
			continue
		}
		if state.cancel != nil {
			state.cancel()
		}
		delete(g.attempts, id)
	}
	return retired
}

// drainLimit bounds how long a Link the policy no longer allows keeps the
// edge up while waiting for an allowed replacement.
const drainLimit = 30 * time.Second

// drain closes Links kept by updatePolicy once any other Link is healthy,
// they fail, or drainLimit passes. Every Link not draining is allowed.
func (g *group) drain() {
	g.mu.Lock()
	if len(g.draining) == 0 {
		g.mu.Unlock()
		return
	}
	replaced := false
	for id, l := range g.links {
		if _, ok := g.draining[id]; !ok && l.Healthy() {
			replaced = true
			break
		}
	}
	now := time.Now()
	var retired []*link.Link
	for id, deadline := range g.draining {
		l := g.links[id]
		if l == nil {
			delete(g.draining, id)
			continue
		}
		if !replaced && l.Healthy() && now.Before(deadline) {
			continue
		}
		retired = append(retired, l)
		delete(g.links, id)
		delete(g.linkCandidates, id)
		delete(g.draining, id)
		g.edge.Remove(id)
	}
	g.mu.Unlock()
	for _, l := range retired {
		l.Close()
	}
}
