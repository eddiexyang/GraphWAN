package control

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
)

const (
	agentChallengeTTL = time.Minute
	// Challenges are issued without authentication, so the table is bounded.
	maxAgentChallenges = 4096
)

func (s *Server) agentChallenge(w http.ResponseWriter, r *http.Request) {
	raw := make([]byte, 32)
	rand.Read(raw)
	challenge := base64.RawURLEncoding.EncodeToString(raw)
	now := time.Now()
	s.challengeMu.Lock()
	for c, expires := range s.challenges {
		if !now.Before(expires) {
			delete(s.challenges, c)
		}
	}
	if len(s.challenges) >= maxAgentChallenges {
		s.challengeMu.Unlock()
		fail(w, 503, "too many pending agent challenges")
		return
	}
	s.challenges[challenge] = now.Add(agentChallengeTTL)
	s.challengeMu.Unlock()
	respond(w, 200, map[string]any{"challenge": challenge, "expires_at": now.Add(agentChallengeTTL)})
}

// consumeChallenge succeeds at most once per issued challenge.
func (s *Server) consumeChallenge(challenge string) bool {
	s.challengeMu.Lock()
	defer s.challengeMu.Unlock()
	expires, ok := s.challenges[challenge]
	delete(s.challenges, challenge)
	return ok && time.Now().Before(expires)
}

func (s *Server) signedAgent(r *http.Request) (model.ID, ed25519.PublicKey, error) {
	id := model.ID(r.Header.Get(model.AgentIDHeader))
	challenge := r.Header.Get(model.AgentChallengeHeader)
	signature, err := base64.RawURLEncoding.DecodeString(r.Header.Get(model.AgentSignatureHeader))
	if err != nil || challenge == "" || len(signature) != ed25519.SignatureSize {
		return "", nil, errors.New("agent signature required")
	}
	if err := id.Validate(); err != nil {
		return "", nil, err
	}
	if !s.consumeChallenge(challenge) {
		return "", nil, errors.New("unknown or expired agent challenge")
	}
	state, err := s.db.Read()
	if err != nil {
		return "", nil, err
	}
	for _, a := range state.Agents {
		if a.ID == id && len(a.PublicKey) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(a.PublicKey), model.AgentChallengeMessage(id, challenge), signature) {
			return id, ed25519.PublicKey(a.PublicKey), nil
		}
	}
	return "", nil, errors.New("invalid agent signature")
}
