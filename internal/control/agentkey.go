package control

import (
	"net/http"
	"strings"

	"github.com/eWloYW8/GraphWAN/internal/model"
)

// createAgent registers an Agent by its Ed25519 public key, as an alternative
// to enrollment. The Agent keeps its private key and signs controller
// challenges with it; no certificate is issued.
func (s *Server) createAgent(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name      string `json:"name"`
		PublicKey string `json:"public_key"`
	}
	if !decode(w, r, &in) {
		return
	}
	key, ok := model.ParseAgentKey(strings.TrimSpace(in.PublicKey))
	if !ok {
		fail(w, 422, "public key must be a base64 Ed25519 key")
		return
	}
	s.change(w, r, 201, func(state *model.State) error {
		state.Agents = append(state.Agents, model.Agent{ID: model.NewID(), Name: in.Name, PublicKey: key, ListenPort: model.DefaultPort, ExcludeContainerIPs: true, STUNServers: model.DefaultSTUNServers(), Endpoints: []model.Endpoint{}})
		return nil
	})
}

// agentRegistration gives an authenticated Agent what enrollment would have:
// its ID, the controller CA and the controller directory.
func (s *Server) agentRegistration(w http.ResponseWriter, r *http.Request) {
	id, err := s.authenticatedAgent(r)
	if err != nil {
		fail(w, 401, "valid agent identity required")
		return
	}
	state, err := s.db.Read()
	if err != nil {
		s.internal(w, err)
		return
	}
	respond(w, 200, map[string]any{"agent_id": id, "ca_certificate": s.ca.PEM, "servers": state.ServerDirectory()})
}
