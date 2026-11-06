package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/store"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
)

// An operator registers an Agent by public key. Over direct TLS without a
// client certificate, the Agent signs challenges by key to learn its ID and
// then by ID, like an Agent behind a TLS-terminating gateway.
func TestAgentRegisteredByPublicKey(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	current, _ := db.Read()
	if _, err := db.Update(current.Revision, func(s *model.State) error { *s = testutil.Topology(); return nil }); err != nil {
		t.Fatal(err)
	}
	s, err := New(db, Options{Password: "test-password-123"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	server := httptest.NewUnstartedServer(s)
	server.TLS, err = s.ca.ServerTLS([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(s.ca.PEM)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}}

	// Administrator session.
	login, _ := http.NewRequest("POST", server.URL+"/api/v1/login", strings.NewReader(`{"password":"test-password-123"}`))
	login.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(login)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("login: %v %v", err, resp)
	}
	var session struct {
		CSRF string `json:"csrf_token"`
	}
	json.NewDecoder(resp.Body).Decode(&session)
	resp.Body.Close()
	createAgent := func(name string, key ed25519.PublicKey) int {
		t.Helper()
		state, _ := db.Read()
		body, _ := json.Marshal(map[string]string{"name": name, "public_key": base64.StdEncoding.EncodeToString(key)})
		req, _ := http.NewRequest("POST", server.URL+"/api/v1/agents", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", session.CSRF)
		req.Header.Set("If-Match", strconv.FormatUint(state.Revision, 10))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 42
	key := ed25519.NewKeyFromSeed(seed)
	public := key.Public().(ed25519.PublicKey)
	if status := createAgent("by key", public); status != 201 {
		t.Fatalf("create agent: HTTP %d", status)
	}
	if status := createAgent("duplicate", public); status != 422 {
		t.Fatalf("duplicate key: HTTP %d, want 422", status)
	}
	state, _ := db.Read()
	var id model.ID
	for _, a := range state.Agents {
		if a.Name == "by key" && bytes.Equal(a.PublicKey, public) {
			id = a.ID
		}
	}
	if id == "" {
		t.Fatal("agent by key was not stored")
	}

	// The Agent itself: TLS verified by the controller CA, no certificate.
	agent := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}}
	challenge := func() string {
		t.Helper()
		resp, err := agent.Get(server.URL + model.AgentChallengePath)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body struct{ Challenge string }
		json.NewDecoder(resp.Body).Decode(&body)
		return body.Challenge
	}
	byKey := func(signer ed25519.PrivateKey, claimed ed25519.PublicKey) http.Header {
		c := challenge()
		h := http.Header{}
		h.Set(model.AgentKeyHeader, model.EncodeAgentKey(claimed))
		h.Set(model.AgentChallengeHeader, c)
		h.Set(model.AgentSignatureHeader, base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer, model.AgentKeyChallengeMessage(claimed, c))))
		return h
	}
	byID := func(id model.ID) http.Header {
		c := challenge()
		h := http.Header{}
		h.Set(model.AgentIDHeader, string(id))
		h.Set(model.AgentChallengeHeader, c)
		h.Set(model.AgentSignatureHeader, base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, model.AgentChallengeMessage(id, c))))
		return h
	}
	registration := func(h http.Header) (int, model.ID, []byte) {
		t.Helper()
		req, _ := http.NewRequest("GET", server.URL+model.AgentRegistrationPath, nil)
		req.Header = h
		resp, err := agent.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body struct {
			AgentID model.ID `json:"agent_id"`
			CA      []byte   `json:"ca_certificate"`
		}
		json.NewDecoder(resp.Body).Decode(&body)
		return resp.StatusCode, body.AgentID, body.CA
	}
	if status, got, ca := registration(byKey(key, public)); status != 200 || got != id || !bytes.Equal(ca, s.ca.PEM) {
		t.Fatalf("registration by key: HTTP %d, id %s", status, got)
	}
	other := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	for name, h := range map[string]http.Header{
		"signed by another key": byKey(other, public),
		"unregistered key":      byKey(other, other.Public().(ed25519.PublicKey)),
	} {
		if status, _, _ := registration(h); status != 401 {
			t.Errorf("%s: HTTP %d, want 401", name, status)
		}
	}
	both := byKey(key, public)
	both.Set(model.AgentIDHeader, string(id))
	if status, _, _ := registration(both); status != 401 {
		t.Errorf("key and ID together: HTTP %d, want 401", status)
	}

	// After learning its ID, the Agent opens the control stream by ID.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, resp, err := websocket.Dial(ctx, strings.Replace(server.URL, "https://", "wss://", 1)+"/api/v1/agent/control", &websocket.DialOptions{HTTPClient: agent, HTTPHeader: byID(id), Subprotocols: []string{model.DeltaSubprotocol}})
	if err != nil {
		t.Fatalf("control stream by ID over direct TLS: %v %v", err, resp)
	}
	conn.CloseNow()

	state, _ = db.Read()
	if _, err := db.Update(state.Revision, func(s *model.State) error {
		for i := range s.Agents {
			if s.Agents[i].ID == id {
				s.Agents[i].Revoked = true
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := registration(byKey(key, public)); status != 401 {
		t.Errorf("revoked agent: HTTP %d, want 401", status)
	}
}
