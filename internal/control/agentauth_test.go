package control

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/store"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
)

func TestSignedChallengeAuthenticatesPlaintextAgent(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	current, _ := db.Read()
	fixture := testutil.Topology()
	state, err := db.Update(current.Revision, func(s *model.State) error { *s = fixture; return nil })
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(db, Options{Password: "test-password-123"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	seed := make([]byte, 32)
	seed[0] = 1
	key := ed25519.NewKeyFromSeed(seed)
	id := state.Agents[0].ID
	server := httptest.NewServer(s)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	challenge := func() string {
		t.Helper()
		resp, err := http.Get(server.URL + model.AgentChallengePath)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body struct{ Challenge string }
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || body.Challenge == "" {
			t.Fatalf("challenge: status=%d err=%v", resp.StatusCode, err)
		}
		return body.Challenge
	}
	headers := func(id model.ID, challenge string, key ed25519.PrivateKey) http.Header {
		h := http.Header{}
		h.Set(model.AgentIDHeader, string(id))
		h.Set(model.AgentChallengeHeader, challenge)
		h.Set(model.AgentSignatureHeader, base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, model.AgentChallengeMessage(id, challenge))))
		return h
	}
	dial := func(h http.Header) (*websocket.Conn, int) {
		t.Helper()
		conn, resp, err := websocket.Dial(ctx, strings.Replace(server.URL, "http://", "ws://", 1)+"/api/v1/agent/control", &websocket.DialOptions{HTTPHeader: h, Subprotocols: []string{model.DeltaSubprotocol}})
		if err != nil {
			if resp == nil {
				t.Fatal(err)
			}
			return nil, resp.StatusCode
		}
		return conn, http.StatusSwitchingProtocols
	}

	used := challenge()
	conn, status := dial(headers(id, used, key))
	if conn == nil {
		t.Fatalf("signed agent rejected: %d", status)
	}
	var first model.ControlMessage
	if err := wsjson.Read(ctx, conn, &first); err != nil || first.Type != "config" {
		t.Fatalf("first message %q: %v", first.Type, err)
	}
	conn.CloseNow()

	other := ed25519.NewKeyFromSeed(make([]byte, 32))
	expired := challenge()
	s.challengeMu.Lock()
	s.challenges[expired] = time.Now().Add(-time.Second)
	s.challengeMu.Unlock()
	for name, h := range map[string]http.Header{
		"replayed challenge": headers(id, used, key),
		"unknown challenge":  headers(id, "never-issued", key),
		"expired challenge":  headers(id, expired, key),
		"wrong key":          headers(id, challenge(), other),
		"other agent id":     headers(state.Agents[1].ID, challenge(), key),
		"no signature":       {},
	} {
		if conn, status := dial(h); conn != nil || status != http.StatusUnauthorized {
			if conn != nil {
				conn.CloseNow()
			}
			t.Errorf("%s: status=%d, want 401", name, status)
		}
	}

	if _, err := db.Update(state.Revision, func(s *model.State) error { s.Agents[0].Revoked = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if conn, status := dial(headers(id, challenge(), key)); conn != nil || status != http.StatusUnauthorized {
		t.Errorf("revoked agent: status=%d, want 401", status)
	}
}
