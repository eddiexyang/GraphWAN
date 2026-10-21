package agent

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/eWloYW8/GraphWAN/internal/model"
)

func TestGatewayEntranceSignsEachRequest(t *testing.T) {
	cache, _, _ := registeredController(t)
	reg, _ := cache.Registration()
	issued := 0
	gateway := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) != 0 {
			t.Error("gateway entrance received a client certificate")
		}
		if r.URL.Path == model.AgentChallengePath {
			issued++
			w.Write([]byte(`{"challenge":"c` + strconv.Itoa(issued) + `"}`))
			return
		}
		id := model.ID(r.Header.Get(model.AgentIDHeader))
		challenge := r.Header.Get(model.AgentChallengeHeader)
		signature, _ := base64.RawURLEncoding.DecodeString(r.Header.Get(model.AgentSignatureHeader))
		if id != reg.AgentID || challenge != "c"+strconv.Itoa(issued) || !ed25519.Verify(cache.PublicKey(), model.AgentChallengeMessage(id, challenge), signature) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer gateway.Close()
	roots := gateway.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	c, err := NewClient(cache, controllerTestRuntime{}, Options{Server: gateway.URL, ServerTransport: "https", GatewayRoots: roots})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	target, err := c.selectTarget()
	if err != nil {
		t.Fatal(err)
	}
	if target.origin != gateway.URL || target.transport != "https" || target.tlsName != "" {
		t.Fatalf("gateway entrance not selected: %+v", target)
	}
	for _, client := range []*http.Client{c.http, c.updateHTTP()} {
		response, err := client.Get(c.server + "/api/v1/agent/update/latest")
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatal(response.Status)
		}
	}
	if issued != 2 {
		t.Fatalf("issued %d challenges, want one per request", issued)
	}
}
