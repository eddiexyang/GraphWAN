package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/pki"
	"github.com/eWloYW8/GraphWAN/internal/routing"
	"github.com/eWloYW8/GraphWAN/internal/store"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
)

type controllerTestRuntime struct{}

func (controllerTestRuntime) Apply(context.Context, model.Snapshot) error { return nil }
func (controllerTestRuntime) Report() []model.LinkStatus                  { return nil }

func registeredController(t *testing.T, legacy ...bool) (*Cache, *pki.Authority, model.Server) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ca, err := pki.LoadOrCreate(db)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := OpenCache(filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cache.Close() })
	state := testutil.Topology()
	state.Agents[0].PublicKey = cache.PublicKey()
	csr, err := cache.CSR()
	if err != nil {
		t.Fatal(err)
	}
	certificate, _, err := ca.IssueAgent(state.Agents[0].ID, csr)
	if err != nil {
		t.Fatal(err)
	}
	server := model.Server{ID: testutil.ID(90), Name: "controller", PublicKey: state.Agents[1].PublicKey,
		Endpoints: []model.ServerEndpoint{{ID: testutil.ID(91), Transport: "tcp", Source: model.Manual, URL: "tcp://127.0.0.1:1"}}}
	reg := Registration{AgentID: state.Agents[0].ID, Server: "https://127.0.0.1:1", Transport: "tcp", Certificate: certificate, CA: ca.PEM,
		Directory: &model.ServerDirectory{ClusterID: testutil.ID(99), Revision: 1, CA: ca.PEM, Servers: []model.Server{server}}}
	if len(legacy) > 0 && legacy[0] {
		reg.Directory = nil
	}
	if err := cache.SaveRegistration(reg); err != nil {
		t.Fatal(err)
	}
	snapshot, err := routing.Compile(state, state.Agents[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.SaveDesired(snapshot); err != nil {
		t.Fatal(err)
	}
	if err := cache.MarkApplied(snapshot); err != nil {
		t.Fatal(err)
	}
	return cache, ca, server
}

func controllerEndpoint(t *testing.T, ca *pki.Authority, name string, agentID model.ID) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.VerifiedChains) == 0 || r.TLS.PeerCertificates[0].Subject.CommonName != string(agentID) {
			t.Error("controller did not receive the original authenticated Agent")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	var err error
	s.TLS, err = ca.ServerTLS([]string{name})
	if err != nil {
		t.Fatal(err)
	}
	s.TLS.ClientAuth = tls.RequireAndVerifyClientCert
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func TestConfiguredControllerAddressPreservesRegistration(t *testing.T) {
	cache, ca, server := registeredController(t)
	reg, _ := cache.Registration()
	before, _ := json.Marshal(reg)
	privateKey := cache.PrivateKey()
	desired, applied, _ := cache.Snapshots()
	snapshots, _ := json.Marshal([]*model.Snapshot{desired, applied})
	if err := cache.saveLastServer(targets(*reg)[0].key); err != nil {
		t.Fatal(err)
	}
	s := controllerEndpoint(t, ca, server.TLSName(), reg.AgentID)
	c, err := NewClient(cache, controllerTestRuntime{}, Options{Server: s.URL + "/", ServerTransport: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	target, err := c.selectTarget()
	if err != nil {
		t.Fatal(err)
	}
	if target.origin != s.URL || target.tlsName != server.TLSName() {
		t.Fatalf("selected stale or unpinned entrance: %+v", target)
	}
	response, err := c.http.Get(c.server)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatal(response.Status)
	}
	reg, _ = cache.Registration()
	after, _ := json.Marshal(reg)
	if !bytes.Equal(before, after) || !bytes.Equal(privateKey, cache.PrivateKey()) {
		t.Fatal("runtime entrance rewrote registration or identity")
	}
	desired, applied, _ = cache.Snapshots()
	afterSnapshots, _ := json.Marshal([]*model.Snapshot{desired, applied})
	if !bytes.Equal(snapshots, afterSnapshots) {
		t.Fatal("runtime entrance changed cached network snapshots")
	}
}

func TestConfiguredControllerFailureFallsBack(t *testing.T) {
	cache, ca, server := registeredController(t)
	reg, _ := cache.Registration()
	s := controllerEndpoint(t, ca, server.TLSName(), reg.AgentID)
	directory := reg.Directory.Clone()
	directory.Revision++
	directory.Servers[0].Endpoints[0].URL = strings.Replace(s.URL, "https://", "tcp://", 1)
	if err := cache.SaveDirectory(directory, nil); err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(cache, controllerTestRuntime{}, Options{Server: "https://127.0.0.1:1", ServerTransport: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.connect(ctx, reg.AgentID, make(chan model.Snapshot), make(chan struct{})); err == nil {
		t.Fatal("unreachable configured entrance connected")
	}
	target, err := c.selectTarget()
	if err != nil || target.origin != s.URL {
		t.Fatalf("cached entrance did not provide failover: %+v, %v", target, err)
	}
	response, err := c.http.Get(c.server)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatal(response.Status)
	}
}

func TestConfiguredControllerLegacyRegistration(t *testing.T) {
	cache, ca, _ := registeredController(t, true)
	reg, _ := cache.Registration()
	before, _ := json.Marshal(reg)
	s := controllerEndpoint(t, ca, "127.0.0.1", reg.AgentID)
	c, err := NewClient(cache, controllerTestRuntime{}, Options{Server: s.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	target, err := c.selectTarget()
	if err != nil || target.origin != s.URL {
		t.Fatalf("legacy seed was not overridden: %+v, %v", target, err)
	}
	response, err := c.http.Get(c.server)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatal(response.Status)
	}
	reg, _ = cache.Registration()
	after, _ := json.Marshal(reg)
	if !bytes.Equal(before, after) {
		t.Fatal("legacy registration was rewritten")
	}
}

func TestConfiguredControllerCannotChangeTrust(t *testing.T) {
	for _, mismatch := range []string{"controller identity", "CA"} {
		t.Run(mismatch, func(t *testing.T) {
			cache, ca, server := registeredController(t)
			reg, _ := cache.Registration()
			name := server.TLSName()
			if mismatch == "controller identity" {
				name = (model.Server{ID: testutil.ID(92)}).TLSName()
			} else {
				_, ca, _ = registeredController(t)
			}
			s := controllerEndpoint(t, ca, name, reg.AgentID)
			roots := x509.NewCertPool()
			roots.AppendCertsFromPEM(ca.PEM)
			c, err := NewClient(cache, controllerTestRuntime{}, Options{Server: s.URL, Roots: roots})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if _, err := c.selectTarget(); err != nil {
				t.Fatal(err)
			}
			if response, err := c.http.Get(c.server); err == nil {
				response.Body.Close()
				t.Fatal("configured entrance replaced cached controller trust")
			}
		})
	}
}

func TestConfiguredControllerRespectsRevocationAndDefaultSelection(t *testing.T) {
	cache, _, _ := registeredController(t)
	c, err := NewClient(cache, controllerTestRuntime{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	target, err := c.selectTarget()
	if err != nil || target.origin != "https://127.0.0.1:1" {
		t.Fatalf("unconfigured cached selection changed: %+v, %v", target, err)
	}
	reg, _ := cache.Registration()
	directory := reg.Directory.Clone()
	directory.Revision++
	directory.Servers[0].Revoked = true
	if err := cache.SaveDirectory(directory, nil); err != nil {
		t.Fatal(err)
	}
	c.Close()
	c, err = NewClient(cache, controllerTestRuntime{}, Options{Server: "https://127.0.0.1:2"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.selectTarget(); err == nil {
		t.Fatal("explicit address bypassed revoked controller identity")
	}
}
