package agent

import (
	"context"
	"crypto/x509"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/control"
	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/pki"
	"github.com/eWloYW8/GraphWAN/internal/store"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
)

type applyRecorder struct{ applied chan model.Snapshot }

func (r applyRecorder) Apply(_ context.Context, s model.Snapshot) error {
	select {
	case r.applied <- s:
	default:
	}
	return nil
}
func (applyRecorder) Report() []model.LinkStatus { return nil }

// An Agent whose public key was registered on the controller starts without
// an enrollment token: it learns its ID by key and receives its configuration
// over direct TLS without a client certificate.
func TestAgentStartsFromRegisteredPublicKey(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cache, err := OpenCache(filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	fixture := testutil.Topology()
	fixture.Agents[0].PublicKey = cache.PublicKey()
	current, _ := db.Read()
	if _, err := db.Update(current.Revision, func(s *model.State) error { *s = fixture; return nil }); err != nil {
		t.Fatal(err)
	}
	server, err := control.New(db, control.Options{Password: "test-password-123"})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ca, err := pki.LoadOrCreate(db)
	if err != nil {
		t.Fatal(err)
	}
	listener := httptest.NewUnstartedServer(server)
	listener.TLS, err = ca.ServerTLS([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	listener.StartTLS()
	defer listener.Close()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.PEM)

	runtime := applyRecorder{applied: make(chan model.Snapshot, 1)}
	client, err := NewClient(cache, runtime, Options{Server: listener.URL, ServerTransport: "tcp", Roots: roots})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	go client.Run(ctx)
	select {
	case snapshot := <-runtime.applied:
		if snapshot.AgentID != fixture.Agents[0].ID {
			t.Fatalf("configuration for %s, want %s", snapshot.AgentID, fixture.Agents[0].ID)
		}
	case <-ctx.Done():
		t.Fatal("agent registered by key received no configuration")
	}
	reg, err := cache.Registration()
	if err != nil || reg == nil || !reg.KeyOnly() || reg.AgentID != fixture.Agents[0].ID || len(reg.CA) == 0 {
		t.Fatalf("registration %+v, %v", reg, err)
	}
}
