package agent

import (
	"context"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/control"
	"github.com/eWloYW8/GraphWAN/internal/controltransport"
	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/pki"
	"github.com/eWloYW8/GraphWAN/internal/store"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
)

// A fresh Agent registering by public key through a controller tunnel must
// verify the controller by the pinned CA, not by the entrance hostname: before
// registration it cannot know the controller's TLS name, and behind a gateway
// the entrance name never matches it.
func TestAgentRegistersByKeyThroughAControllerTunnel(t *testing.T) {
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
	// The certificate deliberately carries a controller identity that does not
	// match the entrance address the Agent dials.
	tlsConfig, err := ca.ServerTLS([]string{"controller.test"})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tunnel := controltransport.NewServer(listener, server, tlsConfig)
	go tunnel.Serve()
	defer tunnel.Close()

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.PEM)
	runtime := applyRecorder{applied: make(chan model.Snapshot, 1)}
	client, err := NewClient(cache, runtime, Options{
		Server:          "https://" + listener.Addr().String(),
		ServerTransport: "websocket",
		Roots:           roots,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
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
		t.Fatal("agent did not register by key through the controller tunnel")
	}
	reg, err := cache.Registration()
	if err != nil || reg == nil || !reg.KeyOnly() || reg.AgentID != fixture.Agents[0].ID {
		t.Fatalf("registration %+v, %v", reg, err)
	}
}
