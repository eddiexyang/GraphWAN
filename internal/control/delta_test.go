package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
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

func TestControlDeltaNegotiationAndReconnect(t *testing.T) {
	for _, protocol := range []string{model.DeltaSubprotocol, model.RoutingSubprotocol} {
		t.Run(protocol, func(t *testing.T) {
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
			csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
			if err != nil {
				t.Fatal(err)
			}
			certificate, _, err := s.ca.IssueAgent(state.Agents[0].ID, csr)
			if err != nil {
				t.Fatal(err)
			}
			// IssueAgent returns PEM; use the parsed leaf with the fixture key.
			roots := x509.NewCertPool()
			roots.AppendCertsFromPEM(s.ca.PEM)
			block, _ := pem.Decode(certificate)
			if block == nil {
				t.Fatal("invalid agent certificate")
			}
			cert := tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: key}
			server := httptest.NewUnstartedServer(s)
			server.TLS, err = s.ca.ServerTLS([]string{"127.0.0.1"})
			if err != nil {
				t.Fatal(err)
			}
			server.StartTLS()
			defer server.Close()
			tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}}}
			defer tr.CloseIdleConnections()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			dial := func() *websocket.Conn {
				t.Helper()
				c, _, err := websocket.Dial(ctx, strings.Replace(server.URL, "https://", "wss://", 1)+"/api/v1/agent/control", &websocket.DialOptions{HTTPClient: &http.Client{Transport: tr}, Subprotocols: []string{protocol}})
				if err != nil {
					t.Fatal(err)
				}
				return c
			}
			conn := dial()
			defer conn.CloseNow()
			var first model.ControlMessage
			if err := wsjson.Read(ctx, conn, &first); err != nil {
				t.Fatal(err)
			}
			if first.Type != "config" || first.Snapshot == nil {
				t.Fatal("connection did not start full")
			}
			if err := wsjson.Write(ctx, conn, model.ControlMessage{Type: "ack", Report: &model.AgentReport{Version: "test", AppliedRevision: first.Snapshot.Revision, Resources: &model.ResourceUsage{UptimeSeconds: 123, LogicalCPUs: 1, Goroutines: 1}}}); err != nil {
				t.Fatal(err)
			}
			state, err = db.Update(state.Revision, func(s *model.State) error {
				s.Agents[1].Endpoints[0].ExpiresAt = time.Now().UTC().Add(time.Minute)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			s.notify()
			var update model.ControlMessage
			for {
				if err := wsjson.Read(ctx, conn, &update); err != nil {
					t.Fatal(err)
				}
				if update.Type == "config" || update.Type == "config_delta" {
					break
				}
			}
			if protocol == model.DeltaSubprotocol {
				if update.Type != "config_delta" || update.Delta == nil {
					t.Fatal("lease update sent full snapshot")
				}
				if _, err := update.Delta.Apply(*first.Snapshot); err != nil {
					t.Fatal(err)
				}
				if err := wsjson.Write(ctx, conn, model.ControlMessage{Type: "ack_revision", Ack: &model.RevisionAck{AppliedRevision: state.Revision}}); err != nil {
					t.Fatal(err)
				}
				for {
					s.mu.Lock()
					status := s.statuses[state.Agents[0].ID]
					s.mu.Unlock()
					if status.AppliedRevision == state.Revision {
						if status.Resources == nil || status.Resources.UptimeSeconds != 123 {
							t.Fatal("small ack erased telemetry")
						}
						break
					}
					if ctx.Err() != nil {
						t.Fatal(ctx.Err())
					}
					time.Sleep(time.Millisecond)
				}
			} else if update.Type != "config" {
				t.Fatal("legacy agent received delta")
			}
			conn.CloseNow()
			reconnected := dial()
			defer reconnected.CloseNow()
			if err := wsjson.Read(ctx, reconnected, &first); err != nil {
				t.Fatal(err)
			}
			if first.Type != "config" || first.Snapshot == nil || first.Snapshot.Revision != state.Revision {
				t.Fatal("reconnect did not restore full baseline")
			}
		})
	}
}
