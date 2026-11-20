package controltransport_test

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/eWloYW8/GraphWAN/internal/controltransport"
)

// echoTunnel serves the WebSocket tunnel protocol on a TLS listener whose
// certificate belongs to the entrance, not to the controller behind it.
func echoTunnel(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(controltransport.WebSocketPath, func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{controltransport.WebSocketProtocol}, CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			return
		}
		defer ws.CloseNow()
		for {
			kind, data, err := ws.Read(r.Context())
			if err != nil {
				return
			}
			if err := ws.Write(r.Context(), kind, data); err != nil {
				return
			}
		}
	})
	return httptest.NewTLSServer(mux)
}

// The outer WSS hop is authenticated with the entrance's own roots. The
// controller TLS handshake runs above this adapter, so its roots must not be
// used here.
func TestGatewayDialContextAuthenticatesTheOuterHop(t *testing.T) {
	gateway := echoTunnel(t)
	defer gateway.Close()
	roots := x509.NewCertPool()
	roots.AddCert(gateway.Certificate())
	addr := gateway.Listener.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := controltransport.GatewayDialContext("wss", roots)(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("gateway dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		t.Fatal(err)
	}
	if buf[0] != 'x' {
		t.Fatalf("echo %q, want x", buf[0])
	}

	// A plain dialer verifies the entrance with server roots and fails here.
	if _, err := controltransport.DialContext("wss", x509.NewCertPool(), "controller.test")(ctx, "tcp", addr); err == nil {
		t.Fatal("wss entrance accepted controller-only roots")
	}
}
