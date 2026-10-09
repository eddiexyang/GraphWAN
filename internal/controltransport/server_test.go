package controltransport_test

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/controltransport"
)

func TestPlainHTTPStaticAssets(t *testing.T) {
	certificateServer := httptest.NewTLSServer(http.NotFoundHandler())
	defer certificateServer.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /assets/binary", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("agent"))
	})
	mux.HandleFunc("GET /api/private", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	server := controltransport.NewServer(listener, mux, certificateServer.TLS)
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	t.Cleanup(func() {
		server.Close()
		if err := <-done; !controltransport.Closed(err) {
			t.Error(err)
		}
		server.Wait()
	})
	client := &http.Client{Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	for _, method := range []string{"GET", "HEAD"} {
		t.Run(method, func(t *testing.T) {
			client.CloseIdleConnections()
			request, _ := http.NewRequest(method, "http://"+listener.Addr().String()+"/assets/binary", nil)
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, _ := io.ReadAll(response.Body)
			if response.StatusCode != 200 || method == "GET" && string(body) != "agent" || method == "HEAD" && len(body) != 0 {
				t.Fatalf("status=%d body=%q", response.StatusCode, body)
			}
		})
	}
	response, err := client.Get("http://" + listener.Addr().String() + "/api/private")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUpgradeRequired {
		t.Fatal("non-static API reached the plaintext handler")
	}
	secure := certificateServer.Client()
	defer secure.CloseIdleConnections()
	response, err = secure.Get("https://" + listener.Addr().String() + "/api/private")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusTeapot {
		t.Fatal("existing TLS handler stopped working")
	}
}
