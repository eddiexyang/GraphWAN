package webui

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestStaticFiles(t *testing.T) {
	directory := t.TempDir()
	t.Chdir(directory)
	if err := os.MkdirAll(filepath.Join(directory, "assets", "agent", "revision"), 0755); err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string]string{
		"index.html":                        "<html>GraphWAN</html>",
		"assets/agent/revision/linux-amd64": "0123456789",
		"private.txt":                       "private",
	} {
		if err := os.WriteFile(filepath.Join(directory, path), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	handler := Handler()
	for _, tc := range []struct {
		method, path, rangeHeader string
		status                    int
		body                      string
	}{
		{"GET", "/", "", 200, "<html>GraphWAN</html>"},
		{"GET", "/assets/agent/revision/linux-amd64", "", 200, "0123456789"},
		{"HEAD", "/assets/agent/revision/linux-amd64", "", 200, ""},
		{"GET", "/assets/agent/revision/linux-amd64", "bytes=2-4", 206, "234"},
		{"GET", "/assets/agent/revision/", "", 404, ""},
		{"GET", "/assets/../private.txt", "", 404, ""},
		{"GET", "/private.txt", "", 404, ""},
		{"GET", "/api/v1/state", "", 404, ""},
	} {
		t.Run(tc.method+tc.path+tc.rangeHeader, func(t *testing.T) {
			request := httptest.NewRequest(tc.method, tc.path, nil)
			request.Header.Set("Range", tc.rangeHeader)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.status {
				t.Fatalf("status=%d, want %d", response.Code, tc.status)
			}
			if tc.status < 400 && response.Body.String() != tc.body {
				t.Fatalf("body=%q, want %q", response.Body.String(), tc.body)
			}
		})
	}
	if err := os.Remove("index.html"); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusNotFound {
		t.Fatal("missing index exposed a directory listing")
	}
}
