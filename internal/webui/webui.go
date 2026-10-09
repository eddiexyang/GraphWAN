// Package webui serves production static files from the server working directory.
package webui

import (
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"
)

func Handler() http.Handler {
	root := os.DirFS(".")
	files := http.FileServer(http.FS(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Static assets do not bypass API authentication, and missing asset/API
		// paths never receive an HTML fallback masquerading as a successful API.
		if r.URL.Path != "/" && r.URL.Path != "/THIRD_PARTY_LICENSES.txt" && !strings.HasPrefix(r.URL.Path, "/assets/") {
			http.NotFound(w, r)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = "index.html"
		}
		info, err := fs.Stat(root, name)
		if err != nil || !info.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(20 * time.Minute))
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		files.ServeHTTP(w, r)
	})
}
