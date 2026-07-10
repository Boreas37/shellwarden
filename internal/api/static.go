package api

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/gorilla/mux"
)

// serveInstall serves the agent install script.
func (a *API) serveInstall(w http.ResponseWriter, r *http.Request) {
	// TODO: bake install.sh into the gateway image; this serves it from disk.
	http.ServeFile(w, r, filepath.Join("scripts", "install.sh"))
}

// serveAgentBinary serves the cross-compiled agent binary for a target. All
// Linux distros share the same statically linked binary, so the {os} path
// segment (debian/rhel/arch) maps to the single "linux" build directory.
func (a *API) serveAgentBinary(w http.ResponseWriter, r *http.Request) {
	arch := mux.Vars(r)["arch"]
	switch arch {
	case "amd64", "arm64":
	default:
		http.Error(w, "unsupported arch", http.StatusNotFound)
		return
	}

	path := filepath.Join(a.Cfg.AgentsPath, "linux", arch, "shellwarden-agent")
	if _, err := os.Stat(path); err != nil {
		http.Error(w, "agent binary not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, path)
}

// spaHandler serves the built SPA, falling back to index.html for unknown paths
// so client-side routes (e.g. /servers, /audit) resolve correctly.
func (a *API) spaHandler() http.Handler {
	root := a.Cfg.StaticPath
	fileServer := http.FileServer(http.Dir(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := filepath.Clean(r.URL.Path)
		full := filepath.Join(root, clean)
		if info, err := os.Stat(full); err == nil && !info.IsDir() {
			fileServer.ServeHTTP(w, r)
			return
		}
		// Fallback: serve index.html for SPA routing.
		index := filepath.Join(root, "index.html")
		if _, err := os.Stat(index); err != nil {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, index)
	})
}
