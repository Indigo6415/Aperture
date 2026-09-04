// Package api exposes the REST + WebSocket surface used by the frontend:
// flow CRUD, running a flow, and streaming a run's results live.
package api

import (
	"context"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"sync"

	"github.com/Indigo6415/Aperture/internal/adapters"
	"github.com/Indigo6415/Aperture/internal/engine"
	"github.com/Indigo6415/Aperture/internal/store"
)

type Server struct {
	store        *store.Store
	engine       *engine.Engine
	hub          *hub
	mux          *http.ServeMux
	wordlistsDir string

	// cancelMu guards scanCancels/runCancels, populated while a scan's recon
	// phase (scanCancels) or a scanner run (runCancels) is in flight so
	// handleCancelScan can stop them on demand -- see cancel.go.
	cancelMu    sync.Mutex
	scanCancels map[string]context.CancelFunc
	runCancels  map[string]context.CancelFunc

	// screenshotSem bounds how many headless-Chrome screenshot captures run
	// concurrently across the whole server (see captureScreenshot in
	// screenshots.go) -- each is a real browser process, so fanning one out
	// per discovered subdomain unbounded would be its own resource-exhaustion
	// bug.
	screenshotSem chan struct{}
}

// maxConcurrentScreenshots is screenshotSem's capacity.
const maxConcurrentScreenshots = 4

// NewServer wires up all routes. uiFS is the embedded, built frontend; pass
// nil when running against a separate frontend dev server. wordlistsDir is
// where downloaded/bundled fuzzing wordlists live on disk (see the
// internal/wordlists package) -- the auto-generated domain-scan flow and
// the wordlist-management endpoints both read/write it.
func NewServer(st *store.Store, eng *engine.Engine, uiFS fs.FS, wordlistsDir string) *Server {
	s := &Server{
		store:         st,
		engine:        eng,
		hub:           newHub(),
		mux:           http.NewServeMux(),
		wordlistsDir:  wordlistsDir,
		scanCancels:   map[string]context.CancelFunc{},
		runCancels:    map[string]context.CancelFunc{},
		screenshotSem: make(chan struct{}, maxConcurrentScreenshots),
	}

	s.mux.HandleFunc("GET /api/tools", s.handleListTools)

	s.mux.HandleFunc("POST /api/scan", s.handleStartScan)
	s.mux.HandleFunc("GET /api/scans", s.handleListScans)
	s.mux.HandleFunc("GET /api/scans/{id}", s.handleGetScan)
	s.mux.HandleFunc("GET /api/scans/{id}/runs", s.handleListScanRuns)
	s.mux.HandleFunc("POST /api/scans/{id}/content-discovery", s.handleScanContentDiscovery)
	s.mux.HandleFunc("POST /api/scans/{id}/restart", s.handleRestartScan)
	s.mux.HandleFunc("POST /api/scans/{id}/runs/{kind}/restart", s.handleRestartScanRun)
	s.mux.HandleFunc("POST /api/scans/{id}/cancel", s.handleCancelScan)
	s.mux.HandleFunc("GET /api/scans/{id}/report", s.handleScanReport)
	s.mux.HandleFunc("GET /api/scans/{id}/screenshots", s.handleListScreenshots)
	s.mux.HandleFunc("GET /api/scans/{id}/screenshots/{hostname}", s.handleGetScreenshot)
	s.mux.HandleFunc("GET /ws/scans/{id}", s.handleWatchScan)

	s.mux.HandleFunc("GET /api/wordlists", s.handleListWordlists)
	s.mux.HandleFunc("GET /api/wordlists/catalog", s.handleWordlistCatalog)
	s.mux.HandleFunc("POST /api/wordlists/download", s.handleDownloadWordlist)
	s.mux.HandleFunc("DELETE /api/wordlists/{name}", s.handleDeleteWordlist)
	s.mux.HandleFunc("PATCH /api/wordlists/{name}/categories", s.handleSetWordlistCategories)
	s.mux.HandleFunc("POST /api/wordlists/{name}/duplicate", s.handleDuplicateWordlist)

	s.mux.HandleFunc("GET /api/runs/{id}", s.handleGetRun)
	s.mux.HandleFunc("GET /api/runs/{id}/findings", s.handleListFindings)
	s.mux.HandleFunc("GET /ws/runs/{id}", s.handleWatchRun)

	if uiFS != nil {
		s.mux.Handle("/", spaHandler(uiFS))
	}

	return s
}

func (s *Server) Handler() http.Handler { return withLogging(s.mux) }

func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// spaHandler serves the embedded frontend build, falling back to
// index.html for any path that isn't a real file so client-side routing
// (if any is added later) still works on a hard refresh.
func spaHandler(uiFS fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(uiFS))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cleaned := path.Clean(r.URL.Path)
		if _, err := fs.Stat(uiFS, trimLeadingSlash(cleaned)); err != nil {
			if os.IsNotExist(err) {
				r2 := new(http.Request)
				*r2 = *r
				r2.URL.Path = "/"
				fileServer.ServeHTTP(w, r2)
				return
			}
		}
		fileServer.ServeHTTP(w, r)
	})
}

func trimLeadingSlash(p string) string {
	if len(p) > 0 && p[0] == '/' {
		return p[1:]
	}
	return p
}

func (s *Server) handleListTools(w http.ResponseWriter, r *http.Request) {
	type toolInfo struct {
		Name      string `json:"name"`
		Available bool   `json:"available"`
	}
	out := make([]toolInfo, 0, len(adapters.Registry))
	for name := range adapters.Registry {
		_, err := exec.LookPath(name)
		out = append(out, toolInfo{Name: name, Available: err == nil})
	}
	writeJSON(w, http.StatusOK, out)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
