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

	// cancelMu guards jobCancels, populated while a job (engine-backed or
	// identify) is in flight so handleCancelJob can stop it on demand --
	// see cancel.go.
	cancelMu   sync.Mutex
	jobCancels map[string]context.CancelFunc

	// screenshotSem bounds how many headless-Chrome screenshot captures run
	// concurrently across the whole server (see captureScreenshot in
	// screenshots.go) -- each is a real browser process, so fanning one out
	// per discovered subdomain unbounded would be its own resource-exhaustion
	// bug.
	screenshotSem chan struct{}

	// techSem bounds how many technology-fingerprint -> CVE lookups
	// (lookupTechCVEs in identify.go) run concurrently across the whole
	// server -- each one may call out to the rate-limited NVD API, so
	// fanning one out per discovered host unbounded would just make every
	// one of them queue behind NVD's own rate limit anyway.
	techSem chan struct{}
}

// maxConcurrentScreenshots is screenshotSem's capacity.
const maxConcurrentScreenshots = 4

// maxConcurrentTechLookups is techSem's capacity.
const maxConcurrentTechLookups = 4

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
		jobCancels:    map[string]context.CancelFunc{},
		screenshotSem: make(chan struct{}, maxConcurrentScreenshots),
		techSem:       make(chan struct{}, maxConcurrentTechLookups),
	}

	// Login (and its own probe, handleMe, and logout) are the only
	// /api routes reachable without a session -- every other one below is
	// wrapped in requireAuth. Logout doesn't need a *valid* session (it
	// just deletes whatever cookie is presented, if any), so it's left
	// unwrapped too rather than 401ing a client whose session already
	// expired but who's just trying to clear its cookie.
	s.mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/auth/logout", s.handleLogout)
	s.mux.HandleFunc("GET /api/auth/me", s.requireAuth(s.handleMe))

	s.mux.HandleFunc("GET /api/tools", s.requireAuth(s.handleListTools))

	s.mux.HandleFunc("GET /api/settings", s.requireAuth(s.handleGetSettings))
	s.mux.HandleFunc("PUT /api/settings/dnsdumpster-key", s.requireAuth(s.handleSetDNSDumpsterKey))
	s.mux.HandleFunc("PUT /api/settings/nvd-key", s.requireAuth(s.handleSetNVDKey))

	s.mux.HandleFunc("POST /api/cases", s.requireAuth(s.handleStartCase))
	s.mux.HandleFunc("GET /api/cases", s.requireAuth(s.handleListCases))
	s.mux.HandleFunc("GET /api/cases/{id}", s.requireAuth(s.handleGetCase))
	s.mux.HandleFunc("DELETE /api/cases/{id}", s.requireAuth(s.handleDeleteCase))
	s.mux.HandleFunc("GET /api/cases/{id}/checks", s.requireAuth(s.handleListCaseChecks))
	s.mux.HandleFunc("GET /api/cases/{id}/report", s.requireAuth(s.handleCaseReport))
	s.mux.HandleFunc("GET /api/cases/{id}/screenshots", s.requireAuth(s.handleListCaseScreenshots))
	s.mux.HandleFunc("GET /api/cases/{id}/screenshots/{target}", s.requireAuth(s.handleGetCaseScreenshot))

	s.mux.HandleFunc("GET /api/cases/{id}/targets", s.requireAuth(s.handleListTargets))
	s.mux.HandleFunc("POST /api/cases/{id}/targets", s.requireAuth(s.handleAddTarget))
	s.mux.HandleFunc("POST /api/cases/{id}/targets/promote", s.requireAuth(s.handlePromoteTargets))
	s.mux.HandleFunc("DELETE /api/targets/{id}", s.requireAuth(s.handleDeleteTarget))

	s.mux.HandleFunc("GET /api/cases/{id}/jobs", s.requireAuth(s.handleListCaseJobs))
	s.mux.HandleFunc("POST /api/cases/{id}/jobs", s.requireAuth(s.handleStartJob))
	s.mux.HandleFunc("GET /api/jobs/{id}", s.requireAuth(s.handleGetJob))
	s.mux.HandleFunc("POST /api/jobs/{id}/cancel", s.requireAuth(s.handleCancelJob))
	s.mux.HandleFunc("GET /ws/jobs/{id}", s.requireAuth(s.handleWatchJob))

	s.mux.HandleFunc("GET /api/wordlists", s.requireAuth(s.handleListWordlists))
	s.mux.HandleFunc("GET /api/wordlists/catalog", s.requireAuth(s.handleWordlistCatalog))
	s.mux.HandleFunc("POST /api/wordlists/download", s.requireAuth(s.handleDownloadWordlist))
	s.mux.HandleFunc("DELETE /api/wordlists/{name}", s.requireAuth(s.handleDeleteWordlist))
	s.mux.HandleFunc("PATCH /api/wordlists/{name}/categories", s.requireAuth(s.handleSetWordlistCategories))
	s.mux.HandleFunc("POST /api/wordlists/{name}/duplicate", s.requireAuth(s.handleDuplicateWordlist))

	s.mux.HandleFunc("GET /api/runs/{id}", s.requireAuth(s.handleGetRun))
	s.mux.HandleFunc("GET /api/runs/{id}/findings", s.requireAuth(s.handleListFindings))

	s.mux.HandleFunc("POST /api/jwt/scan", s.requireAuth(s.handleJWTScan))

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
