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
	"strings"
	"sync"

	"github.com/Indigo6415/Aperture/internal/adapters"
	"github.com/Indigo6415/Aperture/internal/collaborator"
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
	cancelMu    sync.Mutex
	jobCancels  map[string]context.CancelFunc
	scanCancels map[string]context.CancelFunc

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

	// probeMu guards pendingProbeScans: a probe scan is registered here by
	// handleProbeScan and only actually started once handleWatchProbeScan's
	// client subscribes to its hub channel (see runProbeScan) -- otherwise
	// a fast scan against a responsive target could finish, and every
	// "module" event with it, before the frontend's WebSocket connection
	// even completes its handshake.
	probeMu           sync.Mutex
	pendingProbeScans map[string]pendingProbeScan

	// domainScanMu/pendingDomainScans is domain scan's counterpart to
	// probeMu/pendingProbeScans above -- same registered-but-unclaimed
	// pattern, same reason (see handleDomainScan in
	// handlers_domainscan.go).
	domainScanMu       sync.Mutex
	pendingDomainScans map[string]pendingDomainScan

	// apiEnumMu/pendingApiEnumScans is the API enumerator's counterpart to
	// probeMu/pendingProbeScans above -- same registered-but-unclaimed
	// pattern, same reason (see handleApiEnumScan in
	// handlers_apienum.go).
	apiEnumMu           sync.Mutex
	pendingApiEnumScans map[string]pendingApiEnumScan

	// streamMu/pendingScans is the shared registry for every scanner that
	// streams per-check progress (see scan_stream.go). Same registered-
	// but-unclaimed pattern as the per-tool maps above, one map for all of
	// them since the claim/run/publish shape is identical.
	streamMu     sync.Mutex
	pendingScans map[string]streamedScan

	// collab is the shared out-of-band interaction listener backing
	// /api/collaborator/* and the unauthenticated /collab/{token} callback
	// route -- see internal/collaborator's package doc comment and
	// handlers_collaborator.go. collabMu guards collabDNSStop, the running
	// DNS listener's stop func (nil when it isn't running, e.g. no domain
	// has been configured yet, or the bind itself failed).
	collab        *collaborator.Registry
	collabMu      sync.Mutex
	collabDNSStop func()
	// collabListenAddr is the -collab-addr the callback listener binds, used
	// to build callback URLs when no callbackBase is configured.
	collabListenAddr string
}

// SetCollabListenAddr records the address the callback-only listener binds
// (see CallbackHandler), so callback URLs point at its port.
func (s *Server) SetCollabListenAddr(addr string) { s.collabListenAddr = addr }

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
		store:               st,
		engine:              eng,
		hub:                 newHub(),
		mux:                 http.NewServeMux(),
		wordlistsDir:        wordlistsDir,
		jobCancels:          map[string]context.CancelFunc{},
		scanCancels:         map[string]context.CancelFunc{},
		screenshotSem:       make(chan struct{}, maxConcurrentScreenshots),
		techSem:             make(chan struct{}, maxConcurrentTechLookups),
		pendingProbeScans:   map[string]pendingProbeScan{},
		pendingDomainScans:  map[string]pendingDomainScan{},
		pendingApiEnumScans: map[string]pendingApiEnumScan{},
		pendingScans:        map[string]streamedScan{},
		collab:              collaborator.NewRegistry(),
	}

	// Every HTTP exchange a source node makes is kept in the request log under
	// its run and node, so "Inspect requests" can show it after the scan.
	eng.SetExchangeSink(requestLogSink(st))

	// Resume the DNS listener across a restart if it was previously
	// configured -- best-effort, same posture as every other background
	// setup in this constructor: a bind failure here (e.g. the process no
	// longer has the privilege it once did) is logged, not fatal, since the
	// HTTP half of the collaborator listener works regardless.
	if cfg := s.loadCollaboratorConfig(); cfg.Domain != "" && cfg.AnswerIP != "" {
		if err := s.startCollabDNSLocked(cfg); err != nil {
			log.Printf("collaborator: DNS listener not started: %v", err)
		}
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
	s.mux.HandleFunc("PUT /api/settings/hibp-key", s.requireAuth(s.handleSetHIBPKey))

	s.mux.HandleFunc("POST /api/cases", s.requireAuth(s.handleStartCase))
	s.mux.HandleFunc("GET /api/cases", s.requireAuth(s.handleListCases))
	s.mux.HandleFunc("GET /api/cases/{id}", s.requireAuth(s.handleGetCase))
	s.mux.HandleFunc("DELETE /api/cases/{id}", s.requireAuth(s.handleDeleteCase))
	s.mux.HandleFunc("GET /api/cases/{id}/checks", s.requireAuth(s.handleListCaseChecks))
	s.mux.HandleFunc("GET /api/cases/{id}/report", s.requireAuth(s.handleCaseReport))
	s.mux.HandleFunc("GET /api/cases/{id}/screenshots", s.requireAuth(s.handleListCaseScreenshots))
	s.mux.HandleFunc("GET /api/cases/{id}/screenshots/{target}", s.requireAuth(s.handleGetCaseScreenshot))
	s.mux.HandleFunc("GET /api/cases/{id}/scans", s.requireAuth(s.handleListCaseScans))
	s.mux.HandleFunc("GET /api/scans/{id}", s.requireAuth(s.handleGetCaseScan))
	s.mux.HandleFunc("POST /api/scans/{id}/cancel", s.requireAuth(s.handleCancelScan))

	s.mux.HandleFunc("GET /api/cases/{id}/credentials", s.requireAuth(s.handleListCredentials))
	s.mux.HandleFunc("POST /api/cases/{id}/credentials", s.requireAuth(s.handleAddCredential))
	s.mux.HandleFunc("DELETE /api/credentials/{id}", s.requireAuth(s.handleDeleteCredential))
	s.mux.HandleFunc("POST /api/credentials/{id}/session", s.requireAuth(s.handleCreateCredentialSession))

	s.mux.HandleFunc("GET /api/cases/{id}/cookie-vault", s.requireAuth(s.handleListCookieVault))
	s.mux.HandleFunc("PUT /api/cases/{id}/cookie-vault/{domain}", s.requireAuth(s.handleSetCookieVaultEntry))

	s.mux.HandleFunc("GET /api/job-templates", s.requireAuth(s.handleListJobTemplates))
	s.mux.HandleFunc("POST /api/job-templates", s.requireAuth(s.handleSaveJobTemplate))
	s.mux.HandleFunc("DELETE /api/job-templates/{id}", s.requireAuth(s.handleDeleteJobTemplate))

	s.mux.HandleFunc("GET /api/cases/{id}/targets", s.requireAuth(s.handleListTargets))
	s.mux.HandleFunc("POST /api/cases/{id}/targets", s.requireAuth(s.handleAddTarget))
	s.mux.HandleFunc("POST /api/cases/{id}/targets/promote", s.requireAuth(s.handlePromoteTargets))
	s.mux.HandleFunc("DELETE /api/targets/{id}", s.requireAuth(s.handleDeleteTarget))
	s.mux.HandleFunc("GET /api/cases/{id}/target-lists", s.requireAuth(s.handleListTargetLists))
	s.mux.HandleFunc("POST /api/cases/{id}/target-lists", s.requireAuth(s.handleCreateTargetList))
	s.mux.HandleFunc("PATCH /api/target-lists/{id}", s.requireAuth(s.handleRenameTargetList))
	s.mux.HandleFunc("DELETE /api/target-lists/{id}", s.requireAuth(s.handleDeleteTargetList))
	s.mux.HandleFunc("POST /api/target-lists/{id}/ping", s.requireAuth(s.handlePingTargetList))

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
	s.mux.HandleFunc("POST /api/wordlists/{name}/rename", s.requireAuth(s.handleRenameWordlist))

	s.mux.HandleFunc("GET /api/runs/{id}", s.requireAuth(s.handleGetRun))
	s.mux.HandleFunc("GET /api/runs/{id}/findings", s.requireAuth(s.handleListFindings))
	s.mux.HandleFunc("PATCH /api/findings/{id}/triage", s.requireAuth(s.handleUpdateFindingTriage))
	s.mux.HandleFunc("GET /api/runs/{id}/nodes/{nodeId}/requests", s.requireAuth(s.handleListNodeRequests))
	s.mux.HandleFunc("GET /api/runs/{id}/nodes/{nodeId}/requests/{requestId}", s.requireAuth(s.handleGetNodeRequest))

	s.mux.HandleFunc("POST /api/jwt/scan", s.requireAuth(s.handleJWTScan))
	s.mux.HandleFunc("GET /api/probe/modules", s.requireAuth(s.handleProbeModules))
	s.mux.HandleFunc("POST /api/probe/scan", s.requireAuth(s.handleProbeScan))
	s.mux.HandleFunc("GET /ws/probe/{id}", s.requireAuth(s.handleWatchProbeScan))

	s.mux.HandleFunc("GET /api/domainscan/modules", s.requireAuth(s.handleDomainScanModules))
	s.mux.HandleFunc("POST /api/domainscan/scan", s.requireAuth(s.handleDomainScan))
	s.mux.HandleFunc("GET /ws/domainscan/{id}", s.requireAuth(s.handleWatchDomainScan))

	s.mux.HandleFunc("POST /api/apienum/scan", s.requireAuth(s.handleApiEnumScan))
	s.mux.HandleFunc("GET /ws/apienum/{id}", s.requireAuth(s.handleWatchApiEnumScan))

	// Shared streaming route for every scanner that reports per-check
	// progress (see scan_stream.go) -- each POST /api/<tool>/scan registers
	// its scan here and hands back the ID this route is watched by.
	s.mux.HandleFunc("GET /ws/scans/{id}", s.requireAuth(s.handleWatchScan))

	s.mux.HandleFunc("POST /api/secrets/scan", s.requireAuth(s.handleSecretScan))
	s.mux.HandleFunc("POST /api/breach/check", s.requireAuth(s.handleBreachCheck))
	s.mux.HandleFunc("POST /api/breach/crawl-emails", s.requireAuth(s.handleBreachCrawlEmails))
	s.mux.HandleFunc("POST /api/bypass403/run", s.requireAuth(s.handleBypass403))
	s.mux.HandleFunc("POST /api/pwreset/scan", s.requireAuth(s.handlePwReset))
	s.mux.HandleFunc("POST /api/graphqlenum/scan", s.requireAuth(s.handleGraphQLEnum))
	s.mux.HandleFunc("POST /api/corsscan/scan", s.requireAuth(s.handleCORSScan))
	s.mux.HandleFunc("POST /api/openredirect/scan", s.requireAuth(s.handleOpenRedirect))
	s.mux.HandleFunc("POST /api/ssrf/scan", s.requireAuth(s.handleSSRF))
	s.mux.HandleFunc("POST /api/csrf/scan", s.requireAuth(s.handleCSRF))
	s.mux.HandleFunc("POST /api/xss/scan", s.requireAuth(s.handleXSSScan))
	s.mux.HandleFunc("POST /api/sstiscan/scan", s.requireAuth(s.handleSSTIScan))
	s.mux.HandleFunc("POST /api/pathtraversal/scan", s.requireAuth(s.handlePathTraversal))
	s.mux.HandleFunc("POST /api/xxe/scan", s.requireAuth(s.handleXXE))

	s.mux.HandleFunc("POST /api/tester/send", s.requireAuth(s.handleTesterSend))

	// The collaborator's own config/token/poll endpoints need a session
	// (they're Aperture's own UI talking to itself), but the callback route
	// below deliberately doesn't -- see handleCollaboratorCallback.
	s.mux.HandleFunc("GET /api/collaborator/config", s.requireAuth(s.handleGetCollaboratorConfig))
	s.mux.HandleFunc("GET /api/collaborator/addresses", s.requireAuth(s.handleCollaboratorAddresses))
	s.mux.HandleFunc("GET /api/collaborator/tls", s.requireAuth(s.handleGetCollabTLS))
	s.mux.HandleFunc("PUT /api/collaborator/tls", s.requireAuth(s.handleSetCollabTLS))
	s.mux.HandleFunc("POST /api/collaborator/tls/regenerate", s.requireAuth(s.handleRegenerateCollabTLS))
	s.mux.HandleFunc("PUT /api/collaborator/config", s.requireAuth(s.handleSetCollaboratorConfig))
	s.mux.HandleFunc("POST /api/collaborator/new", s.requireAuth(s.handleCollaboratorNew))
	s.mux.HandleFunc("GET /api/collaborator/poll", s.requireAuth(s.handleCollaboratorPoll))
	s.mux.HandleFunc("GET /api/collaborator/active", s.requireAuth(s.handleListActiveCallbackServers))
	s.mux.HandleFunc("DELETE /api/collaborator/active", s.requireAuth(s.handleRemoveActiveCallbackServer))
	s.mux.HandleFunc("POST /api/collaborator/webhooksite/new", s.requireAuth(s.handleWebhookSiteNew))
	s.mux.HandleFunc("GET /api/collaborator/webhooksite/poll", s.requireAuth(s.handleWebhookSitePoll))

	if uiFS != nil {
		s.mux.Handle("/", spaHandler(uiFS))
	}

	return s
}

// maxRequestBody caps how many bytes any request body may send. Every JSON
// endpoint decodes straight from r.Body, so without a cap one oversized POST
// could make the server buffer unbounded memory. No endpoint takes uploads
// (no multipart handling anywhere), so one ceiling covers them all.
const maxRequestBody = 10 << 20

// Handler returns the full HTTP handler: the route mux, wrapped so every
// request body is capped at maxRequestBody.
func (s *Server) Handler() http.Handler {
	return withLogging(limitBody(s.mux))
}

// limitBody wraps next so each request body is read through
// http.MaxBytesReader. Reads past maxRequestBody fail, and the server closes
// the connection rather than buffering the rest.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		}
		next.ServeHTTP(w, r)
	})
}

// CallbackHandler serves only the unauthenticated /collab/{token} routes, on
// its own mux. main runs it on a separate listener (see -collab-addr) that can
// bind a LAN/public interface, so targets and the internet can reach callbacks
// without exposing the login-protected UI and API on that same interface.
// Everything else 404s.
func (s *Server) CallbackHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/collab/{token}", s.handleCollaboratorCallback)
	mux.HandleFunc("/collab/{token}/{path...}", s.handleCollaboratorCallback)
	return withLogging(mux)
}

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
		// A missing file is only an error if it exists on disk; anything else
		// (a deleted API route, a stale hashed bundle) is a real miss.
		if _, err := fs.Stat(uiFS, trimLeadingSlash(cleaned)); err != nil {
			if os.IsNotExist(err) {
				// Backend and asset paths must 404 instead of falling back: an
				// index.html reply with status 200 is what the frontend then tries
				// to parse as JSON or run as a module, which fails with no clear cause.
				if isBackendPath(cleaned) {
					http.NotFound(w, r)
					return
				}
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

// isBackendPath reports whether a cleaned request path belongs to the API or
// the built asset tree, which are never client-side routes and so must never
// receive the SPA index.html fallback.
func isBackendPath(cleaned string) bool {
	return cleaned == "/api" || strings.HasPrefix(cleaned, "/api/") || strings.HasPrefix(cleaned, "/assets/")
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
	out := make([]toolInfo, 0, len(adapters.Registry)+1)
	for name := range adapters.Registry {
		_, err := exec.LookPath(name)
		out = append(out, toolInfo{Name: name, Available: err == nil})
	}
	// retire.js isn't an adapters.Registry entry -- it's driven by
	// internal/domainscan, not the node-graph engine -- but it's still an
	// external binary the frontend should be able to check for, same as
	// every tool above.
	_, retireErr := exec.LookPath("retire")
	out = append(out, toolInfo{Name: "retire", Available: retireErr == nil})
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
