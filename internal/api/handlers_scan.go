package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Indigo6415/Aperture/internal/adapters"
	"github.com/Indigo6415/Aperture/internal/engine"
	"github.com/Indigo6415/Aperture/internal/recon"
	"github.com/Indigo6415/Aperture/internal/store"
	"github.com/Indigo6415/Aperture/internal/wordlists"
)

// nucleiMaxTargets caps how many content-discovery hits get handed to the
// auto-kicked vuln-scan (see maybeChainVulnScan) -- a content-discovery run
// against a big wordlist can turn up thousands of URLs, and running every
// nuclei template against all of them would take far longer than the scan
// itself; capping keeps the follow-up scan proportionate.
const nucleiMaxTargets = 300

type startScanRequest struct {
	Domain  string             `json:"domain"`
	Options engine.ScanOptions `json:"options,omitempty"`
}

// handleStartScan is the entry point for the dashboard's single domain
// input: it creates a scan record and immediately returns, then runs the
// recon checks and every auto-generated scanner (content discovery,
// subdomain bruteforce, vhost bruteforce, port scan) in the background,
// streamed to the client over GET /ws/scans/{id}.
func (s *Server) handleStartScan(w http.ResponseWriter, r *http.Request) {
	var req startScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	domain, err := recon.NormalizeDomain(req.Domain)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	optionsJSON, err := json.Marshal(req.Options)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	scanID := newID()
	if err := s.store.CreateScan(scanID, domain, string(optionsJSON)); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	go s.runScan(scanID, domain)

	writeJSON(w, http.StatusAccepted, map[string]string{"scanId": scanID})
}

// scanOptionsOf decodes a scan's stored per-scan tuning (see ScanOptions),
// resolved against its preset -- a scan created before this existed, or
// with no options passed, gets the zero value's fallback-to-tool-defaults
// behavior unchanged.
func scanOptionsOf(sc store.Scan) engine.ScanOptions {
	var opts engine.ScanOptions
	if sc.Options != "" {
		_ = json.Unmarshal([]byte(sc.Options), &opts)
	}
	return opts.Resolved()
}

// newTargets filters requested down to hostnames not already claimed by a
// running-or-succeeded scan_runs row of kind for this scan (see
// store.CoveredTargets) -- so "Scan selected", an auto-kicked scanner, and a
// full scan restart never re-launch a scanner subprocess against a target
// that's already being (or has already been) scanned. Order is preserved
// and requested is deduped case-insensitively (hostnames aren't case
// sensitive).
func (s *Server) newTargets(scanID string, kind store.ScanKind, requested []string) ([]string, error) {
	covered, err := s.store.CoveredTargets(scanID, kind)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(requested))
	for _, t := range requested {
		key := strings.ToLower(t)
		if seen[key] || covered[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
	}
	return out, nil
}

// runScan drives one domain scan end to end: it streams each recon.Check as
// it completes, then -- once the apex HTTP check has revealed which scheme
// the domain responds on -- kicks off every auto-generated scanner, each its
// own flow+run so the frontend can watch/display them as independent
// scanner tabs: content discovery (ffuf+feroxbuster against the apex
// domain), subdomain bruteforce (ffuf against FUZZ.<domain>, complementing
// recon.Scan's passive crt.sh discovery), virtual-host bruteforce (ffuf
// against the apex IP with a fuzzed Host header, skipped if the apex has no
// A record), and port scan (nmap against the apex IP). Every scanner is
// skipped if it's already running or has already completed against the
// same target (see newTargets/store.KindRunning) -- this function backs
// both a brand new scan and "Restart scan", and a restart shouldn't spawn a
// redundant second copy of work already done or in flight. All of them
// reuse the existing engine/adapters/store/hub machinery unchanged.
func (s *Server) runScan(scanID, domain string) {
	ctx, cancel := context.WithCancel(context.Background())
	s.trackScanCancel(scanID, cancel)
	defer func() {
		s.untrackScanCancel(scanID)
		cancel()
	}()

	// The apex A record (needed to target vhost bruteforce/port scan) is
	// buried inside whichever Check carries the DNS data; capture it as
	// checks stream by rather than re-resolving it separately. Guarded by mu
	// since onCheck fires concurrently from several goroutines.
	var mu sync.Mutex
	var apexA []string
	onCheck := func(c recon.Check) {
		if c.Domain == domain && c.Kind == recon.KindDNS && c.Status == recon.StatusDone {
			if a, ok := c.Data["a"].([]string); ok {
				mu.Lock()
				apexA = a
				mu.Unlock()
			}
		}
		// A completed HTTP check reveals a live URL for whatever host it
		// ran against (apex or, via fanOutSubdomains, a discovered
		// subdomain) -- opportunistically capture a screenshot of it.
		// captureScreenshot itself skips hosts it's already shot, so a
		// restart re-observing the same host is cheap.
		if c.Kind == recon.KindHTTP && c.Status == recon.StatusDone {
			if finalURL, ok := c.Data["finalUrl"].(string); ok && finalURL != "" {
				go s.captureScreenshot(scanID, c.Domain, finalURL)
			}
		}
		if err := s.store.SaveCheck(scanID, c); err != nil {
			// The check is still delivered live below even if persisting it
			// failed, so a slow/broken disk doesn't stall the scan.
			s.hub.publish(scanID, RunEvent{Type: "check", Check: &c, Message: "warning: failed to persist check: " + err.Error()})
			return
		}
		s.hub.publish(scanID, RunEvent{Type: "check", Check: &c})
	}

	scheme, _ := recon.Scan(ctx, domain, onCheck)
	if err := s.store.SetScanScheme(scanID, scheme); err != nil {
		s.hub.publish(scanID, RunEvent{Type: "done", Message: "warning: failed to persist scheme: " + err.Error()})
	}

	// A cancelled scan skips kicking off its scanners entirely -- there's
	// nothing left to fan out from, and any that already started have their
	// own runCancels entries which handleCancelScan cancels independently.
	if ctx.Err() != nil {
		s.hub.publish(scanID, RunEvent{Type: "done", Message: "scan cancelled"})
		return
	}

	sc, err := s.store.GetScan(scanID)
	if err != nil {
		s.hub.publish(scanID, RunEvent{Type: "done", Message: "failed to load scan options: " + err.Error()})
		return
	}
	opts := scanOptionsOf(sc)

	type scanner struct {
		kind    store.ScanKind
		flow    engine.Flow
		targets []string
	}
	var scanners []scanner

	if cdTargets, err := s.newTargets(scanID, store.ScanKindContentDiscovery, []string{domain}); err == nil && len(cdTargets) > 0 {
		scanners = append(scanners, scanner{store.ScanKindContentDiscovery, s.buildContentDiscoveryFlow(domain, scheme, cdTargets, opts), cdTargets})
	}

	if running, err := s.store.KindRunning(scanID, store.ScanKindSubdomainBruteforce); err == nil && !running {
		if sbTargets, err := s.newTargets(scanID, store.ScanKindSubdomainBruteforce, []string{domain}); err == nil && len(sbTargets) > 0 {
			scanners = append(scanners, scanner{store.ScanKindSubdomainBruteforce, s.buildSubdomainBruteforceFlow(domain, scheme, opts), sbTargets})
		}
	}

	if len(apexA) > 0 {
		if running, err := s.store.KindRunning(scanID, store.ScanKindVHostBruteforce); err == nil && !running {
			if vhTargets, err := s.newTargets(scanID, store.ScanKindVHostBruteforce, []string{apexA[0]}); err == nil && len(vhTargets) > 0 {
				scanners = append(scanners, scanner{store.ScanKindVHostBruteforce, s.buildVHostBruteforceFlow(domain, scheme, apexA[0], opts), vhTargets})
			}
		}
		if psTargets, err := s.newTargets(scanID, store.ScanKindPortScan, []string{apexA[0]}); err == nil && len(psTargets) > 0 {
			scanners = append(scanners, scanner{store.ScanKindPortScan, s.buildPortScanFlow(domain, apexA[0]), psTargets})
		}
	}

	for _, sc := range scanners {
		if _, err := s.startScanRun(scanID, sc.kind, sc.flow, sc.targets); err != nil {
			s.hub.publish(scanID, RunEvent{Type: "done", Message: "failed to start " + string(sc.kind) + " run: " + err.Error()})
		}
	}

	s.hub.publish(scanID, RunEvent{Type: "done"})
}

// startScanRun saves flow, creates its run + scan_run rows (recording
// targets so later callers can tell what this run already covers -- see
// newTargets), tells any watching client (over the scan's own event stream)
// that this scanner's flow/run now exists so it can open
// GET /ws/runs/{runId}, and kicks off execution in the background. Used by
// runScan (every scanner a fresh scan or restart starts),
// handleRestartScanRun (redoing just one), handleScanContentDiscovery (an
// additional content-discovery run against a new target selection), and
// maybeChainVulnScan (nuclei against a finished content-discovery run's
// hits) -- every one of them is just "start one more scanner run for this
// scan", so they all funnel through here instead of repeating this
// plumbing.
func (s *Server) startScanRun(scanID string, kind store.ScanKind, flow engine.Flow, targets []string) (runID string, err error) {
	flow.ID = newID()
	if err := s.store.SaveFlow(flow); err != nil {
		return "", fmt.Errorf("save flow: %w", err)
	}
	runID = newID()
	if err := s.store.CreateRun(runID, flow.ID); err != nil {
		return "", fmt.Errorf("create run: %w", err)
	}
	if err := s.store.CreateScanRun(scanID, kind, flow.ID, runID, targets); err != nil {
		s.hub.publish(scanID, RunEvent{Type: "done", Message: "warning: failed to link scan run: " + err.Error()})
	}
	s.hub.publish(scanID, RunEvent{Type: "scanRun", Kind: string(kind), FlowID: flow.ID, RunID: runID})
	// Each scanner runs independently and concurrently; the caller's own
	// event stream doesn't wait on it.
	go s.executeRun(flow, runID)
	return runID, nil
}

// resolveWordlist returns opts.Wordlist (an explicit filename the user
// chose for this scan) when set, otherwise falls back to whatever's tagged
// cat -- the same category-based selection every scanner used before
// per-scan tuning existed.
func (s *Server) resolveWordlist(opts engine.ScanOptions, cat wordlists.Category, fallback string) string {
	if opts.Wordlist != "" {
		return filepath.Join(s.wordlistsDir, opts.Wordlist)
	}
	path, err := wordlists.CombinedForCategory(s.wordlistsDir, cat, fallback)
	if err != nil {
		return filepath.Join(s.wordlistsDir, fallback)
	}
	return path
}

// buildContentDiscoveryFlow assembles a content-discovery pipeline: one
// ffuf+feroxbuster pair per target host, merged with dedup into one live
// results table. Used both for a scan's initial apex-only auto-run and for
// a later "scan selected subdomains" run (see handleScanContentDiscovery)
// -- it's just an engine.Flow like any other, so it reuses the engine,
// adapters, store, and hub without any changes to that machinery.
func (s *Server) buildContentDiscoveryFlow(domain, scheme string, targets []string, opts engine.ScanOptions) engine.Flow {
	wordlistPath := s.resolveWordlist(opts, wordlists.CategoryDirectories, wordlists.DefaultName)
	extensions, _ := wordlists.ExtensionsForCategory(s.wordlistsDir)

	nodes := make([]engine.Node, 0, len(targets)*2+2)
	edges := make([]engine.Edge, 0, len(targets)*2+1)
	y := 40.0
	for i, target := range targets {
		base := scheme + "://" + target
		ffufID := fmt.Sprintf("ffuf-%d", i)
		feroxID := fmt.Sprintf("feroxbuster-%d", i)

		ffufCfg, _ := json.Marshal(adapters.FFufConfig{
			URL: base + "/FUZZ", Wordlist: wordlistPath, Extensions: extensions,
			Threads: opts.Threads, Timeout: opts.TimeoutSeconds, RateLimit: opts.RateLimit,
		})
		feroxCfg, _ := json.Marshal(adapters.FeroxbusterConfig{
			URL: base + "/", Wordlist: wordlistPath, Extensions: extensions,
			Threads: opts.Threads, Timeout: opts.TimeoutSeconds, RateLimit: opts.RateLimit,
		})

		nodes = append(nodes,
			engine.Node{ID: ffufID, Kind: engine.KindFFuf, Label: "ffuf: " + target, Config: ffufCfg, Position: &engine.Position{X: 40, Y: y}},
			engine.Node{ID: feroxID, Kind: engine.KindFeroxbuster, Label: "feroxbuster: " + target, Config: feroxCfg, Position: &engine.Position{X: 40, Y: y + 80}},
		)
		edges = append(edges,
			engine.Edge{ID: "e-" + ffufID + "-merge", From: ffufID, To: "merge"},
			engine.Edge{ID: "e-" + feroxID + "-merge", From: feroxID, To: "merge"},
		)
		y += 200
	}

	mergeCfg, _ := json.Marshal(engine.MergeConfig{Dedup: true})
	nodes = append(nodes,
		engine.Node{ID: "merge", Kind: engine.KindMerge, Label: "merge", Config: mergeCfg, Position: &engine.Position{X: 340, Y: 120}},
		engine.Node{ID: "table", Kind: engine.KindTable, Label: "results", Position: &engine.Position{X: 600, Y: 120}},
	)
	edges = append(edges, engine.Edge{ID: "e-merge-table", From: "merge", To: "table"})

	return engine.Flow{Name: "Content discovery: " + domain, Nodes: nodes, Edges: edges}
}

// buildSubdomainBruteforceFlow actively bruteforces subdomains by fuzzing
// the hostname itself (scheme://FUZZ.domain/) with ffuf, complementing the
// passive crt.sh discovery recon.Scan already does. Autocalibration filters
// out a wildcard-DNS catch-all answering every hostname identically.
func (s *Server) buildSubdomainBruteforceFlow(domain, scheme string, opts engine.ScanOptions) engine.Flow {
	wordlistPath := s.resolveWordlist(opts, wordlists.CategorySubdomains, wordlists.SubdomainsDefaultName)
	cfg, _ := json.Marshal(adapters.FFufConfig{
		URL: scheme + "://FUZZ." + domain + "/", Wordlist: wordlistPath, AutoCalibrate: true,
		Threads: opts.Threads, Timeout: opts.TimeoutSeconds, RateLimit: opts.RateLimit,
	})
	return engine.Flow{
		Name: "Subdomain bruteforce: " + domain,
		Nodes: []engine.Node{
			{ID: "ffuf", Kind: engine.KindFFuf, Label: "ffuf", Config: cfg, Position: &engine.Position{X: 40, Y: 40}},
			{ID: "table", Kind: engine.KindTable, Label: "results", Position: &engine.Position{X: 340, Y: 40}},
		},
		Edges: []engine.Edge{{ID: "e-ffuf-table", From: "ffuf", To: "table"}},
	}
}

// buildVHostBruteforceFlow fuzzes the Host header against the apex
// domain's IP to find virtual hosts sharing that IP but invisible via
// public DNS. Autocalibration is essential here: the default vhost answers
// every Host header tried with a near-identical response, and -ac is
// ffuf's built-in filter for exactly that.
func (s *Server) buildVHostBruteforceFlow(domain, scheme, ip string, opts engine.ScanOptions) engine.Flow {
	wordlistPath := s.resolveWordlist(opts, wordlists.CategorySubdomains, wordlists.SubdomainsDefaultName)
	cfg, _ := json.Marshal(adapters.FFufConfig{
		URL: scheme + "://" + ip + "/", Wordlist: wordlistPath, Headers: map[string]string{"Host": "FUZZ." + domain}, AutoCalibrate: true,
		Threads: opts.Threads, Timeout: opts.TimeoutSeconds, RateLimit: opts.RateLimit,
	})
	return engine.Flow{
		Name: "Virtual host bruteforce: " + domain,
		Nodes: []engine.Node{
			{ID: "ffuf", Kind: engine.KindFFuf, Label: "ffuf", Config: cfg, Position: &engine.Position{X: 40, Y: 40}},
			{ID: "table", Kind: engine.KindTable, Label: "results", Position: &engine.Position{X: 340, Y: 40}},
		},
		Edges: []engine.Edge{{ID: "e-ffuf-table", From: "ffuf", To: "table"}},
	}
}

// buildPortScanFlow runs nmap against the apex domain's IP as another
// auto-kicked scanner, extending recon beyond HTTP(S) to raw open
// ports/services.
func (s *Server) buildPortScanFlow(domain, ip string) engine.Flow {
	cfg, _ := json.Marshal(adapters.NmapConfig{Target: ip})
	return engine.Flow{
		Name: "Port scan: " + domain,
		Nodes: []engine.Node{
			{ID: "nmap", Kind: engine.KindNmap, Label: "nmap", Config: cfg, Position: &engine.Position{X: 40, Y: 40}},
			{ID: "table", Kind: engine.KindTable, Label: "results", Position: &engine.Position{X: 340, Y: 40}},
		},
		Edges: []engine.Edge{{ID: "e-nmap-table", From: "nmap", To: "table"}},
	}
}

// buildVulnScanFlow runs nuclei against a set of already-discovered URLs
// (see maybeChainVulnScan) to flag known CVEs/misconfigurations on top of
// the raw status/size data those URLs were found with.
func (s *Server) buildVulnScanFlow(domain string, targets []string) engine.Flow {
	cfg, _ := json.Marshal(adapters.NucleiConfig{Targets: targets})
	return engine.Flow{
		Name: "Vulnerability scan: " + domain,
		Nodes: []engine.Node{
			{ID: "nuclei", Kind: engine.KindNuclei, Label: "nuclei", Config: cfg, Position: &engine.Position{X: 40, Y: 40}},
			{ID: "table", Kind: engine.KindTable, Label: "results", Position: &engine.Position{X: 340, Y: 40}},
		},
		Edges: []engine.Edge{{ID: "e-nuclei-table", From: "nuclei", To: "table"}},
	}
}

// maybeChainVulnScan is called (from executeRun in handlers.go) every time
// a run finishes successfully. If it was a content-discovery run, its hits
// become the target list for an auto-kicked vuln-scan -- capped at
// nucleiMaxTargets and, as with every other scanner, filtered down to URLs
// not already covered by a running-or-succeeded vuln-scan so re-finishing
// an overlapping content-discovery run doesn't re-launch nuclei against the
// same URLs. Any other kind, or a content-discovery run with nothing new to
// hand off, is a no-op.
func (s *Server) maybeChainVulnScan(runID string) {
	ref, err := s.store.GetScanRunByRunID(runID)
	if err != nil || ref.Kind != store.ScanKindContentDiscovery {
		return
	}
	findings, err := s.store.ListFindings(runID, "table")
	if err != nil || len(findings) == 0 {
		return
	}

	seen := map[string]bool{}
	urls := make([]string, 0, len(findings))
	for _, f := range findings {
		if seen[f.URL] {
			continue
		}
		seen[f.URL] = true
		urls = append(urls, f.URL)
		if len(urls) >= nucleiMaxTargets {
			break
		}
	}

	newURLs, err := s.newTargets(ref.ScanID, store.ScanKindVulnScan, urls)
	if err != nil || len(newURLs) == 0 {
		return
	}

	sc, err := s.store.GetScan(ref.ScanID)
	if err != nil {
		return
	}
	flow := s.buildVulnScanFlow(sc.Domain, newURLs)
	if _, err := s.startScanRun(ref.ScanID, store.ScanKindVulnScan, flow, newURLs); err != nil {
		s.hub.publish(ref.ScanID, RunEvent{Type: "done", Message: "failed to start vuln-scan run: " + err.Error()})
	}
}

type contentDiscoveryRequest struct {
	Targets []string `json:"targets"`
}

type scanRunStartResult struct {
	RunID   string `json:"runId,omitempty"`
	Skipped bool   `json:"skipped,omitempty"`
	Message string `json:"message,omitempty"`
}

// handleScanContentDiscovery is the "Scan selected" action on the
// Subdomains tab: given the hostnames that passed the user's filters there
// (the frontend always includes the apex domain too), it builds and runs a
// fresh content-discovery flow against whichever of those targets aren't
// already covered by a running-or-succeeded content-discovery run (see
// newTargets) -- so re-clicking "Scan selected" after a few more subdomains
// turn up only scans the newly-added ones instead of re-scanning the whole
// selection, and clicking it while the previous run is still going doesn't
// pile on a second set of ffuf/feroxbuster processes for hosts it's already
// covering. If every requested target is already covered, no run is
// started and the response says so (skipped: true) rather than pretending
// one was.
func (s *Server) handleScanContentDiscovery(w http.ResponseWriter, r *http.Request) {
	scanID := r.PathValue("id")
	sc, err := s.store.GetScan(scanID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if sc.Scheme == "" {
		writeError(w, http.StatusConflict, fmt.Errorf("scan: scheme not resolved yet, try again once recon finishes"))
		return
	}

	var req contentDiscoveryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(req.Targets) == 0 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("scan: at least one target is required"))
		return
	}

	targets, err := s.newTargets(scanID, store.ScanKindContentDiscovery, req.Targets)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if len(targets) == 0 {
		writeJSON(w, http.StatusOK, scanRunStartResult{Skipped: true, Message: "every selected target is already being (or has already been) scanned"})
		return
	}

	flow := s.buildContentDiscoveryFlow(sc.Domain, sc.Scheme, targets, scanOptionsOf(sc))
	runID, err := s.startScanRun(scanID, store.ScanKindContentDiscovery, flow, targets)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusAccepted, scanRunStartResult{RunID: runID})
}

// handleRestartScan redoes a scan -- fresh apex recon checks plus any
// scanner that isn't already running or already covering its target (see
// runScan) -- reusing runScan unchanged. Refuses outright while the scan is
// still running: recon + every scanner it kicks off would otherwise run a
// second time concurrently with the first, doubling CPU/subprocess usage
// for no benefit.
func (s *Server) handleRestartScan(w http.ResponseWriter, r *http.Request) {
	scanID := r.PathValue("id")
	sc, err := s.store.GetScan(scanID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	if running, err := s.store.ScanRunning(scanID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	} else if running {
		writeError(w, http.StatusConflict, fmt.Errorf("scan: already running -- cancel it first if you want to restart from scratch"))
		return
	}

	go s.runScan(scanID, sc.Domain)

	writeJSON(w, http.StatusAccepted, map[string]string{"scanId": scanID})
}

type restartScanRunRequest struct {
	Targets []string `json:"targets,omitempty"`
}

// handleRestartScanRun redoes just one of a scan's scanners, rebuilding its
// flow the same way the initial scan (or, for content discovery,
// handleScanContentDiscovery) did. Refuses if that scanner kind is already
// running for this scan -- an explicit "restart" is a deliberate request to
// redo the work, but two overlapping runs of the same scanner would just
// waste CPU racing each other, so the caller has to wait for (or cancel)
// the one already in flight first.
func (s *Server) handleRestartScanRun(w http.ResponseWriter, r *http.Request) {
	scanID := r.PathValue("id")
	kind := store.ScanKind(r.PathValue("kind"))

	sc, err := s.store.GetScan(scanID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if sc.Scheme == "" {
		writeError(w, http.StatusConflict, fmt.Errorf("scan: scheme not resolved yet, try again once recon finishes"))
		return
	}
	if running, err := s.store.KindRunning(scanID, kind); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	} else if running {
		writeError(w, http.StatusConflict, fmt.Errorf("scan: %s is already running", kind))
		return
	}

	opts := scanOptionsOf(sc)
	var flow engine.Flow
	var targets []string
	switch kind {
	case store.ScanKindContentDiscovery:
		var req restartScanRunRequest
		if r.ContentLength > 0 {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
		}
		targets = req.Targets
		if len(targets) == 0 {
			targets = []string{sc.Domain}
		}
		flow = s.buildContentDiscoveryFlow(sc.Domain, sc.Scheme, targets, opts)
	case store.ScanKindSubdomainBruteforce:
		targets = []string{sc.Domain}
		flow = s.buildSubdomainBruteforceFlow(sc.Domain, sc.Scheme, opts)
	case store.ScanKindVHostBruteforce:
		checks, err := s.store.ListChecks(scanID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		var apexA []string
		for _, c := range checks {
			if c.Domain != sc.Domain || c.Kind != recon.KindDNS || c.Status != recon.StatusDone {
				continue
			}
			// Data round-tripped through JSON (store.ListChecks decodes it
			// back from persisted text), so the []string DNS.go wrote comes
			// back as []any here.
			raw, ok := c.Data["a"].([]any)
			if !ok {
				continue
			}
			for _, v := range raw {
				if s, ok := v.(string); ok {
					apexA = append(apexA, s)
				}
			}
		}
		if len(apexA) == 0 {
			writeError(w, http.StatusConflict, fmt.Errorf("scan: no IPv4 address found for the apex domain"))
			return
		}
		targets = []string{apexA[0]}
		flow = s.buildVHostBruteforceFlow(sc.Domain, sc.Scheme, apexA[0], opts)
	default:
		writeError(w, http.StatusBadRequest, fmt.Errorf("scan: unknown scanner kind %q", kind))
		return
	}

	runID, err := s.startScanRun(scanID, kind, flow, targets)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{"runId": runID})
}

func (s *Server) handleListScanRuns(w http.ResponseWriter, r *http.Request) {
	runs, err := s.store.ListScanRuns(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, runs)
}

// scanSummary is GET /api/scans's per-row response shape: the scan record
// plus lightweight aggregates the dashboard uses to show more than a
// domain and a timestamp -- how many subdomains/findings were found, the
// apex's HTTP status, and whether anything is still running.
type scanSummary struct {
	store.Scan
	SubdomainCount int    `json:"subdomainCount"`
	FindingCount   int    `json:"findingCount"`
	HTTPStatus     int    `json:"httpStatus,omitempty"`
	HTTPTitle      string `json:"httpTitle,omitempty"`
	Cloudflare     bool   `json:"cloudflare"`
	Running        bool   `json:"running"`
}

func (s *Server) summarize(sc store.Scan) (scanSummary, error) {
	out := scanSummary{Scan: sc}

	subdomainCount, _, err := s.store.SubdomainCount(sc.ID, sc.Domain)
	if err != nil {
		return out, err
	}
	out.SubdomainCount = subdomainCount

	findingCount, err := s.store.ContentDiscoveryFindingCount(sc.ID)
	if err != nil {
		return out, err
	}
	out.FindingCount = findingCount

	if status, title, ok, err := s.store.ApexHTTP(sc.ID, sc.Domain); err != nil {
		return out, err
	} else if ok {
		out.HTTPStatus, out.HTTPTitle = status, title
	}

	if cloudflare, err := s.store.ApexCloudflare(sc.ID, sc.Domain); err != nil {
		return out, err
	} else {
		out.Cloudflare = cloudflare
	}

	running, err := s.store.ScanRunning(sc.ID)
	if err != nil {
		return out, err
	}
	out.Running = running

	return out, nil
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	scans, err := s.store.ListScans()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]scanSummary, 0, len(scans))
	for _, sc := range scans {
		summary, err := s.summarize(sc)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		out = append(out, summary)
	}
	writeJSON(w, http.StatusOK, out)
}

// scanDetail is GET /api/scans/{id}'s response shape: the scan record plus
// every check recorded for it so far, for a client reloading a past scan
// (or one that missed some live events) to reconstruct the dashboard. The
// scanner runs themselves are fetched separately via
// GET /api/scans/{id}/runs.
type scanDetail struct {
	store.Scan
	Checks []recon.Check `json:"checks"`
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sc, err := s.store.GetScan(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	checks, err := s.store.ListChecks(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, scanDetail{Scan: sc, Checks: checks})
}
