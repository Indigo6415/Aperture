package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/apienum"
	"github.com/Indigo6415/Aperture/internal/engine"
	"github.com/Indigo6415/Aperture/internal/store"
)

// apiEnumScanClaimTimeout is the API enumerator's counterpart to
// probeScanClaimTimeout (see handlers_probe.go) -- same reasoning.
const apiEnumScanClaimTimeout = 30 * time.Second

// apiEnumMaxCrawlDepth/apiEnumMaxPages cap what a request can ask for --
// same posture as handlers_domainscan.go's identical constants.
const (
	apiEnumMaxCrawlDepth = 4
	apiEnumMaxPages      = 50
)

// apiEnumDefaultRateLimit is the enumerator's own floor on requests/sec
// when the launch preset doesn't already set one (the "custom"/unset
// preset's Threads/RateLimit are literally 0 -- see engine.ScanOptions'
// doc comment on what a preset's zero value means) -- this run fires
// meaningfully more requests per route than a probe scan does (OPTIONS,
// a method swap, an auth probe, content-type negotiation), on top of a
// crawl, JS mining, and a wordlist brute force, so it gets a safety
// default even when the operator hasn't picked "stealth" -- see the
// apienum package doc's rate-limiting guardrail goal. A named preset
// (aggressive/normal/stealth) is still honored exactly as given, including
// "normal"/"aggressive" leaving RateLimit at its own deliberate 0
// (unlimited).
const apiEnumDefaultRateLimit = 15

// apiEnumScanRequest is the request body for POST /api/apienum/scan.
type apiEnumScanRequest struct {
	Target       string `json:"target"`
	Preset       string `json:"preset,omitempty"`
	CredentialID string `json:"credentialId,omitempty"`
	CrawlDepth   int    `json:"crawlDepth,omitempty"`
	MaxPages     int    `json:"maxPages,omitempty"`
	// ExtraWordlist adds caller-supplied path segments to the bundled
	// default wordlist the brute-force phase draws from -- see
	// apienum.Options.ExtraWordlist.
	ExtraWordlist []string `json:"extraWordlist,omitempty"`
	// CaseID -- see probeScanRequest.CaseID's doc comment.
	CaseID string `json:"caseId,omitempty"`
}

// pendingApiEnumScan is what handleApiEnumScan registers and
// handleWatchApiEnumScan later claims -- the API enumerator's counterpart
// to pendingProbeScan.
type pendingApiEnumScan struct {
	Target string
	Opts   apienum.Options
	CaseID string
}

// apiEnumScanStartResult is the immediate response to starting an API
// enumeration run: a scan ID the client subscribes to over
// GET /ws/apienum/{id} for live phase/route progress.
type apiEnumScanStartResult struct {
	ScanID string `json:"scanId"`
}

// handleApiEnumScan registers an API enumeration run against req.Target
// and immediately returns a scan ID -- it does not start running yet, for
// the same reason handleProbeScan doesn't (see its doc comment): the scan
// only actually starts once the frontend connects to GET /ws/apienum/{id},
// guaranteeing a subscriber is listening before the first progress event
// is published.
func (s *Server) handleApiEnumScan(w http.ResponseWriter, r *http.Request) {
	var req apiEnumScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.Target = strings.TrimSpace(req.Target)
	if req.Target == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("target is required"))
		return
	}
	if req.CrawlDepth < 0 {
		req.CrawlDepth = 0
	}
	if req.CrawlDepth > apiEnumMaxCrawlDepth {
		req.CrawlDepth = apiEnumMaxCrawlDepth
	}
	if req.MaxPages < 0 {
		req.MaxPages = 0
	}
	if req.MaxPages > apiEnumMaxPages {
		req.MaxPages = apiEnumMaxPages
	}

	resolved := engine.ScanOptions{Preset: req.Preset}.Resolved()
	rateLimit := resolved.RateLimit
	if (req.Preset == "" || req.Preset == engine.PresetCustom) && rateLimit <= 0 {
		rateLimit = apiEnumDefaultRateLimit
	}

	opts := apienum.Options{
		Concurrency: resolved.Threads, RateLimit: rateLimit,
		CrawlDepth: req.CrawlDepth, MaxPages: req.MaxPages, ExtraWordlist: req.ExtraWordlist,
	}
	if req.CredentialID != "" {
		cred, err := s.store.GetCredential(req.CredentialID)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusBadRequest, fmt.Errorf("credential %s not found", req.CredentialID))
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		opts.Headers = mergedCredentialHeaders(cred, nil)
	}
	opts.Headers = s.applyDomainCookie(req.CaseID, req.Target, opts.Headers)

	scanID := newID()
	s.apiEnumMu.Lock()
	s.pendingApiEnumScans[scanID] = pendingApiEnumScan{Target: req.Target, Opts: opts, CaseID: req.CaseID}
	s.apiEnumMu.Unlock()
	time.AfterFunc(apiEnumScanClaimTimeout, func() {
		s.apiEnumMu.Lock()
		delete(s.pendingApiEnumScans, scanID)
		s.apiEnumMu.Unlock()
	})

	writeJSON(w, http.StatusAccepted, apiEnumScanStartResult{ScanID: scanID})
}

// handleWatchApiEnumScan claims a scan ID registered by handleApiEnumScan
// (if it hasn't already been claimed or timed out) and starts the scan
// only once this connection has subscribed to its hub channel -- see
// handleApiEnumScan's comment for why that ordering matters.
func (s *Server) handleWatchApiEnumScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	s.apiEnumMu.Lock()
	pending, ok := s.pendingApiEnumScans[id]
	if ok {
		delete(s.pendingApiEnumScans, id)
	}
	s.apiEnumMu.Unlock()
	if !ok {
		http.Error(w, "unknown or already-claimed scan id", http.StatusNotFound)
		return
	}

	s.watchWithStart(w, r, id, func() { go s.runApiEnumScan(id, pending) })
}

// runApiEnumScan runs the scan and publishes its progress to scanID's hub
// channel -- counterpart to runProbeScan/runDomainScan. An API enum run
// isn't tied to a case or stored anywhere beyond the optional case-scan
// summary saved below; the terminal "done" event carries the target,
// schema/GraphQL summaries, injection points, and stats, while the route
// list itself is only ever sent incrementally via "apiEnumRoute" events
// (see hub.go's RunEvent doc comment for why).
func (s *Server) runApiEnumScan(scanID string, pending pendingApiEnumScan) {
	opts := pending.Opts
	opts.Progress = hubReporter{hub: s.hub, scanID: scanID}
	resp, err := apienum.RunScanStreaming(context.Background(), pending.Target, opts,
		func(p apienum.PhaseEvent) {
			phase := p
			s.hub.publish(scanID, RunEvent{Type: "apiEnumPhase", ApiEnumPhase: &phase})
		},
		func(route apienum.Route) {
			rt := route
			s.hub.publish(scanID, RunEvent{Type: "apiEnumRoute", ApiEnumRoute: &rt})
		},
	)
	if err != nil {
		s.hub.publish(scanID, RunEvent{Type: "done", Status: engine.StatusFailed, Message: err.Error()})
		return
	}
	stats := resp.Stats
	s.hub.publish(scanID, RunEvent{
		Type: "done", Status: engine.StatusSucceeded, ApiEnumTarget: resp.Target,
		ApiEnumSchema: resp.Schema, ApiEnumGraphQL: resp.GraphQL,
		ApiEnumInjectionPoints: orEmptyInjectionPoints(resp.InjectionPoints), ApiEnumStats: &stats,
	})

	if pending.CaseID != "" {
		severity := "info"
		if stats.InjectionPoints > 0 {
			severity = "medium"
		}
		summary := fmt.Sprintf("%d route(s) found (%d confirmed) · %d injection point(s) staged", stats.RoutesFound, stats.ConfirmedRoutes, stats.InjectionPoints)
		if data, err := json.Marshal(resp); err == nil {
			s.saveCaseScan(pending.CaseID, pending.Target, "apienum", severity, summary, data)
		}
	}
}

// orEmptyInjectionPoints turns a nil slice into an empty (but non-nil) one
// -- a nil slice would otherwise serialize to JSON `null` instead of `[]`,
// which the frontend treats as an always-present array (same reasoning as
// graphqlenum.Run's identical helper).
func orEmptyInjectionPoints(points []apienum.InjectionPoint) []apienum.InjectionPoint {
	if points == nil {
		return []apienum.InjectionPoint{}
	}
	return points
}
