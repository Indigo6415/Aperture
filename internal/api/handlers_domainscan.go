package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/domainscan"
	"github.com/Indigo6415/Aperture/internal/engine"
	"github.com/Indigo6415/Aperture/internal/netgov"
	"github.com/Indigo6415/Aperture/internal/store"
)

// domainScanClaimTimeout is domain scan's counterpart to
// probeScanClaimTimeout (see handlers_probe.go) -- same reasoning.
const domainScanClaimTimeout = 30 * time.Second

// domainScanRequest is the request body for POST /api/domainscan/scan.
type domainScanRequest struct {
	Target string `json:"target"`
	// CredentialID optionally names a saved case credential (see
	// handlers_credentials.go) whose headers/cookie are applied to every
	// request the underlying crawl makes.
	CredentialID string `json:"credentialId,omitempty"`
	// CrawlDepth/MaxPages tune how far the domain-wide crawl a module like
	// retire's goes before handing its tool whatever it found -- see
	// domainscan.Options' doc comment. Zero uses that package's own
	// defaults.
	CrawlDepth int `json:"crawlDepth,omitempty"`
	MaxPages   int `json:"maxPages,omitempty"`
	// CaseID optionally scopes this scan to a case -- see
	// probeScanRequest.CaseID's doc comment.
	CaseID string `json:"caseId,omitempty"`
	// RequestsPerSecond is the scan speed the Slow/Normal/Fast/Custom control
	// sends; zero means scanRate's default.
	RequestsPerSecond float64 `json:"requestsPerSecond,omitempty"`
}

// maxDomainScanCrawlDepth/maxDomainScanPages cap what a request can ask
// for, same posture as handlers_secrets.go's maxSecretScanRecursionDepth --
// domainscan's own crawl.go already caps these internally, but clamping
// here too keeps an out-of-range request from round-tripping through the
// package only to be silently capped there.
const (
	maxDomainScanCrawlDepth = 4
	maxDomainScanPages      = 50
)

// pendingDomainScan is what handleDomainScan registers and
// handleWatchDomainScan later claims -- domain scan's counterpart to
// pendingProbeScan.
type pendingDomainScan struct {
	Target string
	Opts   domainscan.Options
	CaseID string
	RPS    float64
}

// domainScanStartResult is the immediate response to starting a domain
// scan: a scan ID the client subscribes to over GET /ws/domainscan/{id}
// for live per-module progress.
type domainScanStartResult struct {
	ScanID string `json:"scanId"`
}

// handleDomainScanModules lists every registered domain-scan module (id/
// name, no findings) so the frontend can render the full tool list --
// greyed out, not yet run -- before a scan even starts.
func (s *Server) handleDomainScanModules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, domainscan.Modules())
}

// handleDomainScan registers a domain-wide vulnerability/misconfiguration
// scan against req.Target and immediately returns a scan ID -- it does not
// start running yet, for the same reason handleProbeScan doesn't (see its
// doc comment): the scan only actually starts once the frontend connects
// to GET /ws/domainscan/{id}, guaranteeing a subscriber is listening before
// the first "domainModule" event is published.
func (s *Server) handleDomainScan(w http.ResponseWriter, r *http.Request) {
	var req domainScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.Target = strings.TrimSpace(req.Target)
	rps, err := scanRate(req.RequestsPerSecond)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Target == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("target is required"))
		return
	}
	if req.CrawlDepth < 0 {
		req.CrawlDepth = 0
	}
	if req.CrawlDepth > maxDomainScanCrawlDepth {
		req.CrawlDepth = maxDomainScanCrawlDepth
	}
	if req.MaxPages < 0 {
		req.MaxPages = 0
	}
	if req.MaxPages > maxDomainScanPages {
		req.MaxPages = maxDomainScanPages
	}

	opts := domainscan.Options{CrawlDepth: req.CrawlDepth, MaxPages: req.MaxPages}
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
	s.domainScanMu.Lock()
	s.pendingDomainScans[scanID] = pendingDomainScan{Target: req.Target, Opts: opts, CaseID: req.CaseID, RPS: rps}
	s.domainScanMu.Unlock()
	time.AfterFunc(domainScanClaimTimeout, func() {
		s.domainScanMu.Lock()
		delete(s.pendingDomainScans, scanID)
		s.domainScanMu.Unlock()
	})

	writeJSON(w, http.StatusAccepted, domainScanStartResult{ScanID: scanID})
}

// handleWatchDomainScan claims a scan ID registered by handleDomainScan (if
// it hasn't already been claimed or timed out) and starts the scan only
// once this connection has subscribed to its hub channel -- see
// handleDomainScan's comment for why that ordering matters.
func (s *Server) handleWatchDomainScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	s.domainScanMu.Lock()
	pending, ok := s.pendingDomainScans[id]
	if ok {
		delete(s.pendingDomainScans, id)
	}
	s.domainScanMu.Unlock()
	if !ok {
		http.Error(w, "unknown or already-claimed scan id", http.StatusNotFound)
		return
	}

	s.watchWithStart(w, r, id, func() { go s.runDomainScan(id, pending) })
}

// runDomainScan runs the scan and publishes its progress to scanID's hub
// channel -- domainscan's counterpart to runProbeScan. Unlike an
// engine-backed job, a domain scan isn't tied to a case or stored anywhere
// beyond the optional case-scan summary saved below; the "done" event
// itself carries everything the frontend needs (target plus every module's
// findings via the "domainModule" events that preceded it).
func (s *Server) runDomainScan(scanID string, pending pendingDomainScan) {
	opts := pending.Opts
	opts.Progress = hubReporter{hub: s.hub, scanID: scanID}
	ctx, cancel := context.WithCancel(s.withScanRecorder(netgov.WithPolicy(context.Background(), netgov.Policy{MaxRPS: pending.RPS}), scanID))
	s.trackScanCancel(scanID, cancel)
	defer s.untrackScanCancel(scanID)
	defer cancel()
	resp, err := domainscan.RunScanStreaming(ctx, pending.Target, opts, func(m domainscan.ModuleResult) {
		mod := m
		s.hub.publish(scanID, RunEvent{Type: "domainModule", DomainModule: &mod})
	})
	// A stopped scan is reported as stopped and never saved, even if the run
	// returned partial output without an error.
	if ctx.Err() == context.Canceled {
		publishScanStopped(s.hub, scanID)
		return
	}
	if err != nil {
		s.hub.publish(scanID, RunEvent{Type: "done", Status: engine.StatusFailed, Message: err.Error()})
		return
	}
	s.hub.publish(scanID, RunEvent{Type: "done", Status: engine.StatusSucceeded, DomainTarget: resp.Target})

	if pending.CaseID != "" {
		severity, findingCount := "info", 0
		for _, m := range resp.Modules {
			if len(m.Findings) == 0 {
				continue
			}
			findingCount += len(m.Findings)
			severity = maxSeverity(severity, m.Severity)
		}
		summary := fmt.Sprintf("%d finding(s) across %d module(s)", findingCount, len(resp.Modules))
		if data, err := json.Marshal(resp); err == nil {
			s.saveCaseScan(scanID, pending.CaseID, pending.Target, "domainscan", severity, summary, data)
		}
	}
}
