package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Indigo6415/Aperture/internal/netgov"
	"net/http"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/engine"
	"github.com/Indigo6415/Aperture/internal/probescan"
	"github.com/Indigo6415/Aperture/internal/store"
)

// probeScanClaimTimeout bounds how long a registered-but-unclaimed probe
// scan (see handleProbeScan/handleWatchProbeScan) sits in
// pendingProbeScans -- if the frontend never opens the WebSocket (tab
// closed mid-navigation, network blip), this cleans up the entry rather
// than leaking it for the life of the process.
const probeScanClaimTimeout = 30 * time.Second

// probeScanRequest is the request body for POST /api/probe/scan.
type probeScanRequest struct {
	Target string `json:"target"`
	// Preset mirrors engine.ScanOptions' Preset field (aggressive/normal/
	// stealth/custom) -- resolved into a request concurrency the same way
	// a job's thread count is, rather than probescan having its own
	// parallel preset table.
	Preset string `json:"preset,omitempty"`
	// CredentialID optionally names a saved case credential (see
	// handlers_credentials.go) whose headers/cookie are applied to every
	// request this scan issues.
	CredentialID string `json:"credentialId,omitempty"`
	// CaseID optionally scopes this scan to a case: when set, the finished
	// result is persisted (see store.SaveCaseScan) instead of only ever
	// existing on the WebSocket stream the requesting tab happened to be
	// watching.
	CaseID string `json:"caseId,omitempty"`
}

// pendingProbeScan is what handleProbeScan registers and
// handleWatchProbeScan later claims -- the target plus whatever tuning
// (concurrency, headers) the request asked for, resolved once up front
// rather than re-derived when the scan actually starts.
type pendingProbeScan struct {
	Target string
	Opts   probescan.Options
	CaseID string
}

// probeScanStartResult is the immediate response to starting a probe scan:
// a scan ID the client subscribes to over GET /ws/probe/{id} for live
// per-module progress (see handleProbeScan and runProbeScan below).
type probeScanStartResult struct {
	ScanID string `json:"scanId"`
}

// handleProbeModules lists every registered check module (id/name/severity,
// no findings) so the frontend can render the full test list -- greyed out,
// not yet run -- before a scan even starts.
func (s *Server) handleProbeModules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, probescan.Modules())
}

// handleProbeScan registers a probe misconfiguration scan against
// req.Target and immediately returns a scan ID -- it does not start
// running yet. The scan only actually starts once the frontend connects to
// GET /ws/probe/{id} (see handleWatchProbeScan), which guarantees a
// subscriber is listening before the first event is published: a scan
// against a fast/local target can otherwise complete, and every "module"
// event with it, before a WebSocket opened after the POST response even
// finishes its handshake.
func (s *Server) handleProbeScan(w http.ResponseWriter, r *http.Request) {
	var req probeScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.Target = strings.TrimSpace(req.Target)
	if req.Target == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("target is required"))
		return
	}

	opts := probescan.Options{Concurrency: engine.ScanOptions{Preset: req.Preset}.Resolved().Threads}
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
	s.probeMu.Lock()
	s.pendingProbeScans[scanID] = pendingProbeScan{Target: req.Target, Opts: opts, CaseID: req.CaseID}
	s.probeMu.Unlock()
	time.AfterFunc(probeScanClaimTimeout, func() {
		s.probeMu.Lock()
		delete(s.pendingProbeScans, scanID)
		s.probeMu.Unlock()
	})

	writeJSON(w, http.StatusAccepted, probeScanStartResult{ScanID: scanID})
}

// handleWatchProbeScan claims a scan ID registered by handleProbeScan (if
// it hasn't already been claimed or timed out) and starts the scan only
// once this connection has subscribed to its hub channel -- see
// handleProbeScan's comment for why that ordering matters.
func (s *Server) handleWatchProbeScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	s.probeMu.Lock()
	pending, ok := s.pendingProbeScans[id]
	if ok {
		delete(s.pendingProbeScans, id)
	}
	s.probeMu.Unlock()
	if !ok {
		http.Error(w, "unknown or already-claimed scan id", http.StatusNotFound)
		return
	}

	s.watchWithStart(w, r, id, func() { go s.runProbeScan(id, pending) })
}

// runProbeScan runs the scan and publishes its progress to scanID's hub
// channel. Unlike an engine-backed job, a probe scan isn't tied to a case
// or stored anywhere -- the "done" event itself carries everything the
// frontend needs (target, health, and every module's findings via the
// "module" events that preceded it) since there's no job row to re-fetch
// state from afterward.
func (s *Server) runProbeScan(scanID string, pending pendingProbeScan) {
	opts := pending.Opts
	opts.Progress = hubReporter{hub: s.hub, scanID: scanID}
	resp, err := probescan.RunScanStreaming(netgov.WithPolicy(context.Background(), netgov.Policy{MaxConcurrency: pending.Opts.Concurrency}), pending.Target, opts, func(m probescan.ModuleResult) {
		mod := m
		s.hub.publish(scanID, RunEvent{Type: "module", Module: &mod})
	})
	if err != nil {
		s.hub.publish(scanID, RunEvent{Type: "done", Status: engine.StatusFailed, Message: err.Error()})
		return
	}
	s.hub.publish(scanID, RunEvent{Type: "done", Status: engine.StatusSucceeded, ProbeTarget: resp.Target, ProbeHealth: &resp.Health})

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
			s.saveCaseScan(pending.CaseID, pending.Target, "probe", severity, summary, data)
		}
	}
}
