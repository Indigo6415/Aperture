package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"

	"github.com/Indigo6415/Aperture/internal/adapters"
	"github.com/Indigo6415/Aperture/internal/engine"
	"github.com/Indigo6415/Aperture/internal/recon"
	"github.com/Indigo6415/Aperture/internal/store"
	"github.com/Indigo6415/Aperture/internal/wordlists"
)

type startScanRequest struct {
	Domain string `json:"domain"`
}

// handleStartScan is the entry point for the dashboard's single domain
// input: it creates a scan record and immediately returns, then runs the
// recon checks and the auto-generated ffuf/feroxbuster flow in the
// background, streamed to the client over GET /ws/scans/{id}.
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

	scanID := newID()
	if err := s.store.CreateScan(scanID, domain); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	go s.runScan(scanID, domain)

	writeJSON(w, http.StatusAccepted, map[string]string{"scanId": scanID})
}

// runScan drives one domain scan end to end: it streams each recon.Check as
// it completes, then -- once the apex HTTP check has revealed which scheme
// the domain responds on -- builds and kicks off the content-discovery flow
// that reuses the existing engine/adapters machinery for ffuf/feroxbuster.
func (s *Server) runScan(scanID, domain string) {
	ctx := context.Background()

	onCheck := func(c recon.Check) {
		if err := s.store.SaveCheck(scanID, c); err != nil {
			// The check is still delivered live below even if persisting it
			// failed, so a slow/broken disk doesn't stall the scan.
			s.hub.publish(scanID, RunEvent{Type: "check", Check: &c, Message: "warning: failed to persist check: " + err.Error()})
			return
		}
		s.hub.publish(scanID, RunEvent{Type: "check", Check: &c})
	}

	scheme, _ := recon.Scan(ctx, domain, onCheck)

	flow := s.buildDomainFlow(domain, scheme)
	flow.ID = newID()
	if err := s.store.SaveFlow(flow); err != nil {
		s.hub.publish(scanID, RunEvent{Type: "done", Message: "failed to create scan flow: " + err.Error()})
		return
	}

	runID := newID()
	if err := s.store.CreateRun(runID, flow.ID); err != nil {
		s.hub.publish(scanID, RunEvent{Type: "done", Message: "failed to start scan flow: " + err.Error()})
		return
	}
	if err := s.store.SetScanFlow(scanID, flow.ID, runID); err != nil {
		s.hub.publish(scanID, RunEvent{Type: "done", Message: "warning: failed to link scan flow: " + err.Error()})
	}

	// Let the client know the flow/run exist so it can open its own
	// GET /ws/runs/{runId} watch (existing, unmodified machinery) for live
	// ffuf/feroxbuster findings; this scan's own event stream is done once
	// recon checks + kicking off the flow are complete.
	s.hub.publish(scanID, RunEvent{Type: "flow", FlowID: flow.ID, RunID: runID})
	s.hub.publish(scanID, RunEvent{Type: "done"})

	// executeRun blocks until the flow finishes; run it in the same
	// goroutine since runScan itself already runs in its own goroutine
	// (started by handleStartScan) and nothing here waits on it further.
	s.executeRun(flow, runID)
}

// buildDomainFlow assembles the default two-scanner content-discovery
// pipeline a domain scan runs: ffuf and feroxbuster against the domain,
// merged with dedup into a live results table. It's just an engine.Flow
// like any hand-built one in the flow editor, so it reuses the engine,
// adapters, store, and hub without any changes to that machinery.
func (s *Server) buildDomainFlow(domain, scheme string) engine.Flow {
	wordlistPath := filepath.Join(s.wordlistsDir, wordlists.DefaultName)
	base := scheme + "://" + domain

	ffufCfg, _ := json.Marshal(adapters.FFufConfig{URL: base + "/FUZZ", Wordlist: wordlistPath})
	feroxCfg, _ := json.Marshal(adapters.FeroxbusterConfig{URL: base + "/", Wordlist: wordlistPath})
	mergeCfg, _ := json.Marshal(engine.MergeConfig{Dedup: true})

	return engine.Flow{
		Name: "Scan: " + domain,
		Nodes: []engine.Node{
			// Positions are purely so the flow editor doesn't stack every
			// node on top of the others if the user opens this flow to
			// tweak it -- the engine itself only cares about the edges.
			{ID: "ffuf", Kind: engine.KindFFuf, Label: "ffuf", Config: ffufCfg, Position: &engine.Position{X: 40, Y: 40}},
			{ID: "feroxbuster", Kind: engine.KindFeroxbuster, Label: "feroxbuster", Config: feroxCfg, Position: &engine.Position{X: 40, Y: 200}},
			{ID: "merge", Kind: engine.KindMerge, Label: "merge", Config: mergeCfg, Position: &engine.Position{X: 340, Y: 120}},
			{ID: "table", Kind: engine.KindTable, Label: "results", Position: &engine.Position{X: 600, Y: 120}},
		},
		Edges: []engine.Edge{
			{ID: "e-ffuf-merge", From: "ffuf", To: "merge"},
			{ID: "e-ferox-merge", From: "feroxbuster", To: "merge"},
			{ID: "e-merge-table", From: "merge", To: "table"},
		},
	}
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	scans, err := s.store.ListScans()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, scans)
}

// scanDetail is GET /api/scans/{id}'s response shape: the scan record plus
// every check recorded for it so far, for a client reloading a past scan
// (or one that missed some live events) to reconstruct the dashboard.
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
