package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Indigo6415/Aperture/internal/netgov"
	"github.com/Indigo6415/Aperture/internal/store"
)

// targetListForCase looks up a target list by id and confirms it belongs to
// caseID, so a listId from another case (or a stale/bogus one) can't be
// used to attach a target where it doesn't belong.
func (s *Server) targetListForCase(w http.ResponseWriter, caseID, listID string) (store.TargetList, bool) {
	list, err := s.store.GetTargetListByID(listID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return store.TargetList{}, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return store.TargetList{}, false
	}
	if list.CaseID != caseID {
		writeError(w, http.StatusBadRequest, errors.New("target: list does not belong to this case"))
		return store.TargetList{}, false
	}
	return list, true
}

type addTargetRequest struct {
	Value  string `json:"value"`
	ListID string `json:"listId"`
	Notes  string `json:"notes,omitempty"`
}

func (s *Server) handleAddTarget(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("id")
	var req addTargetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Value == "" {
		writeError(w, http.StatusBadRequest, errors.New("target: value is required"))
		return
	}
	if req.ListID == "" {
		writeError(w, http.StatusBadRequest, errors.New("target: listId is required"))
		return
	}
	if _, ok := s.targetListForCase(w, caseID, req.ListID); !ok {
		return
	}

	if err := s.store.AddTarget(store.Target{ID: newID(), CaseID: caseID, ListID: req.ListID, Value: req.Value, Notes: req.Notes}); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	t, err := s.store.GetTargetByValue(caseID, req.Value)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) handleListTargets(w http.ResponseWriter, r *http.Request) {
	targets, err := s.store.ListTargets(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, targets)
}

type promoteTargetsRequest struct {
	JobID  string   `json:"jobId"`
	ListID string   `json:"listId"`
	Values []string `json:"values"`
}

// handlePromoteTargets is how a tool's results become case targets: given a
// job that belongs to this case, a destination list, and a set of values
// derived from its selected result rows (client-side -- see ResultsTable's
// selection column), it records each one as a target tagged with the job's
// tool as its source. AddTarget's UNIQUE(case_id, value) + INSERT OR IGNORE
// makes re-promoting an already-known value a harmless no-op rather than a
// duplicate row, so the client doesn't need to track what's already been
// promoted.
func (s *Server) handlePromoteTargets(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("id")
	var req promoteTargetsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(req.Values) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("target: at least one value is required"))
		return
	}
	if req.ListID == "" {
		writeError(w, http.StatusBadRequest, errors.New("target: listId is required"))
		return
	}
	if _, ok := s.targetListForCase(w, caseID, req.ListID); !ok {
		return
	}

	job, err := s.store.GetJob(req.JobID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if job.CaseID != caseID {
		writeError(w, http.StatusBadRequest, errors.New("target: job does not belong to this case"))
		return
	}

	out := make([]store.Target, 0, len(req.Values))
	for _, value := range req.Values {
		if value == "" {
			continue
		}
		if err := s.store.AddTarget(store.Target{
			ID: newID(), CaseID: caseID, ListID: req.ListID, Value: value, SourceTool: job.Tool, SourceJobID: job.ID,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		t, err := s.store.GetTargetByValue(caseID, value)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		out = append(out, t)
	}

	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleDeleteTarget(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// Looked up first so a missing target is a 404 rather than a silent 204.
	if _, err := s.store.GetTargetByID(id); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.store.DeleteTarget(id); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Target Lists ---

func (s *Server) handleListTargetLists(w http.ResponseWriter, r *http.Request) {
	lists, err := s.store.ListTargetLists(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, lists)
}

type targetListRequest struct {
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"`
}

func (s *Server) handleCreateTargetList(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("id")
	if _, err := s.store.GetCase(caseID); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	var req targetListRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, errors.New("target list: name is required"))
		return
	}
	kind := req.Kind
	if kind == "" {
		kind = "other"
	}

	l := store.TargetList{ID: newID(), CaseID: caseID, Name: req.Name, Kind: kind}
	if err := s.store.CreateTargetList(l); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	saved, err := s.store.GetTargetListByID(l.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, saved)
}

func (s *Server) handleRenameTargetList(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req targetListRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, errors.New("target list: name is required"))
		return
	}
	if err := s.store.RenameTargetList(id, req.Name); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	saved, err := s.store.GetTargetListByID(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) handleDeleteTargetList(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// Looked up first so a missing list is a 404 rather than a silent 204.
	if _, err := s.store.GetTargetListByID(id); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.store.DeleteTargetList(id); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Liveness ping ---

// pingConcurrency caps how many targets one ping run checks at once, so a
// long list doesn't fan out into hundreds of simultaneous connections.
const pingConcurrency = 8

// pingTimeout bounds each single HTTP attempt against a target.
const pingTimeout = 5 * time.Second

// pingResult is one target's liveness verdict. Alive means the host sent back
// any HTTP response at all -- even a 404 or 403 proves it's up. Otherwise
// Error holds the last transport-level failure (DNS, refused, timeout, ...).
type pingResult struct {
	TargetID   string `json:"targetId"`
	Value      string `json:"value"`
	Alive      bool   `json:"alive"`
	StatusCode int    `json:"statusCode,omitempty"`
	URL        string `json:"url,omitempty"`
	Error      string `json:"error,omitempty"`
}

// handlePingTargetList checks every target in one list for liveness. Only
// network lists (domain, url, other) can be pinged -- a directory or file
// entry is a local path, so there's nothing on the wire to check.
func (s *Server) handlePingTargetList(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.GetTargetListByID(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if list.Kind == "directory" || list.Kind == "file" {
		writeError(w, http.StatusBadRequest, errors.New("target list: only domain, URL, and other lists can be pinged"))
		return
	}

	all, err := s.store.ListTargets(list.CaseID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// ListTargets returns the whole case, so keep only this list's targets.
	var targets []store.Target
	for _, t := range all {
		if t.ListID == list.ID {
			targets = append(targets, t)
		}
	}

	// Results are streamed as NDJSON: one pingResult per line, flushed the
	// moment each check finishes, so the UI can show verdicts as they land
	// instead of waiting for the whole list.
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	enc := json.NewEncoder(w)
	if flusher != nil {
		flusher.Flush()
	}

	streamPingTargets(r.Context(), targets, func(_ int, res pingResult) {
		// A failed write means the browser went away; the request context is
		// then cancelled, so the remaining checks wind down on their own.
		if err := enc.Encode(res); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	})
}

// streamPingTargets checks each target with up to pingConcurrency running at
// once and calls emit for every verdict as soon as it is ready. emit is only
// ever called from the caller's goroutine, so it needs no locking. The index
// passed to emit is the target's position in targets.
func streamPingTargets(ctx context.Context, targets []store.Target, emit func(int, pingResult)) {
	// Routed through netgov like every other outbound scan. Redirects are not
	// followed: a 3xx is itself proof the host answered.
	client := netgov.NewClient(pingTimeout, false)

	type indexed struct {
		i   int
		res pingResult
	}
	done := make(chan indexed)

	// The producer runs in its own goroutine so this function can drain done
	// and emit each verdict while checks are still running.
	go func() {
		sem := make(chan struct{}, pingConcurrency)
		var wg sync.WaitGroup
		// The send on sem blocks while pingConcurrency checks are already in
		// flight, which is what keeps the number of running goroutines bounded.
		for i, t := range targets {
			sem <- struct{}{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				done <- indexed{i, pingTarget(ctx, client, t)}
			}()
		}
		wg.Wait()
		close(done)
	}()

	for d := range done {
		emit(d.i, d.res)
	}
}

// pingTargets runs streamPingTargets to completion and returns every verdict
// in the same order as targets, for callers that want the whole batch at once.
func pingTargets(ctx context.Context, targets []store.Target) []pingResult {
	out := make([]pingResult, len(targets))
	streamPingTargets(ctx, targets, func(i int, res pingResult) {
		out[i] = res
	})
	return out
}

// pingTarget checks one target. A value with an explicit scheme is tried
// exactly as written. A bare host is tried over https first and then http,
// the same order the recon scanner uses. The first HTTP response wins.
func pingTarget(ctx context.Context, client *http.Client, t store.Target) pingResult {
	res := pingResult{TargetID: t.ID, Value: t.Value}

	candidates := []string{t.Value}
	if !strings.HasPrefix(t.Value, "http://") && !strings.HasPrefix(t.Value, "https://") {
		candidates = []string{"https://" + t.Value, "http://" + t.Value}
	}

	var lastErr error
	for _, u := range candidates {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		// The body isn't needed, only that a response arrived.
		resp.Body.Close()
		res.Alive = true
		res.StatusCode = resp.StatusCode
		res.URL = u
		return res
	}

	res.Error = lastErr.Error()
	return res
}
