package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/Indigo6415/Aperture/internal/collaborator"
	"github.com/Indigo6415/Aperture/internal/engine"
	"github.com/Indigo6415/Aperture/internal/netgov"
	"github.com/Indigo6415/Aperture/internal/store"
)

// requestLogResponse is the list view of one node's request log.
type requestLogResponse struct {
	Requests []store.RequestRecord `json:"requests"`
	// Limit is the most requests one node keeps. A log exactly this long was
	// cut short, so the UI can say so instead of implying it is complete.
	Limit int `json:"limit"`
}

// directScanNodeID is the node name a direct scan's requests are filed under.
// A scan started from a tool tab has no flow node, so its log is keyed by the
// scan's own ID with this fixed node. RecordRequest's frontend twin is
// DIRECT_SCAN_NODE_ID in RequestLogModal.tsx; the two must stay equal.
const directScanNodeID = "scan"

// requestLogSink returns the engine hook that persists each node's HTTP
// exchanges, converting netgov's view of a request into the stored row.
func requestLogSink(st *store.Store) engine.ExchangeSink {
	return func(runID, nodeID string, ex netgov.Exchange) {
		st.RecordRequest(requestRecord(runID, nodeID, ex))
	}
}

// requestRecord converts one netgov exchange into the row the request log
// stores, filed under the given run and node.
func requestRecord(runID, nodeID string, ex netgov.Exchange) store.RequestRecord {
	return store.RequestRecord{
		RunID:       runID,
		NodeID:      nodeID,
		Method:      ex.Method,
		URL:         ex.URL,
		Host:        ex.Host,
		StatusCode:  ex.Status,
		Size:        ex.Size,
		TTFBMs:      ex.TTFB.Milliseconds(),
		Error:       ex.Error,
		RequestRaw:  ex.RequestRaw,
		ResponseRaw: ex.ResponseRaw,
		Timestamp:   ex.Timestamp,
		Ref:         ex.Ref,
		FromRef:     ex.FromRef,
		Location:    ex.Location,
	}
}

// withScanRecorder returns ctx with a request recorder that files every
// exchange the scan makes under scanID, capped like a job node so one noisy
// scan can't flood storage. Every direct scan calls this, so every request it
// sends can be inspected afterwards.
func (s *Server) withScanRecorder(ctx context.Context, scanID string) context.Context {
	return netgov.WithRecorder(ctx, netgov.LimitRecorder(netgov.RecorderFunc(func(ex netgov.Exchange) {
		s.store.RecordRequest(requestRecord(scanID, directScanNodeID, ex))
	}), engine.MaxRecordedExchangesPerNode))
}

// handleListNodeRequests returns the request log for one node of a run. It
// omits raw bodies so opening the view stays cheap however large the log. A
// ?q= parameter narrows the log to rows whose method, URL, status, or raw
// request/response contains that text.
func (s *Server) handleListNodeRequests(w http.ResponseWriter, r *http.Request) {
	var list []store.RequestRecord
	var err error
	if q := r.URL.Query().Get("q"); q != "" {
		list, err = s.store.SearchRequests(r.PathValue("id"), r.PathValue("nodeId"), q)
	} else {
		list, err = s.store.ListRequests(r.PathValue("id"), r.PathValue("nodeId"))
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// Counted per row so the list can mark a redirect that reached a callback.
	for i := range list {
		list[i].CallbackCount = len(s.callbacksFor(list[i]))
	}
	writeJSON(w, http.StatusOK, requestLogResponse{Requests: list, Limit: engine.MaxRecordedExchangesPerNode})
}

// handleGetNodeRequest returns one logged exchange with its full raw request
// and response, for the expanded view of a row.
func (s *Server) handleGetNodeRequest(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("requestId"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	rec, err := s.store.GetRequest(r.PathValue("id"), r.PathValue("nodeId"), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, requestDetailResponse{RequestRecord: rec, Callbacks: s.callbacksFor(rec)})
}

// scanResultHits reads a direct scan's saved result and returns the request
// behind each finding it reports. Every native scanner's result has the same
// shape: modules, each with findings, and a finding's request is the exact
// method and URL it sent. Findings without a captured request (info-only
// notes, for example) contribute nothing, and so do tools with another shape.
func scanResultHits(data []byte) []store.RequestHit {
	var result struct {
		Modules []struct {
			Findings []struct {
				Request *struct {
					Method string `json:"method"`
					URL    string `json:"url"`
				} `json:"request"`
			} `json:"findings"`
		} `json:"modules"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}
	var hits []store.RequestHit
	for _, m := range result.Modules {
		for _, f := range m.Findings {
			if f.Request != nil && f.Request.URL != "" {
				hits = append(hits, store.RequestHit{Method: f.Request.Method, URL: f.Request.URL})
			}
		}
	}
	return hits
}

// requestDetailResponse is one logged exchange with its raw request and
// response, plus the collaborator hits its Location led to.
type requestDetailResponse struct {
	store.RequestRecord
	Callbacks []collaborator.Interaction `json:"callbacks,omitempty"`
}

// callbackToken matches a collaborator token inside a Location. Tokens are 20
// lowercase hex characters (see collaborator.NewToken), and the surrounding
// characters must not be hex, so a longer hex run isn't mistaken for one.
var callbackToken = regexp.MustCompile(`(?:^|[^0-9a-f])([0-9a-f]{20})(?:[^0-9a-f]|$)`)

// callbacksFor returns the collaborator hits that a redirect led to. A hit counts
// when it arrived after the exchange was sent, on a token named in the exchange's
// Location. When the hit carries an identifier (the label a test chose for its
// own address), that identifier must also appear in the Location, so a shared
// token can't pin an unrelated hit on this redirect. The hit is only read here,
// so the collaborator keeps its history for the Collaborator tab.
func (s *Server) callbacksFor(rec store.RequestRecord) []collaborator.Interaction {
	if rec.Location == "" || s.collab == nil {
		return nil
	}
	var out []collaborator.Interaction
	seen := map[string]bool{}
	for _, m := range callbackToken.FindAllStringSubmatch(rec.Location, -1) {
		token := m[1]
		if seen[token] {
			continue
		}
		seen[token] = true
		for _, in := range s.collab.Poll(token) {
			if in.Timestamp.Before(rec.Timestamp) {
				continue
			}
			if in.Identifier != "" && !strings.Contains(rec.Location, in.Identifier) {
				continue
			}
			out = append(out, in)
		}
	}
	return out
}
