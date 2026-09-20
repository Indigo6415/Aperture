package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/store"
)

// jobTemplateOptions is what a saved template's Options JSON blob decodes
// to. Deliberately flat (not engine.ScanOptions nested inside a wrapper)
// so it's a byte-for-byte match of the frontend's JobOptions type --
// the same object already built for a startJobRequest can be POSTed here
// verbatim to save it, and a fetched template can be applied straight back
// onto the launcher's state.
type jobTemplateOptions struct {
	Preset         string          `json:"preset,omitempty"`
	Threads        int             `json:"threads,omitempty"`
	TimeoutSeconds int             `json:"timeoutSeconds,omitempty"`
	RateLimit      int             `json:"rateLimit,omitempty"`
	Wordlist       string          `json:"wordlist,omitempty"`
	Scheme         string          `json:"scheme,omitempty"`
	HostSuffix     string          `json:"hostSuffix,omitempty"`
	Recursive      bool            `json:"recursive,omitempty"`
	FFuf           *FFufJobOptions `json:"ffuf,omitempty"`
}

// saveJobTemplateRequest is the request body for POST /api/job-templates.
type saveJobTemplateRequest struct {
	Tool    string             `json:"tool"`
	Name    string             `json:"name"`
	Options jobTemplateOptions `json:"options"`
}

// jobTemplateResponse is store.JobTemplate reshaped for the wire: Options
// is embedded as raw JSON (json.RawMessage) rather than store.JobTemplate's
// own opaque string field, so the frontend's JobTemplate.options decodes
// straight to a JobOptions object instead of a double-encoded JSON string.
type jobTemplateResponse struct {
	ID        string          `json:"id"`
	Tool      string          `json:"tool"`
	Name      string          `json:"name"`
	Options   json.RawMessage `json:"options"`
	CreatedAt time.Time       `json:"createdAt"`
}

func toJobTemplateResponse(t store.JobTemplate) jobTemplateResponse {
	return jobTemplateResponse{ID: t.ID, Tool: t.Tool, Name: t.Name, Options: json.RawMessage(t.Options), CreatedAt: t.CreatedAt}
}

func (s *Server) handleListJobTemplates(w http.ResponseWriter, r *http.Request) {
	tool := r.URL.Query().Get("tool")
	if tool == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("tool is required"))
		return
	}
	templates, err := s.store.ListJobTemplates(tool)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	resp := make([]jobTemplateResponse, len(templates))
	for i, t := range templates {
		resp[i] = toJobTemplateResponse(t)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleSaveJobTemplate(w http.ResponseWriter, r *http.Request) {
	var req saveJobTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.Tool = strings.TrimSpace(req.Tool)
	req.Name = strings.TrimSpace(req.Name)
	if req.Tool == "" || req.Name == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("tool and name are required"))
		return
	}

	optionsJSON, err := json.Marshal(req.Options)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	tmplID := newID()
	if err := s.store.SaveJobTemplate(store.JobTemplate{ID: tmplID, Tool: req.Tool, Name: req.Name, Options: string(optionsJSON)}); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// CreatedAt is set by SaveJobTemplate's own INSERT (time.Now(), not
	// taken from the struct passed in) -- re-fetch so the response reflects
	// the actual stored value rather than a zero time.
	templates, err := s.store.ListJobTemplates(req.Tool)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	for _, t := range templates {
		if t.ID == tmplID {
			writeJSON(w, http.StatusCreated, toJobTemplateResponse(t))
			return
		}
	}
	writeError(w, http.StatusInternalServerError, fmt.Errorf("job template saved but could not be re-read"))
}

func (s *Server) handleDeleteJobTemplate(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteJobTemplate(r.PathValue("id")); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
