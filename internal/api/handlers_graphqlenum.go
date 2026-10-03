package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/graphqlenum"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
	"github.com/Indigo6415/Aperture/internal/store"
)

// graphqlEnumRequest is the request body for POST /api/graphqlenum/scan. It
// mirrors graphqlenum.Request field-for-field, plus the credential/case
// wiring every other tool's request carries (see bypass403Request).
type graphqlEnumRequest struct {
	URL          string            `json:"url"`
	CredentialID string            `json:"credentialId,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	CaseID       string            `json:"caseId,omitempty"`
}

// graphqlEnumTimeout bounds a full run: one baseline request, up to five
// introspection attempts, then seven more check modules' own request
// batches, all but the introspection step running concurrently against one
// endpoint.
const graphqlEnumTimeout = 60 * time.Second

// handleGraphQLEnum runs internal/graphqlenum.Run against req.URL
// synchronously and returns the full result in one response -- same
// posture as handleBypass403/handlePwReset: one endpoint, finishes well
// under graphqlEnumTimeout in practice, no meaningful "module finished"
// progress worth streaming.
func (s *Server) handleGraphQLEnum(w http.ResponseWriter, r *http.Request) {
	var req graphqlEnumRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	if req.URL == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("url is required"))
		return
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
		req.Headers = mergedCredentialHeaders(cred, req.Headers)
	}
	req.Headers = s.applyDomainCookie(req.CaseID, req.URL, req.Headers)

	s.queueScan(w, streamedScan{
		caseID:  req.CaseID,
		target:  req.URL,
		tool:    "graphqlenum",
		timeout: graphqlEnumTimeout,
		run: func(ctx context.Context, rep scanprogress.Reporter) (scanOutcome, error) {
			resp, err := graphqlenum.Run(ctx, graphqlenum.Request{Progress: rep, URL: req.URL, Headers: req.Headers})
			if err != nil {
				return scanOutcome{}, err
			}

			severity := "info"
			summary := "does not look like a GraphQL endpoint"
			if resp.Baseline.Confirmed {
				total := 0
				// Same "only a module that actually found something drags the
				// summary severity up" rule as handlePwReset.
				for _, m := range resp.Modules {
					total += len(m.Findings)
					if len(m.Findings) > 0 {
						severity = maxSeverity(severity, m.Severity)
					}
				}
				summary = "no issues found"
				if total > 0 {
					summary = fmt.Sprintf("%d issue(s) found across %d check(s)", total, len(resp.Modules))
				}
			}
			return scanOutcome{result: resp, severity: severity, summary: summary}, nil
		},
	})
}
