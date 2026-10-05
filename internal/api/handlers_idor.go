package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/idor"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
	"github.com/Indigo6415/Aperture/internal/store"
)

// idorRequest is the request body for POST /api/idor/scan. It mirrors
// idor.Request plus the credential and case wiring every other tool carries
// (see pathTraversalRequest), with a second credential/headers for the
// attacker identity the cross-identity module replays under.
type idorRequest struct {
	// RequestsPerSecond is the Slow/Normal/Fast/Custom scan speed; zero means the default.
	RequestsPerSecond float64 `json:"requestsPerSecond,omitempty"`
	URL               string  `json:"url"`
	// Method is GET or POST. Empty means POST when Body is set, GET otherwise.
	Method      string   `json:"method,omitempty"`
	Body        string   `json:"body,omitempty"`
	ContentType string   `json:"contentType,omitempty"`
	Params      []string `json:"params,omitempty"`
	MineParams  bool     `json:"mineParams,omitempty"`
	// CredentialID is the owner identity: the user who legitimately owns the
	// objects under test. Its headers/cookie are merged into Headers.
	CredentialID string `json:"credentialId,omitempty"`
	// AttackerCredentialID is the second identity. When set, the cross-identity
	// module replays each request under it to prove object-level authorization.
	AttackerCredentialID string            `json:"attackerCredentialId,omitempty"`
	Headers              map[string]string `json:"headers,omitempty"`
	// AttackerHeaders are extra headers (e.g. a Cookie) for the second identity,
	// merged on top of the attacker credential.
	AttackerHeaders map[string]string `json:"attackerHeaders,omitempty"`
	CaseID          string            `json:"caseId,omitempty"`
}

// idorTimeout bounds a full run. IDOR fans a large mutation catalog across
// every reference point, so a complex target takes time even at the default
// rate.
const idorTimeout = 10 * time.Minute

// handleIDOR runs internal/idor.Run against req.URL and streams progress as a
// queued scan, the same as the other point-based scanners. A second credential
// (or stripped auth) drives the cross-identity module that confirms broken
// object-level authorization.
func (s *Server) handleIDOR(w http.ResponseWriter, r *http.Request) {
	var req idorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	rps, err := scanRate(req.RequestsPerSecond)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	if req.URL == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("url is required"))
		return
	}

	// The owner identity: the credential whose objects are the baseline.
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

	// The attacker identity: an optional second credential the cross-identity
	// module replays under.
	if req.AttackerCredentialID != "" {
		cred, err := s.store.GetCredential(req.AttackerCredentialID)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusBadRequest, fmt.Errorf("attacker credential %s not found", req.AttackerCredentialID))
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		req.AttackerHeaders = mergedCredentialHeaders(cred, req.AttackerHeaders)
	}

	s.queueScan(w, streamedScan{
		rps:     rps,
		caseID:  req.CaseID,
		target:  req.URL,
		tool:    "idor",
		timeout: idorTimeout,
		run: func(ctx context.Context, rep scanprogress.Reporter) (scanOutcome, error) {
			resp, err := idor.Run(ctx, idor.Request{
				Progress:        rep,
				URL:             req.URL,
				Method:          req.Method,
				Body:            req.Body,
				ContentType:     req.ContentType,
				Params:          req.Params,
				MineParams:      req.MineParams,
				Headers:         req.Headers,
				AttackerHeaders: req.AttackerHeaders,
			})
			if err != nil {
				return scanOutcome{}, err
			}

			severity := "info"
			total := 0
			// Roll up the worst severity across modules that actually reported.
			for _, m := range resp.Modules {
				total += len(m.Findings)
				if len(m.Findings) > 0 {
					severity = maxSeverity(severity, m.Severity)
				}
			}
			summary := "no issues found"
			if total > 0 {
				summary = fmt.Sprintf("%d possible IDOR issue(s) across %d check(s) (%d point(s), %d test(s))", total, len(resp.Modules), resp.PointsTested, resp.TestsRun)
			}
			// Say when no second identity was configured, so an empty
			// cross-identity result is not mistaken for a clean one.
			if len(resp.Identities) == 0 {
				summary += "; cross-identity not tested (no second credential, request carries no auth to drop)"
			}
			return scanOutcome{result: resp, severity: severity, summary: summary}, nil
		},
	})
}
