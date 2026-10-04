package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/csrf"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
	"github.com/Indigo6415/Aperture/internal/store"
)

// csrfScanRequest is the request body for POST /api/csrf/scan -- mirrors
// csrf.Request field-for-field plus the credential/case wiring every other
// tool's request carries (see pwResetRequest). A credential matters more
// here than for the other new scanners: an unauthenticated crawl typically
// only reaches a login form, never the actual state-changing forms this
// scan exists to check.
type csrfScanRequest struct {
	// RequestsPerSecond is the scan speed the Slow/Normal/Fast/Custom control sends; zero means scanRate's default.
	RequestsPerSecond float64           `json:"requestsPerSecond,omitempty"`
	URL               string            `json:"url"`
	RecursionDepth    int               `json:"recursionDepth,omitempty"`
	MaxPages          int               `json:"maxPages,omitempty"`
	CredentialID      string            `json:"credentialId,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
	CaseID            string            `json:"caseId,omitempty"`

	// APIURL/APIMethod/APIBody optionally request the one active check this
	// scanner has -- see csrf.Request's own doc comment.
	APIURL    string `json:"apiUrl,omitempty"`
	APIMethod string `json:"apiMethod,omitempty"`
	APIBody   string `json:"apiBody,omitempty"`

	// TokenProbe optionally requests the token-enforcement check, which sends
	// state-changing requests to one named form endpoint. It only runs when
	// the request also sets Confirm -- see csrfTokenProbeRequest.
	TokenProbe *csrfTokenProbeRequest `json:"tokenProbe,omitempty"`
}

// csrfTokenProbeRequest is the wire shape of csrf.TokenProbe. Confirm is the
// operator's explicit acknowledgement that the check replays the form with the
// token removed, emptied and tampered, so it has real effects on the target.
// Without it the handler refuses the request rather than silently skipping.
type csrfTokenProbeRequest struct {
	URL     string `json:"url"`
	Method  string `json:"method,omitempty"`
	Body    string `json:"body"`
	Field   string `json:"field"`
	Confirm bool   `json:"confirm"`
}

// csrfTokenProbeMethods are the methods the token check will send. A form
// submission is a POST in nearly every case; the others cover REST-style forms.
var csrfTokenProbeMethods = map[string]bool{"POST": true, "PUT": true, "PATCH": true, "DELETE": true}

// tokenProbeFor validates a token-probe request and converts it to the csrf
// package's type. A nil request means the operator did not ask for the check.
// Any other incomplete or unconfirmed request is an error, so the scan never
// starts with a half-specified state-changing probe.
func tokenProbeFor(in *csrfTokenProbeRequest) (*csrf.TokenProbe, error) {
	if in == nil || strings.TrimSpace(in.URL) == "" {
		return nil, nil
	}
	if !in.Confirm {
		return nil, fmt.Errorf("tokenProbe sends state-changing requests to %s; set confirm to true to run it", in.URL)
	}
	if strings.TrimSpace(in.Field) == "" || strings.TrimSpace(in.Body) == "" {
		return nil, fmt.Errorf("tokenProbe needs both the form body and the name of its token field")
	}
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	if method == "" {
		method = "POST"
	}
	if !csrfTokenProbeMethods[method] {
		return nil, fmt.Errorf("tokenProbe method %q is not one of POST, PUT, PATCH, DELETE", in.Method)
	}
	return &csrf.TokenProbe{URL: strings.TrimSpace(in.URL), Method: method, Body: in.Body, Field: strings.TrimSpace(in.Field)}, nil
}

// csrfScanTimeout is more generous than the other new scanners' handler
// timeouts -- a crawl fetches pages sequentially (see internal/csrf.crawl),
// up to crawlMaxPagesCap of them, rather than firing everything
// concurrently.
const csrfScanTimeout = 120 * time.Second

// handleCSRF validates the request and registers a CSRF run, returning its
// scan ID -- the crawl and checks stream their progress over /ws/scans/{id}.
func (s *Server) handleCSRF(w http.ResponseWriter, r *http.Request) {
	var req csrfScanRequest
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
	req.APIURL = strings.TrimSpace(req.APIURL)
	if req.URL == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("url is required"))
		return
	}
	tokenProbe, err := tokenProbeFor(req.TokenProbe)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	// The optional endpoints are named by the operator, not crawled, so they
	// must be checked against the case scope here. netgov enforces scope on
	// every real request as well, but refusing early gives a clear 400.
	scope, err := s.scopeFor(req.CaseID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	named := []string{req.APIURL}
	if tokenProbe != nil {
		named = append(named, tokenProbe.URL)
	}
	if err := checkTargetsInScope(scope, named...); err != nil {
		writeError(w, http.StatusBadRequest, err)
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
		rps:     rps,
		caseID:  req.CaseID,
		target:  req.URL,
		tool:    "csrf",
		timeout: csrfScanTimeout,
		run: func(ctx context.Context, rep scanprogress.Reporter) (scanOutcome, error) {
			resp, err := csrf.Run(ctx, csrf.Request{
				URL: req.URL, RecursionDepth: req.RecursionDepth, MaxPages: req.MaxPages, Headers: req.Headers,
				APIURL: req.APIURL, APIMethod: req.APIMethod, APIBody: req.APIBody,
				TokenProbe: tokenProbe,
				Progress:   rep,
			})
			if err != nil {
				return scanOutcome{}, err
			}

			severity := "info"
			total := 0
			for _, m := range resp.Modules {
				total += len(m.Findings)
				if len(m.Findings) > 0 {
					severity = maxSeverity(severity, m.Severity)
				}
			}
			summary := "no issues found"
			if total > 0 {
				summary = fmt.Sprintf("%d issue(s) found across %d check(s) (%d page(s), %d form(s) crawled)", total, len(resp.Modules), len(resp.PagesScanned), resp.FormsFound)
			}
			return scanOutcome{result: resp, severity: severity, summary: summary}, nil
		},
	})
}
