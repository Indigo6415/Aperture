package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/breach"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
	"github.com/Indigo6415/Aperture/internal/store"
)

// breachCheckRequest is the request body for POST /api/breach/check.
type breachCheckRequest struct {
	Emails []string `json:"emails"`
	// CaseID optionally scopes this check to a case -- see
	// secretScanRequest.CaseID's doc comment.
	CaseID string `json:"caseId,omitempty"`
}

// breachEmailResult is one email's outcome -- Error is set instead of
// Breaches when that one lookup failed, so one bad address (or a
// mid-batch rate limit) doesn't fail the whole batch's response.
type breachEmailResult struct {
	Email    string          `json:"email"`
	Breaches []breach.Breach `json:"breaches"`
	Error    string          `json:"error,omitempty"`
}

type breachCheckResponse struct {
	Results []breachEmailResult `json:"results"`
}

// maxBreachEmailsPerCheck bounds one request's batch size -- HIBP's rate
// limit (see internal/breach's limiter) already paces requests out, so a
// large batch would otherwise just make one click hang for minutes.
const maxBreachEmailsPerCheck = 20

// breachCheckTimeout is generous: at up to maxBreachEmailsPerCheck emails
// paced by HIBP's 10-req/minute limit, a full batch can take a couple of
// minutes on its own.
const breachCheckTimeout = 3 * time.Minute

// handleBreachCheck looks up every email in req.Emails against
// HaveIBeenPwned (internal/breach.Lookup), one at a time -- sequential, not
// concurrent, since HIBP's rate limit is shared across the whole key
// regardless of how many requests are in flight at once. Requires an HIBP
// API key to already be configured (see Settings/handleSetHIBPKey); this
// isn't optional the way DNSDumpster/NVD's keys are.
func (s *Server) handleBreachCheck(w http.ResponseWriter, r *http.Request) {
	var req breachCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	emails := make([]string, 0, len(req.Emails))
	seen := map[string]bool{}
	for _, e := range req.Emails {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" || seen[e] {
			continue
		}
		seen[e] = true
		emails = append(emails, e)
	}
	if len(emails) == 0 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("at least one email is required"))
		return
	}
	if len(emails) > maxBreachEmailsPerCheck {
		emails = emails[:maxBreachEmailsPerCheck]
	}

	apiKey, _, err := s.store.GetSetting(settingHIBPAPIKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if apiKey == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("an HaveIBeenPwned API key is required -- add one in Settings"))
		return
	}

	s.queueScan(w, streamedScan{
		caseID:  req.CaseID,
		target:  strings.Join(emails, ", "),
		tool:    "breach",
		timeout: breachCheckTimeout,
		run: func(ctx context.Context, rep scanprogress.Reporter) (scanOutcome, error) {
			// Lookups run one after another against HIBP's rate limit, so every
			// email is planned up front and starts only when its own lookup does.
			checks := make([]scanprogress.Check, len(emails))
			for i, email := range emails {
				checks[i] = scanprogress.Check{ID: email, Label: email}
			}
			rep.Plan(checks...)

			resp := breachCheckResponse{Results: make([]breachEmailResult, 0, len(emails))}
			worstSeverity := "info"
			for _, email := range emails {
				rep.Start(email)
				result := breachEmailResult{Email: email}
				breaches, err := breach.Lookup(ctx, email, apiKey)
				if err != nil {
					result.Error = err.Error()
				} else {
					result.Breaches = breaches
				}
				rep.Done(email, len(breaches), err)
				resp.Results = append(resp.Results, result)

				if len(breaches) > 0 {
					sev := "high"
					for _, b := range breaches {
						if b.IsSensitive || containsSensitiveDataClass(b.DataClasses) {
							sev = "critical"
							break
						}
					}
					worstSeverity = maxSeverity(worstSeverity, sev)
				}
			}

			total := 0
			for _, r := range resp.Results {
				total += len(r.Breaches)
			}
			summary := fmt.Sprintf("%d breach(es) across %d email(s)", total, len(emails))
			return scanOutcome{result: resp, severity: worstSeverity, summary: summary}, nil
		},
	})
}

// breachCrawlEmailsRequest is the request body for POST
// /api/breach/crawl-emails -- same shape as secretScanRequest, since this
// runs the very same crawl (see breach.CrawlForEmails' doc comment).
type breachCrawlEmailsRequest struct {
	// RequestsPerSecond is the scan speed the Slow/Normal/Fast/Custom control sends; zero means scanRate's default.
	RequestsPerSecond float64           `json:"requestsPerSecond,omitempty"`
	URL               string            `json:"url"`
	RecursionDepth    int               `json:"recursionDepth,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
	// CredentialID optionally names a saved case credential (see
	// handlers_credentials.go) merged into Headers.
	CredentialID string `json:"credentialId,omitempty"`
	// CaseID optionally scopes this crawl to a case -- see
	// secretScanRequest.CaseID's doc comment.
	CaseID string `json:"caseId,omitempty"`
}

// maxCrawlEmailsRecursionDepth mirrors maxSecretScanRecursionDepth.
const maxCrawlEmailsRecursionDepth = 3

// crawlEmailsTimeout mirrors secretScanTimeout -- same bounded crawl, same
// budget reasoning.
const crawlEmailsTimeout = 45 * time.Second

// handleBreachCrawlEmails runs breach.CrawlForEmails against req.URL
// synchronously and returns every address found in one response -- the
// on-ramp into handleBreachCheck for an operator who doesn't have a
// starting list of addresses yet. Unlike handleBreachCheck, this needs no
// API key: it's Aperture's own crawl, not a third-party lookup. Mirrors
// handleSecretScan almost exactly -- same crawl, same one-target-per-
// request shape (see BreachCheck.tsx, which fires one of these per
// selected target and shows each its own progress card, same as
// SecretScan.tsx).
func (s *Server) handleBreachCrawlEmails(w http.ResponseWriter, r *http.Request) {
	var req breachCrawlEmailsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	if req.URL == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("url is required"))
		return
	}
	if req.RecursionDepth < 0 {
		req.RecursionDepth = 0
	}
	if req.RecursionDepth > maxCrawlEmailsRecursionDepth {
		req.RecursionDepth = maxCrawlEmailsRecursionDepth
	}
	// Rejects an out-of-range rate before any credential lookup or queueing.
	rps, err := scanRate(req.RequestsPerSecond)
	if err != nil {
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
		rps:    rps,
		caseID: req.CaseID,
		target: req.URL,
		// Saved under its own tool name ("breach-crawl") rather than "breach" --
		// the check handler above persists a different response shape under
		// "breach" (per-email lookup results), and the two must not collide
		// when either tab restores its own history (see loadCaseScans in
		// web/src/scanHistory.ts).
		tool:    "breach-crawl",
		timeout: crawlEmailsTimeout,
		run: func(ctx context.Context, rep scanprogress.Reporter) (scanOutcome, error) {
			resp, err := breach.CrawlForEmails(ctx, breach.CrawlRequest{
				URL:            req.URL,
				RecursionDepth: req.RecursionDepth,
				Headers:        req.Headers,
				Progress:       rep,
			})
			if err != nil {
				return scanOutcome{}, err
			}
			summary := fmt.Sprintf("%d email(s) found across %d page(s)", len(resp.Emails), len(resp.PagesScanned))
			return scanOutcome{result: resp, severity: "info", summary: summary}, nil
		},
	})
}

// containsSensitiveDataClass flags a breach as critical (not just "high,
// breach found") when the exposed data includes something more sensitive
// than an email/password pair -- the kind of exposure that's an immediate
// follow-up action (credential stuffing, targeted phishing, financial
// fraud) rather than just "rotate this password."
func containsSensitiveDataClass(classes []string) bool {
	for _, c := range classes {
		switch strings.ToLower(c) {
		case "passwords", "credit cards", "social security numbers", "security questions and answers", "private messages", "financial information":
			return true
		}
	}
	return false
}
