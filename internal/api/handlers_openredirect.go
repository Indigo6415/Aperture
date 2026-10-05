package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/collaborator"
	"github.com/Indigo6415/Aperture/internal/openredirect"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
	"github.com/Indigo6415/Aperture/internal/store"
)

// openRedirectRequest is the request body for POST /api/openredirect/scan --
// mirrors openredirect.Request field-for-field plus the credential/case
// wiring every other tool's request carries (see pwResetRequest).
type openRedirectRequest struct {
	// RequestsPerSecond is the scan speed the Slow/Normal/Fast/Custom control sends; zero means scanRate's default.
	RequestsPerSecond float64  `json:"requestsPerSecond,omitempty"`
	URL               string   `json:"url"`
	Params            []string `json:"params,omitempty"`
	MineParams        bool     `json:"mineParams,omitempty"`
	// Discover also scans redirect-shaped URLs Common Crawl has seen under the
	// same host (see openredirect.Request.Discover). Off by default.
	Discover     bool              `json:"discover,omitempty"`
	CredentialID string            `json:"credentialId,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	CaseID       string            `json:"caseId,omitempty"`
	// Callback optionally names a long-lived callback server the operator
	// picked from their own Callback picker (see collaborator.Ref) instead of
	// the fresh throwaway token handleOpenRedirect mints by default -- lets a
	// human watch one shared listener in the Collaborator tab across an
	// entire scan (and across other scanners/tests reusing the same server).
	// Every scan is confirmation-gated via a live callback either way -- see
	// openredirect.Request.CallbackBase.
	Callback *collaborator.Ref `json:"callback,omitempty"`
	// FollowRedirects is a pointer so an omitted field can default to on
	// (the scanner's default) instead of decoding to false. Off confines
	// confirmation to the first Location hop.
	FollowRedirects *bool `json:"followRedirects,omitempty"`
}

// collabCallbackHost strips the scheme from a scheme://host[:port] base (as
// collabCallbackBase returns it), leaving the bare host[:port] that
// openredirect.Request.CallbackBase expects. Anything without a known scheme
// is returned unchanged.
func collabCallbackHost(base string) string {
	base = strings.TrimPrefix(base, "https://")
	return strings.TrimPrefix(base, "http://")
}

// openRedirectTimeout bounds a full run: every module's probes (about two
// dozen payload shapes per candidate parameter, roughly 35 parameters by
// default, plus CR/LF, IP-literal, path-segment, Referer, and header probes)
// share one concurrency limit, so the total run time is what needs the
// headroom.
const openRedirectTimeout = 6 * time.Minute

// openRedirectDiscoverTimeout bounds a run that also scans Common Crawl's
// discovered endpoints. Each endpoint is a full pass of its own, so the budget
// covers the base run plus that many more.
const openRedirectDiscoverTimeout = 20 * time.Minute

// handleOpenRedirect runs internal/openredirect.Run against req.URL
// synchronously and returns the full result in one response -- same posture
// as handlePwReset/handleCORSScan.
func (s *Server) handleOpenRedirect(w http.ResponseWriter, r *http.Request) {
	var req openRedirectRequest
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

	// Follow redirects defaults to on: a missing field means on, and only an
	// explicit false turns it off.
	followRedirects := true
	if req.FollowRedirects != nil {
		followRedirects = *req.FollowRedirects
	}

	orReq := openredirect.Request{URL: req.URL, Params: req.Params, MineParams: req.MineParams, Discover: req.Discover, Headers: req.Headers, FollowRedirects: followRedirects}
	// CallbackBase is a bare "host[:port]/path" with no scheme -- every
	// payload module's build() prepends its own scheme (or none at all, for
	// the protocol-relative/backslash-trick payloads), so baking one in here
	// would just end up double-schemed. Host-header and forwarded-host probes
	// use only the host portion, and their confirmation adds the path back.
	//
	// Always wired, same as handleSSRF's OOBConfig: a redirect is only ever
	// reported once following it actually reaches a live listener, so this
	// never falls back to the old unconfirmed "the response merely looks
	// like a redirect" heuristic. When the operator hasn't picked a callback
	// server of their own, this mints a fresh throwaway token against
	// Aperture's own collaborator registry instead -- the operator never has
	// to open the Callback picker just to get a confirmed result.
	// The Aperture listener's base comes from collabCallbackBase, not r.Host:
	// r.Host is the login-protected UI port (e.g. 127.0.0.1:8337), which doesn't
	// serve /collab/ at all, so every confirmation request 404'd and no hit was
	// ever recorded. The base carries a scheme, which CallbackBase must not, so
	// it is stripped here.
	if req.Callback != nil {
		if req.Callback.Provider == "webhooksite" {
			orReq.CallbackBase = strings.TrimPrefix(collaborator.WebhookSiteCallbackURL(req.Callback.Token), "https://")
		} else {
			orReq.CallbackBase = collabCallbackHost(s.collabCallbackBase(r)) + "/collab/" + req.Callback.Token
		}
		orReq.CallbackPoll = openredirect.CallbackPollConfig{
			Registry: s.collab,
			Token:    req.Callback.Token,
			Provider: req.Callback.Provider,
		}
	} else {
		token := s.collab.NewToken()
		orReq.CallbackBase = collabCallbackHost(s.collabCallbackBase(r)) + "/collab/" + token
		orReq.CallbackPoll = openredirect.CallbackPollConfig{Registry: s.collab, Token: token, Provider: "aperture"}
	}

	timeout := openRedirectTimeout
	if req.Discover {
		timeout = openRedirectDiscoverTimeout
	}
	s.queueScan(w, streamedScan{
		rps:     rps,
		caseID:  req.CaseID,
		target:  req.URL,
		tool:    "openredirect",
		timeout: timeout,
		run: func(ctx context.Context, rep scanprogress.Reporter) (scanOutcome, error) {
			orReq.Progress = rep
			resp, err := openredirect.Run(ctx, orReq)
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
				summary = fmt.Sprintf("%d issue(s) found across %d check(s)", total, len(resp.Modules))
			}
			return scanOutcome{result: resp, severity: severity, summary: summary}, nil
		},
	})
}
