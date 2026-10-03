package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/Indigo6415/Aperture/internal/store"
)

// cookieVaultEntry is one domain's row in a case's cookie vault: GET
// returns one per domain the case knows about (from its targets, plus any
// domain that still has a saved cookie even if its target was later
// removed), with whatever cookie is currently saved for it, if any.
type cookieVaultEntry struct {
	Domain string `json:"domain"`
	Cookie string `json:"cookie,omitempty"`
}

// handleListCookieVault handles GET /api/cases/{id}/cookie-vault, returning
// every domain this case has seen (from its targets) merged with any
// per-domain cookie already saved, so the UI can render the full vault --
// including domains with nothing saved yet -- in one request.
func (s *Server) handleListCookieVault(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("id")
	if _, err := s.store.GetCase(caseID); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	targets, err := s.store.ListTargets(caseID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	saved, err := s.store.ListDomainCookies(caseID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	cookies := make(map[string]string, len(saved))
	for _, c := range saved {
		cookies[c.Domain] = c.Cookie
	}
	domains := make(map[string]bool, len(targets)+len(saved))
	for _, t := range targets {
		if d := hostFromTarget(t.Value); d != "" {
			domains[d] = true
		}
	}
	for d := range cookies {
		domains[d] = true
	}

	out := make([]cookieVaultEntry, 0, len(domains))
	for d := range domains {
		out = append(out, cookieVaultEntry{Domain: d, Cookie: cookies[d]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	writeJSON(w, http.StatusOK, out)
}

// setCookieVaultEntryRequest is the request body for PUT
// /api/cases/{id}/cookie-vault/{domain}.
type setCookieVaultEntryRequest struct {
	Cookie string `json:"cookie"`
}

// handleSetCookieVaultEntry handles PUT /api/cases/{id}/cookie-vault/{domain}:
// saves (or, given a blank cookie, clears) the Cookie header automatically
// attached to every request this case makes against domain -- see
// applyDomainCookie for where that's applied.
func (s *Server) handleSetCookieVaultEntry(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("id")
	if _, err := s.store.GetCase(caseID); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	domain := strings.ToLower(strings.TrimSpace(r.PathValue("domain")))
	if domain == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("domain is required"))
		return
	}

	var req setCookieVaultEntryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	cookie := strings.TrimSpace(req.Cookie)
	if err := s.store.SetDomainCookie(caseID, domain, cookie); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, cookieVaultEntry{Domain: domain, Cookie: cookie})
}

// hostFromTarget extracts the lowercased hostname a target value (bare
// domain, host:port, or full URL) resolves to, or "" if it doesn't look
// like a host at all (e.g. a bare path). Shared by the vault's domain
// listing above and applyDomainCookie below, so both agree on what "the
// domain" of a given string means.
func hostFromTarget(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	raw := value
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// applyDomainCookie merges caseID's saved cookie-vault entry for rawURL's
// domain into headers, filling in "Cookie" only when headers doesn't
// already set one -- an explicit per-request Cookie, whether typed by hand
// or supplied by a chosen Credential, always takes precedence over the
// vault's automatic one. caseID or rawURL being empty, or no cookie being
// saved for that domain, all leave headers untouched.
func (s *Server) applyDomainCookie(caseID, rawURL string, headers map[string]string) map[string]string {
	if caseID == "" {
		return headers
	}
	for k := range headers {
		if strings.EqualFold(k, "Cookie") {
			return headers
		}
	}
	domain := hostFromTarget(rawURL)
	if domain == "" {
		return headers
	}
	cookie, err := s.store.CookieForDomain(caseID, domain)
	if err != nil || cookie == "" {
		return headers
	}
	merged := make(map[string]string, len(headers)+1)
	maps.Copy(merged, headers)
	merged["Cookie"] = cookie
	return merged
}
