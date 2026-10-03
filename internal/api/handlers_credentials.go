package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/store"
)

// addCredentialRequest is the request body for POST /api/cases/{id}/credentials.
// Username/Password/LoginURL are optional and, together, turn this into a
// "test credential" -- see the credentials table's schema comment in
// internal/store/store.go.
type addCredentialRequest struct {
	Name          string            `json:"name"`
	Headers       map[string]string `json:"headers,omitempty"`
	Cookie        string            `json:"cookie,omitempty"`
	Notes         string            `json:"notes,omitempty"`
	Username      string            `json:"username,omitempty"`
	Password      string            `json:"password,omitempty"`
	LoginURL      string            `json:"loginUrl,omitempty"`
	LoginMethod   string            `json:"loginMethod,omitempty"`
	UsernameField string            `json:"usernameField,omitempty"`
	PasswordField string            `json:"passwordField,omitempty"`
	TokenField    string            `json:"tokenField,omitempty"`
}

func (s *Server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	creds, err := s.store.ListCredentials(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, creds)
}

func (s *Server) handleAddCredential(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("id")
	if _, err := s.store.GetCase(caseID); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	var req addCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("name is required"))
		return
	}
	req.LoginURL = strings.TrimSpace(req.LoginURL)
	if req.LoginURL != "" {
		parsed, err := url.ParseRequestURI(req.LoginURL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			writeError(w, http.StatusBadRequest, fmt.Errorf("login URL must be an absolute http(s) URL"))
			return
		}
		if req.Username == "" || req.Password == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("username and password are required when a login URL is set"))
			return
		}
	}

	cred := store.Credential{
		ID:            newID(),
		CaseID:        caseID,
		Name:          req.Name,
		Headers:       req.Headers,
		Cookie:        req.Cookie,
		Notes:         req.Notes,
		Username:      req.Username,
		Password:      req.Password,
		LoginURL:      req.LoginURL,
		LoginMethod:   req.LoginMethod,
		UsernameField: req.UsernameField,
		PasswordField: req.PasswordField,
		TokenField:    req.TokenField,
	}
	if err := s.store.SaveCredential(cred); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	saved, err := s.store.GetCredential(cred.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, saved)
}

func (s *Server) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// Looked up first so a missing credential is a 404 rather than a silent 204.
	if _, err := s.store.GetCredential(id); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.store.DeleteCredential(id); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// credentialSessionTimeout bounds the one login request a "create session"
// click issues -- generous like the Tester's own timeout, since this is a
// single explicit, operator-initiated request rather than one of hundreds
// run automatically.
const credentialSessionTimeout = 20 * time.Second

// credentialSessionBodyLimit caps how much of the login response body is
// read when looking for a bearer token, so a huge response can't blow up
// server memory over what's only ever a small JSON login payload.
const credentialSessionBodyLimit = 2 << 20 // 2 MiB

// handleCreateCredentialSession performs the login a "test credential" (see
// the credentials table's schema comment) describes -- POSTing (or
// whatever LoginMethod says) a JSON {usernameField: ..., passwordField:
// ...} body to LoginURL -- and writes whatever session it gets back
// (Set-Cookie and/or a TokenField extracted from the JSON response) into
// the credential's Headers/Cookie. Every scanner that already applies this
// credential by ID via mergedCredentialHeaders picks up the refreshed
// session with no change of its own.
func (s *Server) handleCreateCredentialSession(w http.ResponseWriter, r *http.Request) {
	cred, err := s.store.GetCredential(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	loginURL := strings.TrimSpace(cred.LoginURL)
	if loginURL == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("credential %q has no login URL configured", cred.Name))
		return
	}
	parsed, err := url.ParseRequestURI(loginURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		writeError(w, http.StatusBadRequest, fmt.Errorf("login URL must be an absolute http(s) URL"))
		return
	}

	method := strings.ToUpper(strings.TrimSpace(cred.LoginMethod))
	if method == "" {
		method = http.MethodPost
	}
	usernameField := cred.UsernameField
	if usernameField == "" {
		usernameField = "username"
	}
	passwordField := cred.PasswordField
	if passwordField == "" {
		passwordField = "password"
	}
	loginBody, err := json.Marshal(map[string]string{usernameField: cred.Username, passwordField: cred.Password})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), credentialSessionTimeout)
	defer cancel()
	loginReq, err := http.NewRequestWithContext(ctx, method, loginURL, bytes.NewReader(loginBody))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	loginReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout:   credentialSessionTimeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // deliberate: authorized testing against lab/CTF/self-signed targets
		// Not following redirects so a Set-Cookie on the login response
		// itself (the common 302-after-login flow) lands on resp directly
		// instead of being discarded partway through a redirect chain --
		// same posture as the tester package.
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(loginReq)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Errorf("login request failed: %w", err))
		return
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, credentialSessionBodyLimit))

	var cookieParts []string
	// Join every cookie the login response set into one "name=value; ..."
	// Cookie header, the same shape mergedCredentialHeaders expects.
	for _, c := range resp.Cookies() {
		cookieParts = append(cookieParts, c.Name+"="+c.Value)
	}
	cookie := strings.Join(cookieParts, "; ")

	headers := map[string]string{}
	// Start from whatever headers were already saved on this credential so
	// a manually-added header (e.g. a custom API key) survives a session
	// refresh instead of being wiped by it.
	for k, v := range cred.Headers {
		headers[k] = v
	}
	if cred.TokenField != "" {
		var decoded map[string]any
		if json.Unmarshal(bodyBytes, &decoded) == nil {
			if token := lookupJSONField(decoded, cred.TokenField); token != "" {
				headers["Authorization"] = "Bearer " + token
			}
		}
	}

	if cookie == "" && headers["Authorization"] == "" {
		writeError(w, http.StatusBadGateway, fmt.Errorf("login returned HTTP %d with no session cookie or token", resp.StatusCode))
		return
	}

	if err := s.store.UpdateCredentialSession(cred.ID, headers, cookie); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	saved, err := s.store.GetCredential(cred.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

// lookupJSONField walks a dot-separated path ("data.token") through a
// decoded JSON object and returns the string found there, or "" if any
// segment along the path is missing or isn't itself an object/string.
func lookupJSONField(data map[string]any, path string) string {
	var cur any = data
	// Descend one path segment at a time ("data" then "token" for
	// "data.token"), bailing out as soon as a segment isn't an object.
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = m[part]
	}
	str, _ := cur.(string)
	return str
}

// mergedCredentialHeaders returns a new headers map combining cred's saved
// headers (and its Cookie, folded in as a "Cookie" header) with existing --
// existing's values always win, so an explicit per-request header/cookie
// the caller typed overrides the vault rather than being silently replaced
// by it. existing may be nil.
func mergedCredentialHeaders(cred store.Credential, existing map[string]string) map[string]string {
	merged := map[string]string{}
	for k, v := range cred.Headers {
		merged[k] = v
	}
	if cred.Cookie != "" {
		merged["Cookie"] = cred.Cookie
	}
	for k, v := range existing {
		merged[k] = v
	}
	return merged
}
