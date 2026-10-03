package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/collaborator"
)

// Settings keys collaboratorConfig is persisted under -- same
// store.GetSetting/SetSetting mechanism as the DNSDumpster/NVD/HIBP API
// keys in settings.go, just three plain (non-secret) strings instead of one.
const (
	settingCollabDomain   = "collaborator_domain"
	settingCollabAnswerIP = "collaborator_answer_ip"
	settingCollabDNSAddr  = "collaborator_dns_addr"
)

// collabCallbackBodyLimit caps how much of an inbound callback's body this
// listener reads and stores -- it only needs enough to show the operator
// *that* (and roughly *what*) called back, not a faithful full-body capture.
const collabCallbackBodyLimit = 8 << 10 // 8 KiB

// collabHeaderAllowlist is which inbound headers get recorded on an HTTP
// interaction -- a blind callback from an attacker-controlled internal
// service is exactly the kind of thing that might carry a cloud metadata
// token, an internal auth header, or other secret in its own request to
// prove where it came from; this listener has no reason to store that
// alongside its own UI, so only headers useful for identifying the caller
// itself are kept.
var collabHeaderAllowlist = []string{"User-Agent", "Content-Type", "Content-Length", "Accept", "X-Forwarded-For"}

type collaboratorConfig struct {
	Domain   string `json:"domain"`
	AnswerIP string `json:"answerIp"`
	DNSAddr  string `json:"dnsAddr"`
}

func (s *Server) loadCollaboratorConfig() collaboratorConfig {
	var cfg collaboratorConfig
	cfg.Domain, _, _ = s.store.GetSetting(settingCollabDomain)
	cfg.AnswerIP, _, _ = s.store.GetSetting(settingCollabAnswerIP)
	cfg.DNSAddr, _, _ = s.store.GetSetting(settingCollabDNSAddr)
	return cfg
}

// startCollabDNSLocked (re)starts the DNS half of the collaborator listener
// from cfg, stopping whatever instance was previously running first --
// called both at startup (from NewServer, once the config was already
// persisted in an earlier run) and whenever the operator saves a new config.
// Left stopped (nil err, no listener running) when Domain or AnswerIP is
// blank, or DNSAddr defaults to ":53" -- binding a privileged port commonly
// fails without elevated privileges, which is reported back to the caller
// rather than silently swallowed, since without it blind/DNS-only OOB
// detection just won't see anything.
func (s *Server) startCollabDNSLocked(cfg collaboratorConfig) error {
	if s.collabDNSStop != nil {
		s.collabDNSStop()
		s.collabDNSStop = nil
	}
	if cfg.Domain == "" || cfg.AnswerIP == "" {
		return nil
	}
	addr := cfg.DNSAddr
	if addr == "" {
		addr = ":53"
	}
	stop, err := s.collab.StartDNS(addr, cfg.Domain, cfg.AnswerIP)
	if err != nil {
		return err
	}
	s.collabDNSStop = stop
	return nil
}

// handleGetCollaboratorConfig returns the collaborator listener's current
// domain/answer-IP/DNS-bind-address configuration, plus whether its DNS
// listener is actually running right now (binding it can fail, most often
// over an unprivileged port -- the UI needs to be able to tell "saved" from
// "actually listening" apart).
func (s *Server) handleGetCollaboratorConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.loadCollaboratorConfig()
	s.collabMu.Lock()
	dnsActive := s.collabDNSStop != nil
	s.collabMu.Unlock()
	writeJSON(w, http.StatusOK, struct {
		collaboratorConfig
		DNSActive bool `json:"dnsActive"`
	}{cfg, dnsActive})
}

// handleSetCollaboratorConfig persists cfg and (re)starts the DNS listener
// to match -- see startCollabDNSLocked. A bind failure is reported as a 502
// rather than 400/500: the request body itself was fine, it's the listener
// (an external resource -- a port this process may not have the privilege
// to bind) that couldn't come up; the config is still saved either way so
// the operator doesn't have to retype it after fixing the underlying issue
// (e.g. an authbind/setcap grant, or picking an unprivileged port).
func (s *Server) handleSetCollaboratorConfig(w http.ResponseWriter, r *http.Request) {
	var cfg collaboratorConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	cfg.Domain = strings.TrimSpace(cfg.Domain)
	cfg.AnswerIP = strings.TrimSpace(cfg.AnswerIP)
	cfg.DNSAddr = strings.TrimSpace(cfg.DNSAddr)

	if err := s.store.SetSetting(settingCollabDomain, cfg.Domain); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.store.SetSetting(settingCollabAnswerIP, cfg.AnswerIP); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.store.SetSetting(settingCollabDNSAddr, cfg.DNSAddr); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	s.collabMu.Lock()
	dnsErr := s.startCollabDNSLocked(cfg)
	dnsActive := s.collabDNSStop != nil
	s.collabMu.Unlock()

	resp := struct {
		collaboratorConfig
		DNSActive bool   `json:"dnsActive"`
		DNSError  string `json:"dnsError,omitempty"`
	}{cfg, dnsActive, ""}
	if dnsErr != nil {
		resp.DNSError = dnsErr.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

// collabNewTokenResponse is one freshly minted token plus every way of
// reaching it that's currently usable -- httpCallback always works (it's
// just this same server's own address), dnsHostname/dnsAvailable reflect
// whether a domain has actually been configured for the DNS side yet (see
// handleSetCollaboratorConfig).
type collabNewTokenResponse struct {
	Token        string `json:"token"`
	HTTPCallback string `json:"httpCallback"`
	DNSHostname  string `json:"dnsHostname,omitempty"`
	DNSAvailable bool   `json:"dnsAvailable"`
}

// handleCollaboratorNew mints a fresh OOB token and returns every callback
// address a payload could be pointed at -- an SSRF/XXE/blind-injection
// module elsewhere in Aperture calls this once per test, embeds the
// returned address in its payload, then polls handleCollaboratorPoll for
// whether it fired. Also registers it as an active Session (see
// collaborator.Registry.RegisterSession) so it immediately shows up in
// every scanner's Callback picker, not just this response.
func (s *Server) handleCollaboratorNew(w http.ResponseWriter, r *http.Request) {
	token := s.collab.NewToken()
	cfg := s.loadCollaboratorConfig()

	resp := collabNewTokenResponse{
		Token: token,
		// r.Host is this request's own view of where Aperture is reachable
		// -- correct whether that's a bare IP:port during local testing or a
		// real hostname once deployed behind one, without needing its own
		// separate "public address" setting.
		HTTPCallback: fmt.Sprintf("%s://%s/collab/%s", schemeOf(r), r.Host, token),
	}
	if cfg.Domain != "" {
		resp.DNSHostname = token + "." + cfg.Domain
		resp.DNSAvailable = true
	}

	s.collab.RegisterSession(collaborator.Session{
		Token:        token,
		Provider:     "aperture",
		Label:        "Aperture " + token[:6],
		HTTPCallback: resp.HTTPCallback,
		DNSHostname:  resp.DNSHostname,
		CreatedAt:    time.Now(),
	})

	writeJSON(w, http.StatusOK, resp)
}

func schemeOf(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// handleCollaboratorPoll returns every interaction recorded so far for
// ?token= -- called repeatedly (short-polled) by whichever module/UI is
// waiting on a blind callback, since there's no way to push "it just fired"
// to the caller the way a WebSocket-backed scan streams progress.
// handleListActiveCallbackServers returns every currently-registered Session
// (see collaborator.Registry.ListSessions), newest first -- what populates a
// scanner's Callback picker dropdown.
func (s *Server) handleListActiveCallbackServers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.collab.ListSessions())
}

// handleRemoveActiveCallbackServer drops ?token= from the active-Session
// list (the Collaborator tab's "Stop" button) -- it only stops the token
// from being offered as pickable going forward, it doesn't retire the token
// itself or discard anything already recorded against it (see
// collaborator.Registry.RemoveSession).
func (s *Server) handleRemoveActiveCallbackServer(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("token is required"))
		return
	}
	s.collab.RemoveSession(token)
	writeJSON(w, http.StatusOK, struct{}{})
}

func (s *Server) handleCollaboratorPoll(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("token is required"))
		return
	}
	writeJSON(w, http.StatusOK, s.collab.Poll(token))
}

// handleCollaboratorCallback is the actual OOB listener's HTTP half --
// mounted at /collab/{token}/... without requireAuth, deliberately: it has
// to accept a request from whatever third-party server an operator's target
// was made to call out to, which was never given (and has no way to
// present) an Aperture session cookie. Every method is accepted and every
// request is recorded. The first path segment after the token is treated as
// a caller-chosen Identifier rather than part of the recorded Path (see
// collaborator.Interaction.Identifier) -- it's what lets one shared token
// disambiguate which of many concurrent tests actually caused a given hit.
// Replies with whatever collaborator.Registry.Staged has for the remaining
// path (see handleCollaboratorCallback's own doc on Stage/Staged -- used by
// a jku/x5u-style check that needs the target to fetch and parse a document
// this process controls), or a bare 200 otherwise: there's no "right"
// response to send back for an ordinary hit (the caller is presumed to be an
// unwitting victim server, not a client this system is otherwise talking
// to), and a plain 200 is the least likely to itself break whatever code
// path triggered the callback.
func (s *Server) handleCollaboratorCallback(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")

	headers := map[string]string{}
	for _, name := range collabHeaderAllowlist {
		if v := r.Header.Get(name); v != "" {
			headers[name] = v
		}
	}

	body, _ := io.ReadAll(io.LimitReader(r.Body, collabCallbackBodyLimit))

	identifier, path := splitIdentifier(r.PathValue("path"))

	s.collab.Record(token, collaborator.Interaction{
		ID:         newID(),
		Protocol:   "http",
		Timestamp:  time.Now(),
		RemoteAddr: r.RemoteAddr,
		Method:     r.Method,
		Path:       path,
		Query:      r.URL.RawQuery,
		Headers:    headers,
		Body:       string(body),
		Identifier: identifier,
	})

	log.Printf("collaborator: %s hit by %s %s from %s", token, r.Method, r.URL.Path, r.RemoteAddr)

	if contentType, staged, ok := s.collab.Staged(token, strings.TrimPrefix(path, "/")); ok {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(staged)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// splitIdentifier splits a "/collab/{token}/..." route's remaining path
// (rawPath, without its leading "/") into its leading identifier segment and
// whatever's left (always "/"-prefixed, defaulting to "/"). rawPath=="" (a
// bare "/collab/{token}" hit, e.g. a manual payload with no sub-test to
// distinguish) returns identifier="", path="/".
func splitIdentifier(rawPath string) (identifier, path string) {
	if rawPath == "" {
		return "", "/"
	}
	if i := strings.IndexByte(rawPath, '/'); i >= 0 {
		return rawPath[:i], rawPath[i:]
	}
	return rawPath, "/"
}

// handleWebhookSiteNew mints a fresh webhook.site token -- the alternative
// callback provider alongside Aperture's own listener above, for an operator
// who'd rather have a ready-made link (and webhook.site's own hosted view of
// it) than configure a domain/answer-IP here. See
// collaborator.NewWebhookSiteToken. Requires this server's own host to reach
// the internet; a 502 (not 400/500) reflects that the failure is webhook.site
// itself being unreachable or erroring, not anything wrong with the request.
// Also registers it as an active Session (see handleCollaboratorNew) --
// webhook.site itself has no notion of Aperture's Session list, so this is
// the only place that metadata is ever recorded.
func (s *Server) handleWebhookSiteNew(w http.ResponseWriter, r *http.Request) {
	token, err := collaborator.NewWebhookSiteToken(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}

	s.collab.RegisterSession(collaborator.Session{
		Token:        token.UUID,
		Provider:     "webhooksite",
		Label:        "webhook.site " + token.UUID[:8],
		HTTPCallback: token.URL,
		ViewURL:      token.ViewURL,
		CreatedAt:    time.Now(),
	})

	writeJSON(w, http.StatusOK, token)
}

// handleWebhookSitePoll proxies webhook.site's own "list requests for this
// token" call for ?uuid= -- proxied through this server rather than called
// directly from the browser because webhook.site's API doesn't send
// Access-Control-Allow-Origin, so a cross-origin fetch from the UI would
// just be blocked by CORS. See collaborator.PollWebhookSite.
func (s *Server) handleWebhookSitePoll(w http.ResponseWriter, r *http.Request) {
	uuid := r.URL.Query().Get("uuid")
	if uuid == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("uuid is required"))
		return
	}
	interactions, err := collaborator.PollWebhookSite(r.Context(), uuid)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, interactions)
}
