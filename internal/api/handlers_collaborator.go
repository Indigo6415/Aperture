package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/collaborator"
)

// Settings keys collaboratorConfig is persisted under -- same
// store.GetSetting/SetSetting mechanism as the DNSDumpster/NVD/HIBP API
// keys in settings.go, just three plain (non-secret) strings instead of one.
const (
	settingCollabDomain       = "collaborator_domain"
	settingCollabAnswerIP     = "collaborator_answer_ip"
	settingCollabDNSAddr      = "collaborator_dns_addr"
	settingCollabCallbackBase = "collaborator_callback_base"
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
	Domain       string `json:"domain"`
	AnswerIP     string `json:"answerIp"`
	DNSAddr      string `json:"dnsAddr"`
	CallbackBase string `json:"callbackBase"`
}

func (s *Server) loadCollaboratorConfig() collaboratorConfig {
	var cfg collaboratorConfig
	cfg.Domain, _, _ = s.store.GetSetting(settingCollabDomain)
	cfg.AnswerIP, _, _ = s.store.GetSetting(settingCollabAnswerIP)
	cfg.DNSAddr, _, _ = s.store.GetSetting(settingCollabDNSAddr)
	cfg.CallbackBase, _, _ = s.store.GetSetting(settingCollabCallbackBase)
	return cfg
}

// collabCallbackBase returns the base URL (scheme://host[:port], no trailing
// slash) that outbound payloads should call back to. An operator-configured
// callbackBase wins, since it's the only address a target on another network
// can actually reach (a LAN IP or public IP:port behind a port-forward). With
// none set, it uses the detected LAN IP and the callback listener's port (see
// SetCollabListenAddr), since callbacks aren't served on the UI port. If no
// LAN IP can be detected, it uses the UI request's host with the callback port.
// If the callback port is unknown, it falls back to the request's own host:port.
func (s *Server) collabCallbackBase(r *http.Request) string {
	if base := s.loadCollaboratorConfig().CallbackBase; base != "" {
		return strings.TrimRight(base, "/")
	}
	port := portOf(s.collabListenAddr)
	if port == "" {
		return fmt.Sprintf("%s://%s", schemeOf(r), r.Host)
	}
	host := ""
	if lan, err := collaborator.LocalIPv4(); err == nil {
		host = lan
	} else if h, _, err := net.SplitHostPort(r.Host); err == nil {
		host = h
	} else {
		host = r.Host
	}
	return fmt.Sprintf("%s://%s", schemeOf(r), net.JoinHostPort(host, port))
}

// collabAddressesResponse lists the callback addresses Aperture can detect
// automatically, so the operator can pick one instead of typing it.
type collabAddressesResponse struct {
	LocalIP     string `json:"localIp"`
	LocalBase   string `json:"localBase"`
	PublicIP    string `json:"publicIp"`
	PublicBase  string `json:"publicBase"`
	CollabPort  string `json:"collabPort"`
	PublicError string `json:"publicError,omitempty"`
}

// handleCollaboratorAddresses detects this host's LAN IP (from its network
// interfaces) and public IP (from an external lookup service, cached), and
// returns ready-to-use callback base URLs for each. A failed public lookup is
// reported in publicError rather than as an HTTP error, since the LAN address
// is still useful on its own.
func (s *Server) handleCollaboratorAddresses(w http.ResponseWriter, r *http.Request) {
	port := portOf(s.collabListenAddr)
	resp := collabAddressesResponse{CollabPort: port}

	if lan, err := collaborator.LocalIPv4(); err == nil {
		resp.LocalIP = lan
		resp.LocalBase = fmt.Sprintf("%s://%s", schemeOf(r), net.JoinHostPort(lan, port))
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	if pub, err := collaborator.PublicIPv4(ctx); err == nil {
		resp.PublicIP = pub
		resp.PublicBase = fmt.Sprintf("%s://%s", schemeOf(r), net.JoinHostPort(pub, port))
	} else {
		resp.PublicError = err.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

// portOf returns the port part of a host:port listen address, or "" if it
// can't be parsed.
func portOf(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return port
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
	cfg.CallbackBase = strings.TrimRight(strings.TrimSpace(cfg.CallbackBase), "/")

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
	if err := s.store.SetSetting(settingCollabCallbackBase, cfg.CallbackBase); err != nil {
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
	Token        string             `json:"token"`
	HTTPCallback string             `json:"httpCallback"`
	Links        collaborator.Links `json:"links"`
	DNSHostname  string             `json:"dnsHostname,omitempty"`
	DNSAvailable bool               `json:"dnsAvailable"`
}

// collabLinksFor builds the callback URL for token on each network path:
// localhost (the listener is on 0.0.0.0, so 127.0.0.1 reaches it), the detected
// LAN IP, and the detected public IP. Paths that can't be detected are left
// empty. The public lookup is bounded by a short timeout so minting a token
// never waits long on an external service.
func (s *Server) collabLinksFor(ctx context.Context, token string) collaborator.Links {
	port := portOf(s.collabListenAddr)
	if port == "" {
		return collaborator.Links{}
	}
	// Build http://<host>:<port>/collab/<token>, and the https:// form too when TLS is on.
	url := func(scheme, host string) string {
		return fmt.Sprintf("%s://%s/collab/%s", scheme, net.JoinHostPort(host, port), token)
	}
	tlsOn := s.collabTLSEnabled()
	links := collaborator.Links{Localhost: url("http", "127.0.0.1")}
	if tlsOn {
		links.LocalhostTLS = url("https", "127.0.0.1")
	}
	if lan, err := collaborator.LocalIPv4(); err == nil {
		links.Private = url("http", lan)
		if tlsOn {
			links.PrivateTLS = url("https", lan)
		}
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if pub, err := collaborator.PublicIPv4(lookupCtx); err == nil {
		links.Public = url("http", pub)
		if tlsOn {
			links.PublicTLS = url("https", pub)
		}
	}
	return links
}

// CallbackTLSEnabled reports whether the callback listener should accept TLS.
// Passed to collaborator.Serve so the HTTPS side can be toggled at runtime.
func (s *Server) CallbackTLSEnabled() bool { return s.collabTLSEnabled() }

// CallbackTLSConfig returns the TLS config for the callback listener. It reads
// the stored certificate per handshake, so regenerating it takes effect at once.
func (s *Server) CallbackTLSConfig() *tls.Config {
	return &tls.Config{GetCertificate: s.collabGetCertificate}
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

	links := s.collabLinksFor(r.Context(), token)
	resp := collabNewTokenResponse{
		Token:        token,
		HTTPCallback: s.collabCallbackBase(r) + "/collab/" + token,
		Links:        links,
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
		Links:        links,
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

	// A staged document for this path wins, so checks that need the target to
	// fetch a specific file (jku/x5u) still get it.
	if contentType, staged, ok := s.collab.Staged(token, strings.TrimPrefix(path, "/")); ok {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(staged)
		return
	}
	// Every other hit gets the same fixed greeting, as plain text.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, collabGreeting)
}

// collabGreeting is the fixed body returned for a plain callback hit.
const collabGreeting = "HELL YEA BABY!\nHELL YEA BABY!\nHELL YEA BABY!\n"

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
