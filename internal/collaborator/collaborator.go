// Package collaborator is Aperture's own out-of-band interaction listener --
// the same role Burp Suite's Collaborator (or interact.sh) plays: hand out a
// unique, unguessable token, point a blind payload (an SSRF target, an XXE
// external entity, a stored-XSS callback, ...) at it, and later poll whether
// anything actually reached that token over HTTP or DNS. That's the only
// reliable signal for a vulnerability class whose effect is otherwise
// invisible in the response the attacker's own request gets back.
//
// It runs in-process as part of Aperture's own server: the HTTP side reuses
// the server's existing listener (see internal/api/handlers_collaborator.go,
// which mounts Registry.Record behind an unauthenticated catch-all route --
// it has to be reachable by whatever third-party server the operator's
// target calls out to, which never has an Aperture session), and the DNS
// side is a small UDP server started separately (see StartDNS) once the
// operator points a real domain's NS records at wherever Aperture is
// reachable from the internet. Neither piece needs that domain configured to
// compile or run -- until it is, the HTTP listener still works for any SSRF/
// callback payload that can reach Aperture's own host:port directly, and
// polling just never finds a DNS-only interaction.
//
// Every token and its interactions live only in memory (see Registry) --
// same posture as a real Collaborator server's event history: ephemeral,
// scoped to this process's uptime, gone on restart. That's fine for its one
// job (catch a callback during a single scan/session), and avoids storing
// what amounts to a log of exactly which external hosts an operator's
// targets were made to contact.
package collaborator

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"sync"
	"time"
)

// maxTrackedTokens bounds how many distinct tokens Registry holds
// interactions for at once -- protects against unbounded memory growth from
// background internet noise (random bots probing the DNS listener) piling up
// entries for tokens nobody ever asked for.
const maxTrackedTokens = 5000

// maxInteractionsPerToken bounds one token's own interaction history --
// oldest is dropped once a single (mis)configured payload floods callbacks,
// same posture as pwreset's rate-limit burst being bounded rather than
// unbounded.
const maxInteractionsPerToken = 500

// maxStagedResponseBody bounds a single staged response (see Stage) -- a
// JWKS document or an X.509 cert chain is at most a couple KB, so this is
// generous headroom without letting a caller park something unbounded in
// memory per token.
const maxStagedResponseBody = 32 << 10 // 32 KiB

// tokenTTL is how long a token and its interactions are kept before being
// pruned -- long enough to outlast any single scan run, short enough that a
// long-lived Aperture process doesn't accumulate tokens forever.
const tokenTTL = 24 * time.Hour

// Interaction is one inbound callback recorded against a token, over either
// protocol Registry listens on.
type Interaction struct {
	ID         string    `json:"id"`
	Protocol   string    `json:"protocol"` // "http" | "dns"
	Timestamp  time.Time `json:"timestamp"`
	RemoteAddr string    `json:"remoteAddr"`

	// HTTP-only fields.
	Method  string            `json:"method,omitempty"`
	Path    string            `json:"path,omitempty"`
	Query   string            `json:"query,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`

	// DNS-only fields.
	QueryName string `json:"queryName,omitempty"`
	QueryType string `json:"queryType,omitempty"`

	// Identifier is the caller-chosen label that precedes the token itself
	// in whatever address was hit -- e.g. "ssrf-webhook_url" in
	// ".../collab/<token>/ssrf-webhook_url/" or
	// "ssrf-webhook_url.<token>.collab.example.com". Lets one shared,
	// long-lived token be reused across many concurrent tests (across one
	// scanner or several) while each hit still says which specific test
	// caused it. Empty for a bare "/collab/<token>" hit, e.g. a manual
	// payload pasted from the Collaborator tab with no sub-test to
	// distinguish.
	Identifier string `json:"identifier,omitempty"`
}

// stagedResponse is a fixed body a caller has asked the HTTP listener to
// serve back (instead of today's bare 200) the next time a specific path
// under a token is hit -- see Stage. Needed for a JWKS/x5u-style check: the
// vulnerability is only confirmed if the target actually *fetches and uses*
// a document this process controls, not just reaches it.
type stagedResponse struct {
	contentType string
	body        []byte
}

// Session is the metadata behind one deliberately-minted, user-facing
// callback address -- what the Collaborator tab's "New token" mints and
// every scanner's Callback picker lists and selects from. Distinct from the
// interaction/createdAt bookkeeping above: a Session can outlive every
// interaction it's ever recorded (most of the time it has none yet), and
// exists purely so other parts of the UI can discover "which servers are
// currently being watched" without re-minting one of their own.
type Session struct {
	Token        string    `json:"token"`
	Provider     string    `json:"provider"` // "aperture" | "webhooksite"
	Label        string    `json:"label"`
	HTTPCallback string    `json:"httpCallback"`
	DNSHostname  string    `json:"dnsHostname,omitempty"`
	ViewURL      string    `json:"viewUrl,omitempty"`
	CreatedAt    time.Time `json:"createdAt"`
}

// Ref is which callback server a scan request opted into -- decoded
// straight from a scanner's request body (see handlers_ssrf.go,
// handlers_openredirect.go, handlers_jwt.go) and passed down into that
// package's own OOB module. Provider/Token mirror Session's own fields;
// kept as a separate, minimal type since a scan request only ever needs to
// *reference* a session, never describe one.
type Ref struct {
	Provider string `json:"provider"`
	Token    string `json:"token"`
}

// Registry is the shared, in-memory interaction log every token's
// HTTP/DNS hits are recorded into and later polled back out of, plus the
// user-facing Session list and any staged per-path responses. The zero
// value is not usable -- construct with NewRegistry.
type Registry struct {
	mu           sync.Mutex
	interactions map[string][]Interaction
	createdAt    map[string]time.Time
	sessions     map[string]Session
	staged       map[string]map[string]stagedResponse
}

// NewRegistry returns an empty, ready-to-use Registry.
func NewRegistry() *Registry {
	return &Registry{
		interactions: map[string][]Interaction{},
		createdAt:    map[string]time.Time{},
		sessions:     map[string]Session{},
		staged:       map[string]map[string]stagedResponse{},
	}
}

// randomHex returns n random bytes hex-encoded -- crypto/rand.Read only
// errors on a broken system entropy source, which would already be fatal
// well before this ever ran, so a panic here (rather than a fallback, unlike
// pwreset.unknownIdentifier's lower-stakes case) is the honest response.
func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic("collaborator: system entropy source failed: " + err.Error())
	}
	return hex.EncodeToString(buf)
}

// NewToken mints a fresh, unguessable token and registers it (with an empty
// interaction list) so it's immediately pollable even before anything has
// reached it. 10 random bytes (20 hex chars) is short enough to fit
// comfortably under DNS's 63-byte label limit alongside whatever subdomain
// labels a payload prepends (e.g. "aws-metadata.<token>.collab.example.com"),
// long enough that a third party can't feasibly guess or brute-force it.
func (r *Registry) NewToken() string {
	token := randomHex(10)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked()
	r.interactions[token] = []Interaction{}
	r.createdAt[token] = time.Now()
	return token
}

// pruneLocked drops every token (and its interactions, session metadata, and
// any staged response) older than tokenTTL. Called with mu already held, on
// every NewToken/Record so the registry self-cleans without needing a
// background goroutine.
func (r *Registry) pruneLocked() {
	cutoff := time.Now().Add(-tokenTTL)
	for token, created := range r.createdAt {
		if created.Before(cutoff) {
			delete(r.createdAt, token)
			delete(r.interactions, token)
			delete(r.sessions, token)
			delete(r.staged, token)
		}
	}
}

// Record appends in to token's interaction history, auto-registering an
// unrecognized token the first time it's hit -- both the HTTP catch-all and
// the DNS listener may see a token before (or without) it ever having been
// separately minted via NewToken, e.g. a payload copied from a previous scan
// still landing after this process restarted. A token is only refused when
// maxTrackedTokens is already full and it's not one already being tracked --
// existing tokens' own bursts are still bounded by maxInteractionsPerToken
// below, not dropped outright.
func (r *Registry) Record(token string, in Interaction) {
	if token == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked()

	if _, exists := r.interactions[token]; !exists {
		if len(r.interactions) >= maxTrackedTokens {
			return
		}
		r.createdAt[token] = time.Now()
	}

	list := r.interactions[token]
	if len(list) >= maxInteractionsPerToken {
		// Drop the oldest to make room -- a flood from a misconfigured
		// payload shouldn't crowd out whatever comes next.
		list = list[1:]
	}
	r.interactions[token] = append(list, in)
}

// Poll returns a copy of every interaction recorded for token so far (empty,
// never nil, for a token that's registered but hasn't been hit yet, or one
// that was never registered at all -- callers can't distinguish "not hit
// yet" from "doesn't exist" through this call alone, which is fine: polling
// an expired/mistyped token should just look like silence, not an error).
func (r *Registry) Poll(token string) []Interaction {
	r.mu.Lock()
	defer r.mu.Unlock()
	list := r.interactions[token]
	out := make([]Interaction, len(list))
	copy(out, list)
	return out
}

// RegisterSession records s as a user-facing active callback server --
// called once, right after a token is minted (see handleCollaboratorNew/
// handleWebhookSiteNew), so it immediately shows up in every scanner's
// Callback picker without that scanner needing to mint one of its own.
func (r *Registry) RegisterSession(s Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked()
	r.sessions[s.Token] = s
}

// ListSessions returns every still-tracked Session, newest first -- what
// a scanner's Callback picker renders as its dropdown.
func (r *Registry) ListSessions() []Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked()
	out := make([]Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		out = append(out, s)
	}
	// Newest first -- the server someone just minted is almost always the
	// one they want to pick next, so it should be at the top of the list
	// rather than wherever Go's unordered map range happened to leave it.
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// RemoveSession drops token's Session entry (e.g. the Collaborator tab's
// "Stop" button) -- the token itself, and anything already recorded against
// it, is untouched: this only controls whether it still shows up as pickable
// in a Callback dropdown, not whether old interactions remain pollable.
func (r *Registry) RemoveSession(token string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, token)
}

// Stage records body (capped at maxStagedResponseBody) as what the HTTP
// listener should serve back, with contentType, the next time path is hit
// under token -- instead of today's bare 200. Used by a check that needs
// the target to actually *fetch and parse* a document this process
// controls (a JWKS doc for a jku-header test, an X.509 cert chain for x5u),
// where the real confirmation is that fetch happening at all, not just an
// inbound hit being logged.
func (r *Registry) Stage(token, path, contentType string, body []byte) {
	if len(body) > maxStagedResponseBody {
		body = body[:maxStagedResponseBody]
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.staged[token] == nil {
		r.staged[token] = map[string]stagedResponse{}
	}
	r.staged[token][path] = stagedResponse{contentType: contentType, body: body}
}

// Staged returns whatever was last staged for token+path (see Stage), or
// ok=false if nothing was.
func (r *Registry) Staged(token, path string) (contentType string, body []byte, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	resp, exists := r.staged[token][path]
	if !exists {
		return "", nil, false
	}
	return resp.contentType, resp.body, true
}
