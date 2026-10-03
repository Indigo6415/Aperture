package openredirect

import (
	"context"
	"fmt"
	"hash/fnv"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Indigo6415/Aperture/internal/collaborator"
)

// commonRedirectParams covers the parameter-naming conventions seen across
// login flows, SSO callbacks, and generic "go back to where you were"
// links -- OWASP's and PortSwigger's own open-redirect testing checklists
// both converge on roughly this set.
var commonRedirectParams = []string{
	"redirect", "redirect_uri", "redirect_url", "redirecturl", "url", "next", "return", "returnto", "return_to",
	"returnurl", "return_url", "continue", "redir", "dest", "destination", "target", "rurl", "forward", "out",
	"view", "path", "r", "u", "link", "goto", "checkout_url", "image_url", "callback", "success_url", "failure_url",
}

// pathRedirectSegments are route names that take the destination as the
// next path segment instead of a query parameter (e.g. "/redirect/https://
// evil.example/" or "/go/https://evil.example/"). Tested at the target's
// origin root, since that's where these routes are almost always mounted.
var pathRedirectSegments = []string{
	"redirect", "redir", "redirect_to", "redirectto", "out", "go", "goto", "link", "exit",
	"away", "jump", "leave", "continue", "next", "return", "url", "r", "to", "visit",
}

// forwardedHostHeaders are the non-standard headers reverse proxies and
// frameworks use to tell the app which host the client "really" asked for.
// An app that builds its own absolute URLs (a redirect back to the site, a
// canonical link) from one of these instead of the validated Host header
// bounces the visitor to whatever value the attacker put there.
var forwardedHostHeaders = []string{
	"X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "X-HTTP-Host-Override", "X-Original-Host", "Forwarded-Host",
}

// maxRedirectHops bounds how far the confirmation walk follows a Location
// chain when Request.FollowRedirects is on. Enough for the common shapes
// (an http->https upgrade, then a "return to" bounce, then the redirect)
// without letting a redirect loop run the scan out of budget.
const maxRedirectHops = 5

// metaRefreshRe/jsRedirectRe flag a *client-side* redirect in a response
// body -- an endpoint that renders "You are being redirected to <url>…"
// rather than sending a 3xx. Matched independently of where the callback
// host turns up in the body; detect() only treats a callback-host hit as a
// redirect when one of these also matches, so a page that merely echoes the
// raw parameter back (e.g. in a "did you mean" or error message) isn't
// mistaken for an actual redirect. Even so, nothing here produces a Finding
// on its own -- it only decides what's worth confirming against the live
// callback server.
var (
	metaRefreshRe = regexp.MustCompile(`(?i)<meta[^>]+http-equiv=["']?refresh["']?[^>]*content=["'][^"']*url=`)
	jsRedirectRe  = regexp.MustCompile(`(?i)(location\.href|location\.replace\s*\(|window\.location(\.href)?)\s*=`)
)

// moduleDef is one vector family -- expand turns it into the concrete
// requests to send for this particular run (one per candidate parameter,
// per path segment, per header, ...). Every probe a module expands to is
// attributed individually via its own identifier.
type moduleDef struct {
	id, name, severity string
	expand             func(d runDeps) []probeSpec
}

// probeSpec is one concrete request a module wants sent.
type probeSpec struct {
	// label names what was tampered with ("Parameter \"next\"", "Header
	// \"X-Forwarded-Host\"", ...) -- used in finding titles.
	label string
	// sent is the payload exactly as the operator would read it in a
	// request ("next=https://…", "X-Forwarded-Host: …") -- used in finding
	// details.
	sent string
	// identifier is the callback path segment that attributes a hit to
	// this probe alone.
	identifier string
	// rawURL is the full URL this probe requests.
	rawURL string
	// headers are added on top of the operator's own headers for this
	// probe only.
	headers map[string]string
	// hostOnly marks a probe whose injected value carries nothing but a
	// host (a Host or X-Forwarded-Host header can't hold a path), so the
	// identifier can't travel in the redirect's own URL. The confirmation
	// request is instead sent to the callback host under this probe's
	// identifier path -- see confirmURL.
	hostOnly bool
}

// candidate is a probe whose response redirected toward the callback host.
// It still isn't a Finding -- only one whose identifier shows up in the
// callback poll becomes one.
type candidate struct {
	spec probeSpec
	res  *orResult
	how  string
}

// runDeps is what every module's expand and every probe needs for one run.
type runDeps struct {
	target *url.URL
	req    Request
	params []string
	// origin is scheme://host of target -- the base for path-segment
	// probes, which don't reuse the target's own path.
	origin string
	sem    chan struct{}
	// nonce is this run's random identifier suffix (see
	// openRedirectIdentifierFor).
	nonce string
}

// poison is the callback address one probe should reach: the run's
// CallbackBase plus this probe's identifier as the path segment after it.
func (d runDeps) poison(identifier string) string {
	return d.req.CallbackBase + "/" + identifier
}

// queryModule builds a payload module that tries build's value against
// every candidate query parameter. build gets the callback address this
// probe should reach and the target itself, for payloads that embed the
// target's own host to look legitimate.
func queryModule(id, name, severity string, build func(poison string, target *url.URL) string) moduleDef {
	return moduleDef{
		id: id, name: name, severity: severity,
		expand: func(d runDeps) []probeSpec {
			specs := make([]probeSpec, 0, len(d.params))
			// One probe per candidate parameter, each with its own
			// identifier so a hit can be pinned to one (payload, parameter).
			for _, p := range d.params {
				identifier := openRedirectIdentifierFor(id, p, d.nonce)
				value := build(d.poison(identifier), d.target)
				specs = append(specs, probeSpec{
					label:      fmt.Sprintf("Parameter %q", p),
					sent:       fmt.Sprintf("%s=%s", p, value),
					identifier: identifier,
					rawURL:     withParam(d.target, p, value),
				})
			}
			return specs
		},
	}
}

// pathModule builds a payload module that tries build's value as the
// destination segment of every route name in pathRedirectSegments, e.g.
// "/go/https://<poison>/".
func pathModule(id, name, severity string, build func(poison string) string) moduleDef {
	return moduleDef{
		id: id, name: name, severity: severity,
		expand: func(d runDeps) []probeSpec {
			specs := make([]probeSpec, 0, len(pathRedirectSegments))
			// One probe per route name, each attributable on its own.
			for _, seg := range pathRedirectSegments {
				identifier := openRedirectIdentifierFor(id, seg, d.nonce)
				value := build(d.poison(identifier))
				specs = append(specs, probeSpec{
					label:      fmt.Sprintf("Path /%s/", seg),
					sent:       fmt.Sprintf("GET /%s/%s", seg, value),
					identifier: identifier,
					rawURL:     d.origin + "/" + seg + "/" + value,
				})
			}
			return specs
		},
	}
}

// refererModule sends the target with a Referer pointing at the callback.
// Apps that bounce the user "back where you came from" after login or
// logout redirect to whatever Referer they were given. The identifier rides
// in the Referer's own path, so the redirect's Location carries it and no
// rewrite is needed.
var refererModule = moduleDef{
	id: "referer", name: "Referer-based redirect", severity: "medium",
	expand: func(d runDeps) []probeSpec {
		identifier := openRedirectIdentifierFor("referer", "Referer", d.nonce)
		value := "https://" + d.poison(identifier) + "/"
		return []probeSpec{{
			label:      "Referer header",
			sent:       "Referer: " + value,
			identifier: identifier,
			rawURL:     d.target.String(),
			headers:    map[string]string{"Referer": value},
		}}
	},
}

// hostHeaderModule sends the target with its Host header replaced by the
// callback host. An app that builds its own absolute URLs from the Host
// header (a redirect to "https://<Host>/", a canonical link) bounces the
// visitor to the injected host -- the vulnerability is in the server
// trusting Host, not in any query parameter.
var hostHeaderModule = moduleDef{
	id: "host-header", name: "Host header redirect", severity: "medium",
	expand: func(d runDeps) []probeSpec {
		cbHost := hostOnly(d.req.CallbackBase)
		identifier := openRedirectIdentifierFor("host-header", "Host", d.nonce)
		return []probeSpec{{
			label:      "Host header",
			sent:       "Host: " + cbHost,
			identifier: identifier,
			rawURL:     d.target.String(),
			headers:    map[string]string{"Host": cbHost},
			hostOnly:   true,
		}}
	},
}

// forwardedHostModule is hostHeaderModule for the proxy-supplied variants:
// each X-Forwarded-Host-style header on its own, plus the standard
// Forwarded header (RFC 7239), which carries the host as host="...".
var forwardedHostModule = moduleDef{
	id: "forwarded-host", name: "Forwarded-host header redirect", severity: "medium",
	expand: func(d runDeps) []probeSpec {
		cbHost := hostOnly(d.req.CallbackBase)
		specs := make([]probeSpec, 0, len(forwardedHostHeaders)+1)
		// One probe per header so a redirect can be pinned to the exact
		// header the app trusted.
		for _, h := range forwardedHostHeaders {
			identifier := openRedirectIdentifierFor("forwarded-host", h, d.nonce)
			specs = append(specs, probeSpec{
				label:      fmt.Sprintf("Header %q", h),
				sent:       h + ": " + cbHost,
				identifier: identifier,
				rawURL:     d.target.String(),
				headers:    map[string]string{h: cbHost},
				hostOnly:   true,
			})
		}
		// The RFC 7239 Forwarded header quotes its host value; the quotes
		// are required once a port is present.
		identifier := openRedirectIdentifierFor("forwarded-host", "Forwarded", d.nonce)
		fwd := `host="` + cbHost + `"`
		specs = append(specs, probeSpec{
			label:      `Header "Forwarded"`,
			sent:       "Forwarded: " + fwd,
			identifier: identifier,
			rawURL:     d.target.String(),
			headers:    map[string]string{"Forwarded": fwd},
			hostOnly:   true,
		})
		return specs
	},
}

// openRedirectModules is every vector this scanner tries. Each query-parameter
// payload is a distinct parser-disagreement shape (see PortSwigger's URL
// validation bypass cheat sheet and the OWASP open-redirect guidance): the
// point is that a filter which rejects one of them often accepts another.
var openRedirectModules = []moduleDef{
	// A plain absolute URL -- what an unfiltered parameter just accepts.
	queryModule("absolute-url", "Absolute-URL redirect", "medium", func(p string, _ *url.URL) string {
		return "https://" + p + "/"
	}),
	// No scheme at all -- the browser reuses the current page's scheme, so
	// this alone bypasses a filter that only rejects values starting "http".
	queryModule("protocol-relative", "Protocol-relative redirect", "medium", func(p string, _ *url.URL) string {
		return "//" + p + "/"
	}),
	// "%2F%2F<poison>" is "//<poison>" already percent-encoded once; the
	// query encoder encodes the '%' again on the wire, so the app sees the
	// still-encoded value. A filter checking the raw value for a literal
	// "//" misses it, and a second decode (client-side JS, or an app that
	// re-decodes) resolves it to the protocol-relative payload above.
	queryModule("double-encoded", "Double-URL-encoded redirect", "medium", func(p string, _ *url.URL) string {
		return "%2F%2F" + p
	}),
	// "/\<poison>" passes a prefix check for a leading "/" but is normalized
	// by browsers (backslash -> slash) into the protocol-relative payload.
	queryModule("backslash-trick", "Backslash-normalization redirect", "low", func(p string, _ *url.URL) string {
		return "/\\" + p
	}),
	// "\\<poison>" is the same normalization with both leading characters
	// backslashes -- filters that only expect forward slashes miss it.
	queryModule("backslash-protocol-relative", "Double-backslash redirect", "medium", func(p string, _ *url.URL) string {
		return "\\\\" + p + "/"
	}),
	// Four slashes: browsers collapse the run into an authority separator,
	// but a "starts with //" check, or a parser that stops at the second
	// slash, reads it as a path.
	queryModule("slash-run", "Slash-run redirect", "medium", func(p string, _ *url.URL) string {
		return "////" + p + "/"
	}),
	// "https://<real-host>@<poison>" starts with the real target's own URL,
	// which passes a naive "starts with our domain" check -- but every URL
	// parser treats everything before "@" as userinfo and resolves the
	// request to poison.
	queryModule("userinfo-trick", "Userinfo (@) redirect", "medium", func(p string, t *url.URL) string {
		return "https://" + t.Host + "@" + p + "/"
	}),
	// "https:<poison>" with no slashes: browsers read it as an absolute
	// https URL, but a filter looking for "https://" misses it.
	queryModule("missing-slashes", "Missing-slashes scheme redirect", "low", func(p string, _ *url.URL) string {
		return "https:" + p + "/"
	}),
	// Bare host with no scheme or slashes -- for apps that prepend their
	// own scheme ("https://" + value) before redirecting.
	queryModule("bare-host", "Bare-host redirect", "low", func(p string, _ *url.URL) string {
		return p + "/"
	}),
	// A literal tab inside the value: browsers strip ASCII tab/newline from
	// anywhere in a URL, so "/\t/<poison>" becomes "//<poison>" once
	// parsed, while the filter only ever saw a harmless-looking "/" prefix.
	queryModule("whitespace-control", "Tab-injection redirect", "low", func(p string, _ *url.URL) string {
		return "/\t/" + p + "/"
	}),
	// Leading space: browsers strip leading C0-control and space characters,
	// so " //<poison>" resolves as protocol-relative even though a filter
	// that checks the first character sees a space.
	queryModule("leading-whitespace", "Leading-whitespace redirect", "low", func(p string, _ *url.URL) string {
		return " //" + p + "/"
	}),
	// The target's own host appears only after the attacker's host (in the
	// query), so a "does the value contain our domain?" check passes.
	queryModule("allowlist-substring", "Allowlist substring redirect", "medium", func(p string, t *url.URL) string {
		return "https://" + p + "/?" + t.Hostname()
	}),

	pathModule("path-absolute", "Path-segment absolute redirect", "medium", func(p string) string {
		return "https://" + p + "/"
	}),
	pathModule("path-protocol-relative", "Path-segment protocol-relative redirect", "medium", func(p string) string {
		return "//" + p + "/"
	}),

	refererModule,
	hostHeaderModule,
	forwardedHostModule,
}

// hostOnly returns s up to (not including) its first "/" -- just the host
// portion of a "host[:port]/path" string like Request.CallbackBase.
func hostOnly(s string) string {
	host, _, _ := strings.Cut(s, "/")
	return host
}

// openRedirectIdentifierFor derives a URL-path-safe identifier for one
// (module, label, run) triple -- used on every probe, so each request stays
// individually attributable in the Collaborator tab even though they all
// share one operator-picked token. The readable prefix alone can collide
// ("URL" vs "url" once lowercased), so an FNV hash of the exact pair is
// appended. nonce is the run's own random value: a shared token keeps every
// earlier run's hits, and without it a later run would be credited with a
// hit that an earlier run produced for the same module and parameter.
func openRedirectIdentifierFor(moduleID, label, nonce string) string {
	var b strings.Builder
	b.WriteString("or-")
	b.WriteString(moduleID)
	b.WriteByte('-')
	for _, r := range label {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		default:
			b.WriteByte('-')
		}
	}
	h := fnv.New32a()
	h.Write([]byte(moduleID + "/" + label))
	fmt.Fprintf(&b, "-%08x-%s", h.Sum32(), nonce)
	return b.String()
}

// runModule expands m into its probes and fires them all concurrently
// (throttled by d.sem), returning every probe whose response led toward the
// callback host. Those are only candidates: a Finding needs the callback
// poll in Run to see the probe's identifier as well.
func runModule(ctx context.Context, d runDeps, m moduleDef, sent *atomic.Int64) []candidate {
	specs := m.expand(d)
	sent.Add(int64(len(specs)))

	var (
		mu  sync.Mutex
		out []candidate
		wg  sync.WaitGroup
	)
	// Each probe gets its own goroutine; d.sem is what bounds how many
	// requests are actually in flight at once.
	for _, ps := range specs {
		wg.Add(1)
		go func(ps probeSpec) {
			defer wg.Done()
			c, ok := runProbe(ctx, d, ps)
			if !ok {
				return
			}
			mu.Lock()
			out = append(out, c)
			mu.Unlock()
		}(ps)
	}
	wg.Wait()
	return out
}

// runProbe sends one probe, looks for a redirect toward the callback host in
// its response (following the chain when the operator asked for that), and
// if it finds one, requests the callback address itself so the listener
// records the hit. It returns ok=false when the probe never pointed at the
// callback host, so the probe can't be a candidate.
func runProbe(ctx context.Context, d runDeps, ps probeSpec) (candidate, bool) {
	res, err := send(ctx, d.sem, ps.rawURL, mergeHeaders(d.req.Headers, ps.headers))
	if err != nil {
		return candidate{}, false
	}
	base, err := url.Parse(ps.rawURL)
	if err != nil {
		return candidate{}, false
	}

	confirm, how, ok := d.findCallbackHop(ctx, res, base, ps)
	if !ok {
		return candidate{}, false
	}
	// The confirming request goes to the external callback host with no
	// operator headers: those credentials belong to the target, and
	// sending them to a third-party listener would leak them. Errors are
	// discarded -- a failed hit just means this probe isn't confirmed.
	_, _ = send(ctx, d.sem, confirm, nil)
	return candidate{spec: ps, res: res, how: how}, true
}

// findCallbackHop walks the redirect chain starting at res, looking for a
// hop whose Location points at the callback host. With FollowRedirects off
// only the first hop is inspected; on, up to maxRedirectHops are followed,
// so a redirect that reaches the callback through an intermediate page
// (login, normalization, "return to") still counts.
//
// It returns the URL to confirm against, a short description of how the
// redirect was detected, and whether one was found. If the response has no
// Location at all, the body is checked for a client-side redirect instead.
func (d runDeps) findCallbackHop(ctx context.Context, res *orResult, base *url.URL, ps probeSpec) (string, string, bool) {
	cbHost := hostOnly(d.req.CallbackBase)
	maxHops := 1
	if d.req.FollowRedirects {
		maxHops = maxRedirectHops
	}

	hop, cur := res, base
	// Walk one hop at a time; each iteration checks the current hop's
	// Location, then (if following) requests it to find the next one.
	for i := 0; i < maxHops && isRedirect(hop); i++ {
		loc, err := browserResolve(cur, hop.Location)
		if err != nil {
			break
		}
		if strings.EqualFold(loc.Host, cbHost) {
			return d.confirmURL(loc, ps), "redirected (Location header)", true
		}
		// Last permitted hop reached without finding the callback -- stop
		// rather than issuing one more request nobody will inspect.
		if i+1 == maxHops {
			break
		}
		next, err := send(ctx, d.sem, loc.String(), d.chainHeaders(loc))
		if err != nil {
			break
		}
		hop, cur = next, loc
	}

	// No redirect in the chain reached the callback. A 2xx body may still
	// describe a client-side redirect to it; only then is that page's
	// behavior worth confirming.
	if !isRedirect(res) && strings.Contains(strings.ToLower(res.Body), strings.ToLower(cbHost)) &&
		(metaRefreshRe.MatchString(res.Body) || jsRedirectRe.MatchString(res.Body)) {
		return "https://" + d.poison(ps.identifier) + "/", "rendered a client-side redirect", true
	}
	return "", "", false
}

// confirmURL is the request that actually confirms a hit. For hostOnly
// probes the redirect's own URL doesn't carry this probe's identifier, so
// the callback is requested under the identifier path instead -- the
// redirect has already proven the server sends visitors to that host.
func (d runDeps) confirmURL(loc *url.URL, ps probeSpec) string {
	if ps.hostOnly {
		return loc.Scheme + "://" + d.poison(ps.identifier) + "/"
	}
	return loc.String()
}

// chainHeaders returns what a followed hop should carry. Only hops that stay
// on the target's own host get the operator's headers (session cookies,
// tokens) -- anything bounced to another host gets none, so credentials
// never leave for a third party.
func (d runDeps) chainHeaders(loc *url.URL) map[string]string {
	if strings.EqualFold(loc.Host, d.target.Host) {
		return d.req.Headers
	}
	return nil
}

// isRedirect reports whether res is a 3xx carrying a Location header --
// the only shape a redirect hop can take.
func isRedirect(res *orResult) bool {
	return res != nil && res.StatusCode >= 300 && res.StatusCode < 400 && res.Location != ""
}

// browserResolve resolves raw against base the way a browser would, not the
// way strict RFC 3986 would: leading and trailing C0/space characters and
// embedded tabs/newlines are stripped, backslashes become slashes, a run of
// slashes after "http:"/"https:" (or at the very start) collapses to "//",
// and a bare "https:host" gets its missing slashes back. Without this, the
// backslash, whitespace, and missing-slash probes would never resolve to the
// host the victim's browser actually goes to.
func browserResolve(base *url.URL, raw string) (*url.URL, error) {
	s := strings.TrimFunc(raw, func(r rune) bool { return r <= 0x20 })
	s = strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(s)
	s = strings.ReplaceAll(s, "\\", "/")

	lower := strings.ToLower(s)
	for _, scheme := range []string{"https:", "http:"} {
		// Normalize "https:" followed by any number of slashes (or none)
		// into "https://" so the host is read the way a browser reads it.
		if strings.HasPrefix(lower, scheme) {
			s = scheme + "//" + strings.TrimLeft(s[len(scheme):], "/")
			break
		}
	}
	// A run of slashes at the start is treated as an authority separator
	// by browsers, so "////host" means "//host".
	if strings.HasPrefix(s, "//") {
		s = "//" + strings.TrimLeft(s, "/")
	}
	return base.Parse(s)
}

// mergeHeaders returns base with extra layered on top. A key in base that
// matches one in extra case-insensitively is dropped first, so the probe's
// header always wins regardless of map iteration order -- and so an operator
// Host header can't be sent alongside a probe's own Host.
func mergeHeaders(base, extra map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		if overridden(k, extra) {
			continue
		}
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// overridden reports whether key matches any name in extra, ignoring case
// (HTTP header names are case-insensitive).
func overridden(key string, extra map[string]string) bool {
	for k := range extra {
		if strings.EqualFold(k, key) {
			return true
		}
	}
	return false
}

// findingFor turns one confirmed candidate and the callback hits recorded
// against its identifier into the Finding shown to the operator.
func findingFor(c candidate, hits []collaborator.Interaction, cbHost string) Finding {
	h := hits[0]
	detail := fmt.Sprintf(
		"Sent %s and the redirect reached the callback address (%s) -- %d inbound %s interaction(s) recorded, the first from %s. Confirmed: the redirect was followed to the callback server, not just offered in a response that mentioned it.",
		c.spec.sent, c.how, len(hits), h.Protocol, h.RemoteAddr,
	)
	if c.spec.hostOnly {
		detail += fmt.Sprintf(" The injected value carries only a host, so the callback was requested under this probe's own path (%s/%s/) -- the Host value itself can't hold the identifier.", cbHost, c.spec.identifier)
	}
	return Finding{
		Label:      fmt.Sprintf("%s redirects to an attacker-controlled host (confirmed via callback)", c.spec.label),
		Detail:     detail,
		Evidence:   fmt.Sprintf("%s callback from %s at %s", h.Protocol, h.RemoteAddr, h.Timestamp.Format(time.RFC3339)),
		Method:     http.MethodGet,
		StatusCode: c.res.StatusCode,
		Request:    &c.res.Request,
	}
}

// pollCallback fetches whatever's been recorded against cb's token so far,
// via whichever provider it names -- mirrors internal/jwtscan's own pollOOB.
// A poll failure (webhook.site unreachable) reads as "nothing yet" rather
// than an error, consistent with this whole pass treating "no confirmation"
// as the safe default.
func pollCallback(cb CallbackPollConfig) []collaborator.Interaction {
	if cb.Provider == "webhooksite" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		hits, err := collaborator.PollWebhookSite(ctx, cb.Token)
		if err != nil {
			return nil
		}
		return hits
	}
	if cb.Registry == nil {
		return nil
	}
	return cb.Registry.Poll(cb.Token)
}
