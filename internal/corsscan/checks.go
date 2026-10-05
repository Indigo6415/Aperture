package corsscan

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
)

// attackerOrigin is the arbitrary, obviously-not-legitimate origin every
// "does this server just reflect whatever I send" check uses -- same role
// as pwreset's poisonDomain.
const attackerOrigin = "https://aperture-cors-poison.invalid"

// reflectsExactly reports whether res's Access-Control-Allow-Origin is
// exactly origin -- a byte-for-byte match, not a substring check, since
// that's the one thing that actually matters: the browser only grants
// cross-origin read access when the header's value equals the requesting
// page's own origin (or "*", checked separately).
func reflectsExactly(res *corsResult, origin string) bool {
	return res != nil && res.AllowOrigin == origin
}

// allowsCredentials reports whether res carries Access-Control-Allow-Credentials
// with the literal value "true". The Fetch spec compares this value
// case-sensitively, so "TRUE" or "True" does not let a browser expose a
// credentialed response and is deliberately not counted.
func allowsCredentials(res *corsResult) bool {
	return res != nil && strings.TrimSpace(res.AllowCredentials) == "true"
}

// --- Arbitrary-origin reflection ---
// The core CORS misconfiguration: the server trusts *any* Origin it's
// handed, rather than checking it against an allowlist. On its own (without
// Allow-Credentials) this only exposes responses that need no session --
// anything behind a cookie is still protected, because a cross-origin page's
// fetch() omits cookies by default -- so this is rated medium, and the
// credentialed module below carries the critical case.
var reflectedOriginModule = moduleDef{
	id: "reflected-origin", name: "Arbitrary origin reflected", severity: "medium",
	exploitation: "Host a page on any domain you control that fetches this URL and reads the response body. This works only for responses that need no session cookie; see credentialed-reflection for the authenticated case.",
	run: func(ctx context.Context, deps runDeps) []Finding {
		res := deps.attacker
		if !reflectsExactly(res, attackerOrigin) {
			return nil
		}
		return []Finding{{
			Label:      "Access-Control-Allow-Origin reflects an arbitrary, attacker-chosen origin",
			Detail:     "Sent Origin: " + attackerOrigin + " (a domain with no relationship to this target) and got it echoed back verbatim in Access-Control-Allow-Origin. Any website can read this endpoint's responses that need no cookie or session. Whether authenticated data is exposed depends on Access-Control-Allow-Credentials, which the credentialed-reflection module checks.",
			Evidence:   "Access-Control-Allow-Origin: " + res.AllowOrigin,
			Method:     deps.req.method(),
			StatusCode: res.StatusCode,
			Request:    &res.Request,
		}}
	},
}

// --- Credentialed arbitrary-origin reflection ---
// The same reflection as above, but with Access-Control-Allow-Credentials:
// true also present -- the combination that lets a malicious page read an
// authenticated (cookie-bearing) response on the victim's behalf. Kept as
// its own critical module so the worse case doesn't get buried at the same
// severity as the milder one.
var credentialedReflectionModule = moduleDef{
	id: "credentialed-reflection", name: "Credentialed arbitrary-origin reflection", severity: "critical",
	exploitation: "From any attacker-controlled page run fetch(url, {credentials: 'include'}) and read the response. The victim's logged-in session is sent along, so their private data can be read cross-origin.",
	run: func(ctx context.Context, deps runDeps) []Finding {
		res := deps.attacker
		if !reflectsExactly(res, attackerOrigin) || !allowsCredentials(res) {
			return nil
		}
		// This is the critical finding, so the flag must reproduce on a second
		// identical request. A flag seen on one response only (a cached or
		// one-off error response) is not reported.
		again, err := doRequest(ctx, deps.client, deps.target, deps.req.method(), attackerOrigin, false, "", "", deps.req.Headers)
		if err != nil || !reflectsExactly(again, attackerOrigin) || !allowsCredentials(again) {
			return nil
		}
		return []Finding{{
			Label:      "Arbitrary origin reflected together with Access-Control-Allow-Credentials: true",
			Detail:     "This is the fully exploitable form of CORS misconfiguration: a page on any origin can send an authenticated (cookie-bearing) cross-origin request here and read the response, effectively bypassing same-origin policy for this endpoint. The credentials flag was returned on two consecutive identical requests.",
			Evidence:   fmt.Sprintf("Access-Control-Allow-Origin: %s; Access-Control-Allow-Credentials: %s", res.AllowOrigin, res.AllowCredentials),
			Method:     deps.req.method(),
			StatusCode: res.StatusCode,
			Request:    &res.Request,
		}}
	},
}

// --- Vary: Origin missing on a reflected origin ---
// A response that varies its Access-Control-Allow-Origin by request Origin must
// say so with Vary: Origin. Without it, a shared cache can store the response
// with the attacker's origin in it and serve that to other users, so the
// reflection becomes a cache-poisoning problem even when no single user is
// attacked directly.
var varyOriginModule = moduleDef{
	id: "vary-origin", name: "Origin-dependent response not marked Vary: Origin", severity: "low",
	exploitation: "Send a request with Origin set to a domain you control so a shared cache stores the reflected Access-Control-Allow-Origin. Other visitors requesting the same URL may then receive a response naming your domain. Confirm the cache behaviour before reporting it as exploitable.",
	run: func(ctx context.Context, deps runDeps) []Finding {
		res := deps.attacker
		if !reflectsExactly(res, attackerOrigin) {
			return nil
		}
		// Only a Vary token of exactly "origin" counts. A substring match would
		// accept an unrelated token such as "Origin-Agent-Cluster".
		if headerTokens(res.Vary)["origin"] {
			return nil
		}
		return []Finding{{
			Label:      "Origin-dependent CORS response is not marked Vary: Origin",
			Detail:     "The endpoint echoes the request's Origin into Access-Control-Allow-Origin but does not send Vary: Origin. A shared cache may store the response with one origin's CORS header and serve it to other visitors, so a reflection can poison cached responses for users who never sent the attacker's origin.",
			Evidence:   "Vary: " + orNone(res.Vary),
			Method:     deps.req.method(),
			StatusCode: res.StatusCode,
			Request:    &res.Request,
		}}
	},
}

// --- null origin ---
// `Origin: null` is sent by browsers for a sandboxed iframe
// (<iframe sandbox src=...>), a `data:` URI, or a local file:// page --
// all trivially achievable by an attacker who doesn't need to control an
// actual domain at all. A server that trusts it is trusting exactly that.
var nullOriginModule = moduleDef{
	id: "null-origin", name: "`null` origin trusted", severity: "high",
	exploitation: "Serve the exploit from a sandboxed iframe (<iframe sandbox='allow-scripts' srcdoc='...'>) or a data: URI. The browser sends Origin: null, which this endpoint trusts.",
	run: func(ctx context.Context, deps runDeps) []Finding {
		res, err := doRequest(ctx, deps.client, deps.target, deps.req.method(), "null", false, "", "", deps.req.Headers)
		if err != nil || !reflectsExactly(res, "null") {
			return nil
		}
		detail := "Sent Origin: null and got it echoed back in Access-Control-Allow-Origin. This origin is trivially forgeable -- a sandboxed iframe, a data: URI, or a local file:// page all send it -- so trusting it is equivalent to trusting every origin."
		if allowsCredentials(res) {
			detail += " Access-Control-Allow-Credentials: true is also present, making this fully exploitable against authenticated requests."
		}
		return []Finding{{
			Label:      "Access-Control-Allow-Origin trusts the `null` origin",
			Detail:     detail,
			Evidence:   fmt.Sprintf("Access-Control-Allow-Origin: null; Access-Control-Allow-Credentials: %s", orNone(res.AllowCredentials)),
			Method:     deps.req.method(),
			StatusCode: res.StatusCode,
			Request:    &res.Request,
		}}
	},
}

// --- wildcard + credentials ---
// Access-Control-Allow-Origin: * combined with Allow-Credentials: true is
// invalid per the Fetch spec -- browsers refuse to expose the response to a
// credentialed request in this exact combination -- but it's still worth
// flagging: it's a server bug regardless (some non-browser/older HTTP
// clients don't enforce the same rule), and it signals the same underlying
// "allow everything" posture as the other checks here.
var wildcardWithCredentialsModule = moduleDef{
	id: "wildcard-credentials", name: "Wildcard origin with credentials enabled", severity: "low",
	exploitation: "Not exploitable from a compliant browser, which refuses credentialed reads under this combination. Fix it anyway: non-browser clients may enforce the rule differently, and the setting signals a permissive policy.",
	run: func(ctx context.Context, deps runDeps) []Finding {
		res := deps.attacker
		if res == nil || res.AllowOrigin != "*" || !allowsCredentials(res) {
			return nil
		}
		return []Finding{{
			Label:      "Access-Control-Allow-Origin: * sent alongside Access-Control-Allow-Credentials: true",
			Detail:     "This combination is invalid under the Fetch spec, and compliant browsers refuse to expose a credentialed response because of it, so it is not exploitable from a browser. It is still a server-side misconfiguration worth fixing: not every HTTP client enforces that rule, and it signals the same permissive CORS posture the other findings here do. Rated low for that reason.",
			Evidence:   "Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: " + res.AllowCredentials,
			Method:     deps.req.method(),
			StatusCode: res.StatusCode,
			Request:    &res.Request,
		}}
	},
}

// --- wildcard origin (no credentials) ---
// Access-Control-Allow-Origin: * on its own lets any site read the response
// to a request that carries no cookies. That is only a real problem when the
// unauthenticated response holds data it should not expose (for example,
// internal-only content reachable from the public internet), so it is rated
// low. The credentialed form is handled by wildcard-credentials above, and is
// skipped here so one header does not produce two findings.
var wildcardOriginModule = moduleDef{
	id: "wildcard-origin", name: "Wildcard origin allowed (any site can read)", severity: "low",
	exploitation: "Any site can read this endpoint's response when the request carries no credentials. It only matters if the unauthenticated response holds data that should not be exposed.",
	run: func(ctx context.Context, deps runDeps) []Finding {
		res := deps.attacker
		if res == nil || res.AllowOrigin != "*" || allowsCredentials(res) {
			return nil
		}
		return []Finding{{
			Label:      "Access-Control-Allow-Origin: * on an endpoint that gives it to any origin",
			Detail:     "The endpoint answers every Origin with Access-Control-Allow-Origin: *, so any website can read an unauthenticated response from it. Browsers never send cookies on a wildcard-origin read of this kind, so this is only a concern if the response itself is sensitive.",
			Evidence:   "Access-Control-Allow-Origin: *",
			Method:     deps.req.method(),
			StatusCode: res.StatusCode,
			Request:    &res.Request,
		}}
	},
}

// --- third-party origin trusted (static allowlist) ---
// The endpoint sends back a fixed absolute origin of another host, for example
// a code-hosting site or a partner domain, which the browser will then allow to
// read the response. Any page on that host -- or any XSS on it -- can exploit
// the trust. Our own reflected origin is excluded, since reflection is covered
// by reflected-origin.
var thirdPartyOriginModule = moduleDef{
	id: "third-party-origin", name: "Third-party origin trusted", severity: "medium",
	exploitation: "If the trusted third-party host lets users run content (codepen.io, a host with an XSS bug, a user-content CDN), run the exploit there. The browser then allows that page to read this endpoint's responses.",
	run: func(ctx context.Context, deps runDeps) []Finding {
		res := deps.attacker
		if res == nil || reflectsExactly(res, attackerOrigin) {
			return nil
		}
		acao := strings.TrimSpace(res.AllowOrigin)
		// Wildcards and the null origin are not hosts, so they have no
		// third-party host to compare against.
		if acao == "" || acao == "*" || acao == "null" {
			return nil
		}
		// Only a parseable absolute http(s) origin counts as a host. Anything
		// else is malformed, not a trusted third party.
		u, err := url.Parse(acao)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil
		}
		if strings.EqualFold(u.Host, deps.target.Host) {
			return nil
		}
		return []Finding{{
			Label:      "Access-Control-Allow-Origin names a third-party host",
			Detail:     "The endpoint always allows " + acao + ", a host other than this target. The browser will let that host's pages read this endpoint's responses, so the security of this endpoint now depends on that third party.",
			Evidence:   "Access-Control-Allow-Origin: " + res.AllowOrigin,
			Method:     deps.req.method(),
			StatusCode: res.StatusCode,
			Request:    &res.Request,
		}}
	},
}

// --- insecure protocol trust ---
// A server that trusts an http:// origin of an otherwise-legitimate host
// (when the target itself is https) is trustable by anyone who can
// man-in-the-middle that host's *plaintext* traffic -- a materially weaker
// bar than compromising the host itself. Skipped entirely when the target
// isn't https, since there's no downgrade to test.
var insecureProtocolModule = moduleDef{
	id: "insecure-protocol", name: "Insecure-protocol origin trusted", severity: "medium",
	exploitation: "Serve a page over plain http from a network position you control (shared Wi-Fi, a rogue router, ARP spoofing). Its origin is trusted, so its script can read this HTTPS endpoint's authenticated responses.",
	run: func(ctx context.Context, deps runDeps) []Finding {
		if deps.target.Scheme != "https" {
			return nil
		}
		origin := "http://" + deps.target.Host
		res, err := doRequest(ctx, deps.client, deps.target, deps.req.method(), origin, false, "", "", deps.req.Headers)
		if err != nil || !reflectsExactly(res, origin) {
			return nil
		}
		return []Finding{{
			Label:      "Plain-HTTP origin of this (HTTPS) host is trusted",
			Detail:     "Sent Origin: " + origin + " -- the same host, but over plain HTTP -- and got it reflected back. Anyone able to intercept that host's unencrypted traffic (a shared network, a malicious router, ARP spoofing on the same LAN) could use it to host a page that then reads this endpoint's authenticated response.",
			Evidence:   "Access-Control-Allow-Origin: " + res.AllowOrigin,
			Method:     deps.req.method(),
			StatusCode: res.StatusCode,
			Request:    &res.Request,
		}}
	},
}

// originProbe is one lookalike origin the related-domain module sends, with a
// human description of which allowlist mistake it is designed to catch.
type originProbe struct {
	id, description, origin string
}

// relatedOriginProbes builds the lookalike origins for target's hostname. Each
// one targets a different way an allowlist can go wrong: an unanchored
// prefix/suffix/substring check, a wildcard subdomain policy, or a regex whose
// dot was never escaped. An IP-literal host returns none, since it has no
// domain to imitate.
func relatedOriginProbes(target *url.URL) []originProbe {
	host := target.Hostname()
	scheme := target.Scheme
	if host == "" || net.ParseIP(host) != nil {
		return nil
	}

	probes := []originProbe{
		{"prefix-concat", "an attacker-chosen prefix directly concatenated onto the real hostname (no separator) -- catches an unanchored `origin.endsWith(host)`/substring check", scheme + "://evil" + host},
		{"suffix-append", "the real hostname with an attacker-controlled suffix appended -- catches an unanchored `origin.startsWith(host)`/substring check", scheme + "://" + host + ".aperture-cors-poison.invalid"},
		{"arbitrary-subdomain", "an arbitrary, never-registered subdomain of the real domain -- catches a wildcard-subdomain trust policy that's broader than intended (including a forgotten/dangling subdomain an attacker could take over)", scheme + "://aperture-cors-poison-subdomain." + host},
		{"contains-substring", "an origin that merely contains the real hostname after an unrelated host -- catches a `strings.Contains(origin, host)` check", scheme + "://aperture-cors-poison.invalid?." + host},
	}

	// A hostname's first dot, written as "." in an allowlist regex, matches any
	// character. Replacing that dot with "X" yields an origin that a regex like
	// ^https://example.com$ still accepts.
	if i := strings.Index(host, "."); i > 0 {
		probes = append(probes, originProbe{
			"regex-unescaped-dot",
			"the real hostname with one dot swapped for another character -- catches an allowlist regex whose dot was never escaped (\"example.com\" as a pattern matches \"exampleXcom\")",
			scheme + "://" + host[:i] + "X" + host[i+1:],
		})
	}
	return probes
}

// --- related-domain trust (naive allowlist matching) ---
// Covers the classic "the allowlist check isn't anchored" bugs: an app
// meaning to trust only its own domain but implemented as a substring/
// prefix/suffix check ends up trusting attacker-registerable lookalikes
// too. See PortSwigger's "CORS with a non-regex-based whitelist bypassed
// using an origin string" and "...whitelist matches related domains"
// writeups, plus the unescaped-dot regex class.
var relatedDomainTrustModule = moduleDef{
	id: "related-domain-trust", name: "Related-domain origin trusted", severity: "medium",
	exploitation: "Register or control the lookalike domain that matches the broken allowlist check (examplexcom, target.com.attacker.tld, attacker-target.com, a dangling subdomain, and so on) and host the exploit page there.",
	run: func(ctx context.Context, deps runDeps) []Finding {
		probes := relatedOriginProbes(deps.target)
		if len(probes) == 0 {
			return nil
		}

		// Every probe is sent concurrently. Each goroutine writes its own slot, so
		// the results keep probe order without a lock.
		found := make([]*Finding, len(probes))
		var wg sync.WaitGroup
		for i, p := range probes {
			wg.Add(1)
			go func(i int, p originProbe) {
				defer wg.Done()
				res, err := doRequest(ctx, deps.client, deps.target, deps.req.method(), p.origin, false, "", "", deps.req.Headers)
				if err != nil || !reflectsExactly(res, p.origin) {
					return
				}
				found[i] = &Finding{
					Label:      "Origin reflected for a related-but-untrusted domain (" + p.description + ")",
					Detail:     "Sent Origin: " + p.origin + " and got it echoed back exactly -- this domain was never registered/controlled by this target, so whatever allowlist logic accepted it is broader than intended.",
					Evidence:   "Access-Control-Allow-Origin: " + res.AllowOrigin,
					Method:     deps.req.method(),
					StatusCode: res.StatusCode,
					Request:    &res.Request,
				}
			}(i, p)
		}
		wg.Wait()

		var out []Finding
		for _, f := range found {
			if f != nil {
				out = append(out, *f)
			}
		}
		return out
	},
}

// parserProbe is one origin the parser-bypass module sends. want is the exact
// Access-Control-Allow-Origin a vulnerable parser echoes back. It differs from
// origin for the encoded-backtick probe, since the server decodes %60 before
// it reflects.
type parserProbe struct {
	id, label, detail, origin, want, exploitation string
}

// parserProbes builds the origins that exploit a sloppy hostname parser, all
// anchored on target's own hostname. An IP-literal host returns none, since it
// has no hostname to extend.
func parserProbes(target *url.URL) []parserProbe {
	host := target.Hostname()
	scheme := target.Scheme
	if host == "" || net.ParseIP(host) != nil {
		return nil
	}

	underscore := scheme + "://" + host + "_.aperture-cors-poison.invalid"
	backtick := scheme + "://" + host + "`.aperture-cors-poison.invalid"
	return []parserProbe{
		{
			id:           "underscore-suffix",
			label:        "Origin accepted when `_` follows the real hostname",
			detail:       "Sent Origin: " + underscore + " and got it echoed back. No legitimate domain of this target is named with a `_` suffix, so the allowlist matched on a prefix or pattern instead of the exact hostname.",
			origin:       underscore,
			want:         underscore,
			exploitation: "Host the exploit on a domain whose name is the target hostname followed by `_`, for example target.com_.attacker.tld, if such a name can be registered or served. Browsers send that Origin unchanged.",
		},
		{
			id:           "backtick-encoded",
			label:        "Origin accepted when a backtick follows the real hostname",
			detail:       "Sent Origin with a percent-encoded backtick (%60) after the real hostname and got back the decoded backtick in Access-Control-Allow-Origin. The server decodes the origin before checking it, so its allowlist can be bypassed with a crafted value.",
			origin:       scheme + "://" + host + "%60.aperture-cors-poison.invalid",
			want:         backtick,
			exploitation: "Browsers will not produce a backtick in an Origin, since it is not a valid host character. This is a parser-weakness signal, and the bypass is practical mainly from non-browser clients that send the raw origin.",
		},
	}
}

// parserBypassModule covers origin parsers that mishandle a character after the
// real hostname: an unescaped `_`, or a backtick that reaches the parser only
// once it has been percent-decoded.
var parserBypassModule = moduleDef{
	id: "parser-bypass", name: "Origin parser accepts a suffixed or encoded hostname", severity: "high",
	exploitation: "Host the exploit on a lookalike origin the parser accepts (see the individual finding for the exact form).",
	run: func(ctx context.Context, deps runDeps) []Finding {
		var out []Finding
		// The probes run one after another. There are only two of them, so
		// ordering them costs almost nothing and keeps the code simple.
		for _, p := range parserProbes(deps.target) {
			res, err := doRequest(ctx, deps.client, deps.target, deps.req.method(), p.origin, false, "", "", deps.req.Headers)
			if err != nil || res == nil || res.AllowOrigin != p.want {
				continue
			}
			out = append(out, Finding{
				Label:        p.label,
				Detail:       p.detail,
				Evidence:     "Access-Control-Allow-Origin: " + res.AllowOrigin,
				Method:       deps.req.method(),
				StatusCode:   res.StatusCode,
				Request:      &res.Request,
				Exploitation: p.exploitation,
			})
		}
		return out
	},
}

// --- preflight permissiveness ---
// A real preflight (OPTIONS with Access-Control-Request-Method/-Headers)
// can expose a *more* permissive policy than the simple-request checks
// above ever trigger -- e.g. a server that only reflects Origin on OPTIONS,
// or one that allows a sensitive method/header combination
// (PUT/DELETE, or reflecting a requested "Authorization" header) for an
// arbitrary origin.
//
// The method and header findings only matter when the origin is actually
// allowed. A browser stops at a preflight that does not grant the origin, so
// an Allow-Methods list on its own exposes nothing, and the module reports
// nothing without that grant.
var preflightPermissivenessModule = moduleDef{
	id: "preflight", name: "Overly permissive preflight response", severity: "medium",
	exploitation: "Trigger a cross-origin preflight from your page with the method or header in question. If the server approves it, the real request with credentials is also allowed.",
	run: func(ctx context.Context, deps runDeps) []Finding {
		res, err := doRequest(ctx, deps.client, deps.target, deps.req.method(), attackerOrigin, true, "DELETE", "Authorization, X-Aperture-Cors-Test", deps.req.Headers)
		if err != nil {
			return nil
		}
		// A browser treats any non-2xx preflight answer as a failed preflight and
		// never sends the real request, so such a response grants nothing.
		if res.StatusCode < 200 || res.StatusCode > 299 {
			return nil
		}

		reflected := reflectsExactly(res, attackerOrigin)
		// A "*" origin also grants non-credentialed cross-origin requests, so it
		// counts for the method check. It does not cover Authorization, which is
		// why the header check below requires that token explicitly.
		allowed := reflected || res.AllowOrigin == "*"

		var out []Finding
		if reflected {
			out = append(out, Finding{
				Label:        "Preflight reflects an arbitrary origin",
				Exploitation: "Any origin passes the preflight, so a credentialed cross-origin request from your page would also be allowed through. See credentialed-reflection for the read-back case.",
				Detail:       "An OPTIONS preflight from " + attackerOrigin + " got that exact origin echoed back in Access-Control-Allow-Origin, confirming the actual (non-preflight) request would be allowed through too.",
				Evidence:     "Access-Control-Allow-Origin: " + res.AllowOrigin,
				Method:       "OPTIONS",
				StatusCode:   res.StatusCode,
				Request:      &res.Request,
			})
		}
		if allowed {
			methods := headerTokens(res.AllowMethods)
			if methods["delete"] || methods["*"] {
				out = append(out, Finding{
					Label:        "Preflight allows a state-changing method (DELETE) for an arbitrary origin",
					Exploitation: "From your page run fetch(url, {method: 'DELETE', credentials: 'include'}). The browser sends the preflight, the server approves DELETE, and the state-changing request runs with the victim's session.",
					Detail:       "Requested Access-Control-Request-Method: DELETE from an attacker-controlled origin and the server's Access-Control-Allow-Methods allowed it.",
					Evidence:     "Access-Control-Allow-Methods: " + res.AllowMethods,
					Method:       "OPTIONS",
					StatusCode:   res.StatusCode,
					Request:      &res.Request,
				})
			}
			if headerTokens(res.AllowHeaders)["authorization"] {
				out = append(out, Finding{
					Label:        "Preflight allows the Authorization header for an arbitrary origin",
					Exploitation: "From your page send a cross-origin request with an Authorization header. Combined with a reflected origin, this lets the page make authenticated requests and read the responses.",
					Detail:       "Requested Access-Control-Request-Headers: Authorization from an attacker-controlled origin and the server's Access-Control-Allow-Headers allowed it -- combined with a reflected origin, this lets a cross-origin page send authenticated requests here.",
					Evidence:     "Access-Control-Allow-Headers: " + res.AllowHeaders,
					Method:       "OPTIONS",
					StatusCode:   res.StatusCode,
					Request:      &res.Request,
				})
			}
		}
		return out
	},
}

// orNone renders an empty header value as a readable placeholder.
func orNone(s string) string {
	if s == "" {
		return "(not set)"
	}
	return s
}
