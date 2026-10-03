package corsscan

import (
	"context"
	"fmt"
	"net"
	"strings"
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

func allowsCredentials(res *corsResult) bool {
	return res != nil && strings.EqualFold(strings.TrimSpace(res.AllowCredentials), "true")
}

// --- Arbitrary-origin reflection ---
// The core CORS misconfiguration: the server trusts *any* Origin it's
// handed, rather than checking it against an allowlist. On its own (without
// Allow-Credentials) this still leaks any response that isn't otherwise
// protected by a cookie/session, since a malicious page can still read it
// via fetch() with credentials: 'omit'.
var reflectedOriginModule = moduleDef{
	id: "reflected-origin", name: "Arbitrary origin reflected", severity: "high",
	run: func(ctx context.Context, deps runDeps) []Finding {
		client := newClient()
		res, err := doRequest(ctx, client, deps.target, deps.req.method(), attackerOrigin, false, "", "", deps.req.Headers)
		if err != nil || !reflectsExactly(res, attackerOrigin) {
			return nil
		}
		return []Finding{{
			Label:      "Access-Control-Allow-Origin reflects an arbitrary, attacker-chosen origin",
			Detail:     "Sent Origin: " + attackerOrigin + " (a domain with no relationship to this target) and got it echoed back verbatim in Access-Control-Allow-Origin -- any website can read this endpoint's response via a cross-origin fetch().",
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
// authenticated (cookie-bearing) response on the victim's behalf, not just
// whatever an anonymous request would've returned anyway. Kept as its own
// critical-severity module rather than folded into reflected-origin above
// so the worse case doesn't get buried at the same severity as the milder
// one.
var credentialedReflectionModule = moduleDef{
	id: "credentialed-reflection", name: "Credentialed arbitrary-origin reflection", severity: "critical",
	run: func(ctx context.Context, deps runDeps) []Finding {
		client := newClient()
		res, err := doRequest(ctx, client, deps.target, deps.req.method(), attackerOrigin, false, "", "", deps.req.Headers)
		if err != nil || !reflectsExactly(res, attackerOrigin) || !allowsCredentials(res) {
			return nil
		}
		return []Finding{{
			Label:      "Arbitrary origin reflected together with Access-Control-Allow-Credentials: true",
			Detail:     "This is the fully exploitable form of CORS misconfiguration: a page on any origin can send an authenticated (cookie-bearing) cross-origin request here and read the response, effectively bypassing same-origin policy for this endpoint entirely.",
			Evidence:   fmt.Sprintf("Access-Control-Allow-Origin: %s; Access-Control-Allow-Credentials: %s", res.AllowOrigin, res.AllowCredentials),
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
	run: func(ctx context.Context, deps runDeps) []Finding {
		client := newClient()
		res, err := doRequest(ctx, client, deps.target, deps.req.method(), "null", false, "", "", deps.req.Headers)
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
	run: func(ctx context.Context, deps runDeps) []Finding {
		client := newClient()
		res, err := doRequest(ctx, client, deps.target, deps.req.method(), attackerOrigin, false, "", "", deps.req.Headers)
		if err != nil || res.AllowOrigin != "*" || !allowsCredentials(res) {
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

// --- insecure protocol trust ---
// A server that trusts an http:// origin of an otherwise-legitimate host
// (when the target itself is https) is trustable by anyone who can
// man-in-the-middle that host's *plaintext* traffic -- a materially weaker
// bar than compromising the host itself. Skipped entirely when the target
// isn't https, since there's no downgrade to test.
var insecureProtocolModule = moduleDef{
	id: "insecure-protocol", name: "Insecure-protocol origin trusted", severity: "medium",
	run: func(ctx context.Context, deps runDeps) []Finding {
		if deps.target.Scheme != "https" {
			return nil
		}
		origin := "http://" + deps.target.Host
		client := newClient()
		res, err := doRequest(ctx, client, deps.target, deps.req.method(), origin, false, "", "", deps.req.Headers)
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

// --- related-domain trust (naive allowlist matching) ---
// Covers the classic "the allowlist check isn't anchored" bugs: an app
// meaning to trust only its own domain but implemented as a substring/
// prefix/suffix check ends up trusting attacker-registerable lookalikes
// too. See PortSwigger's "CORS with a non-regex-based whitelist bypassed
// using an origin string" and "...whitelist matches related domains"
// writeups for the exact patterns these three probes target.
var relatedDomainTrustModule = moduleDef{
	id: "related-domain-trust", name: "Related-domain origin trusted", severity: "medium",
	run: func(ctx context.Context, deps runDeps) []Finding {
		host := deps.target.Hostname()
		// IP-literal hosts have no "related domain" to construct a
		// lookalike of -- this whole check only makes sense against a real
		// domain name.
		if host == "" || net.ParseIP(host) != nil {
			return nil
		}
		scheme := deps.target.Scheme

		type probe struct {
			id, description, origin string
		}
		probes := []probe{
			{"prefix-concat", "an attacker-chosen prefix directly concatenated onto the real hostname (no separator) -- catches an unanchored `origin.endsWith(host)`/substring check", scheme + "://evil" + host},
			{"suffix-append", "the real hostname with an attacker-controlled suffix appended -- catches an unanchored `origin.startsWith(host)`/substring check", scheme + "://" + host + ".aperture-cors-poison.invalid"},
			{"arbitrary-subdomain", "an arbitrary, never-registered subdomain of the real domain -- catches a wildcard-subdomain trust policy that's broader than intended (including a forgotten/dangling subdomain an attacker could take over)", scheme + "://aperture-cors-poison-subdomain." + host},
		}

		client := newClient()
		type hit struct {
			idx     int
			finding Finding
		}
		results := make(chan hit, len(probes))
		for i, p := range probes {
			go func(i int, p probe) {
				res, err := doRequest(ctx, client, deps.target, deps.req.method(), p.origin, false, "", "", deps.req.Headers)
				if err != nil || !reflectsExactly(res, p.origin) {
					results <- hit{idx: i}
					return
				}
				results <- hit{idx: i, finding: Finding{
					Label:      "Origin reflected for a related-but-untrusted domain (" + p.description + ")",
					Detail:     "Sent Origin: " + p.origin + " and got it echoed back exactly -- this domain was never registered/controlled by this target, so whatever allowlist logic accepted it is broader than intended.",
					Evidence:   "Access-Control-Allow-Origin: " + res.AllowOrigin,
					Method:     deps.req.method(),
					StatusCode: res.StatusCode,
					Request:    &res.Request,
				}}
			}(i, p)
		}

		found := make([]*Finding, len(probes))
		for range probes {
			h := <-results
			if h.finding.Label != "" {
				f := h.finding
				found[h.idx] = &f
			}
		}
		var out []Finding
		for _, f := range found {
			if f != nil {
				out = append(out, *f)
			}
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
var preflightPermissivenessModule = moduleDef{
	id: "preflight", name: "Overly permissive preflight response", severity: "medium",
	run: func(ctx context.Context, deps runDeps) []Finding {
		client := newClient()
		res, err := doRequest(ctx, client, deps.target, deps.req.method(), attackerOrigin, true, "DELETE", "Authorization, X-Aperture-Cors-Test", deps.req.Headers)
		if err != nil {
			return nil
		}

		var out []Finding
		if reflectsExactly(res, attackerOrigin) {
			out = append(out, Finding{
				Label:      "Preflight reflects an arbitrary origin",
				Detail:     "An OPTIONS preflight from " + attackerOrigin + " got that exact origin echoed back in Access-Control-Allow-Origin, confirming the actual (non-preflight) request would be allowed through too.",
				Evidence:   "Access-Control-Allow-Origin: " + res.AllowOrigin,
				Method:     "OPTIONS",
				StatusCode: res.StatusCode,
				Request:    &res.Request,
			})
		}
		if strings.Contains(res.AllowMethods, "DELETE") || strings.Contains(res.AllowMethods, "*") {
			out = append(out, Finding{
				Label:      "Preflight allows a state-changing method (DELETE) for an arbitrary origin",
				Detail:     "Requested Access-Control-Request-Method: DELETE from an attacker-controlled origin and the server's Access-Control-Allow-Methods allowed it.",
				Evidence:   "Access-Control-Allow-Methods: " + res.AllowMethods,
				Method:     "OPTIONS",
				StatusCode: res.StatusCode,
				Request:    &res.Request,
			})
		}
		if strings.Contains(strings.ToLower(res.AllowHeaders), "authorization") {
			out = append(out, Finding{
				Label:      "Preflight allows the Authorization header for an arbitrary origin",
				Detail:     "Requested Access-Control-Request-Headers: Authorization from an attacker-controlled origin and the server's Access-Control-Allow-Headers allowed it -- combined with a reflected origin, this lets a cross-origin page send authenticated requests here.",
				Evidence:   "Access-Control-Allow-Headers: " + res.AllowHeaders,
				Method:     "OPTIONS",
				StatusCode: res.StatusCode,
				Request:    &res.Request,
			})
		}
		return out
	},
}

func orNone(s string) string {
	if s == "" {
		return "(not set)"
	}
	return s
}
