package csrf

import (
	"context"
	"fmt"
	"strings"

	"github.com/Indigo6415/Aperture/internal/scanprogress"
)

// formCSRFModule flags every discovered state-changing form that has
// neither a CSRF-token-looking hidden field nor a page-level meta tag a
// script could pull a token from -- see crawl.go's csrfFieldPattern/
// csrfMetaPattern. Each such form is one progress check, judged in parallel
// (the judgement itself is instant; the check grid just shows which forms
// have been looked at).
func formCSRFModule(cr *crawlResult, rep scanprogress.Reporter) ModuleResult {
	// Only state-changing forms need a token. A GET form (search, filter) cannot
	// change anything on the server, so it isn't a check at all.
	var items []indexedForm
	for i, f := range cr.Forms {
		if strings.EqualFold(f.Method, "POST") {
			items = append(items, indexedForm{idx: i, form: f})
		}
	}
	found := make([]*Finding, len(cr.Forms))
	scanprogress.Each(rep, 0, items, func(it indexedForm) scanprogress.Check {
		return scanprogress.Check{
			ID:    fmt.Sprintf("form-csrf-token|%d", it.idx),
			Label: it.form.Method + " " + it.form.Action,
			Group: "Form CSRF tokens",
		}
	}, func(it indexedForm) (int, error) {
		f := it.form
		if f.HasToken || f.HasMetaToken {
			return 0, nil
		}
		found[it.idx] = &Finding{
			Label: fmt.Sprintf("%s form at %s has no CSRF-token-looking field", f.Method, f.Action),
			Detail: fmt.Sprintf(
				"Found on %s: a %s form submitting to %s with no hidden input named like a CSRF/authenticity token, and no page-level csrf-token meta tag either. Confirm it isn't relying on a header-based token this static check can't see (e.g. one a script attaches from a cookie) before treating this as confirmed.",
				f.PageURL, f.Method, f.Action,
			),
			Evidence: f.Method + " " + f.Action,
			Request:  &CapturedRequest{Method: "GET", URL: f.PageURL},
			// Heuristic: the token may be set by script or a header that this
			// static check cannot see, so this is a lead, not a confirmed defect.
			Confidence: ConfidenceHeuristic,
		}
		return 1, nil
	})
	return ModuleResult{ID: "form-csrf-token", Name: "Form CSRF tokens", Severity: "medium", Findings: collectFindings(found)}
}

// indexedForm is one form plus its position in the crawl's Forms slice, so a
// finding can be written back in crawl order no matter which check finished
// first.
type indexedForm struct {
	idx  int
	form discoveredForm
}

// indexedCookie is indexedForm's counterpart for a cookie.
type indexedCookie struct {
	idx    int
	cookie discoveredCookie
}

// collectFindings compacts a per-index findings slice (nil where an item
// produced nothing) into the ordered list a ModuleResult carries, with an
// empty -- never nil -- slice when there's nothing to report.
func collectFindings(found []*Finding) []Finding {
	out := []Finding{}
	for _, f := range found {
		if f != nil {
			out = append(out, *f)
		}
	}
	return out
}

// cookieSameSiteModule flags every cookie seen anywhere during the crawl
// that's missing Secure, HttpOnly, or a SameSite=Lax/Strict attribute --
// the site-wide counterpart to pwreset's own formSecurityModule, which only
// ever looks at cookies set by one specific form page. Each cookie is one
// progress check.
func cookieSameSiteModule(cr *crawlResult, rep scanprogress.Reporter) ModuleResult {
	items := make([]indexedCookie, len(cr.Cookies))
	for i, c := range cr.Cookies {
		items[i] = indexedCookie{idx: i, cookie: c}
	}
	found := make([]*Finding, len(cr.Cookies))
	scanprogress.Each(rep, 0, items, func(it indexedCookie) scanprogress.Check {
		return scanprogress.Check{
			ID:    fmt.Sprintf("samesite-cookies|%d", it.idx),
			Label: it.cookie.Name,
			Group: "Cookie SameSite attributes",
		}
	}, func(it indexedCookie) (int, error) {
		c := it.cookie
		lower := strings.ToLower(c.RawValue)
		var missing []string
		if !strings.Contains(lower, "secure") {
			missing = append(missing, "Secure")
		}
		if !strings.Contains(lower, "httponly") {
			missing = append(missing, "HttpOnly")
		}
		if !hasStrongSameSite(lower) {
			missing = append(missing, "SameSite=Lax/Strict")
		}
		if len(missing) == 0 {
			return 0, nil
		}
		found[it.idx] = &Finding{
			Label:    fmt.Sprintf("Cookie %q is missing %s", c.Name, strings.Join(missing, "/")),
			Detail:   fmt.Sprintf("First seen on %s. Without SameSite=Lax/Strict in particular, the browser will still attach this cookie to a cross-site request, which is exactly what CSRF depends on -- a token check alone doesn't help if the cookie itself rides along regardless of origin.", c.SeenOn),
			Evidence: c.RawValue,
			Request:  &CapturedRequest{Method: "GET", URL: c.SeenOn},
		}
		return 1, nil
	})
	return ModuleResult{ID: "samesite-cookies", Name: "Cookie SameSite attributes", Severity: "medium", Findings: collectFindings(found)}
}

// contentTypeBypassModule checks whether a JSON API endpoint's
// Content-Type requirement is an actual server-side check or just an
// unenforced assumption the operator may be (knowingly or not) relying on
// for CSRF protection. The requirement matters because only a
// CORS-"non-simple" Content-Type like application/json forces a browser to
// send a preflight first -- a cross-origin page can't normally get that
// header through on a real state-changing request without the target's
// CORS policy explicitly allowing it.
//
// That assumption has a well-documented history of not holding:
//   - Chrome's navigator.sendBeacon() let a page send a POST with a Blob of
//     *any* Content-Type -- including application/json -- without ever
//     triggering a preflight, for two years before being fixed in M60 (see
//     crbug.com/490015, issues.chromium.org/40082106). No CORS bypass or
//     JavaScript trick was needed; the browser itself just didn't enforce
//     the rule it was supposed to.
//   - Independent of any browser bug, text/plain has always been one of the
//     three CORS-safelisted Content-Type values (alongside
//     application/x-www-form-urlencoded and multipart/form-data) -- so a
//     plain cross-origin <form enctype="text/plain"> (zero JavaScript, zero
//     preflight, works in every browser that has ever existed) can already
//     deliver an arbitrary request body under that header. If the target
//     framework's JSON parser doesn't actually check the Content-Type it
//     received before parsing the body as JSON -- a common lenient-parser
//     default -- the "it only accepts application/json" assumption was
//     never true to begin with.
//
// This replays req.APIBody against req.APIURL twice: once under
// application/json (the "legitimate" request) and once, unchanged, under
// text/plain (what a cross-origin attacker can already send without a
// preflight). If both are accepted the same way, the Content-Type
// restriction isn't providing the protection it might appear to.
func contentTypeBypassModule(ctx context.Context, req Request) ModuleResult {
	const id, name, severity = "content-type-csrf-bypass", "Content-Type-based CSRF bypass", "high"
	empty := ModuleResult{ID: id, Name: name, Severity: severity, Findings: []Finding{}}

	body := strings.TrimSpace(req.APIBody)
	if body == "" {
		return empty
	}
	target, err := parseTarget(req.APIURL)
	if err != nil {
		return empty
	}
	method := strings.ToUpper(strings.TrimSpace(req.APIMethod))
	if method == "" {
		method = "POST"
	}

	client := newClient()
	baseline, err := submitAPIRequest(ctx, client, target, method, body, "application/json", req.Headers)
	if err != nil || baseline.StatusCode >= 400 {
		// Either the request itself failed, or the server didn't even
		// accept its own expected Content-Type for this body -- nothing
		// meaningful to compare the bypass attempt against.
		return empty
	}

	bypass, err := submitAPIRequest(ctx, client, target, method, body, "text/plain;charset=UTF-8", req.Headers)
	if err != nil || bypass.StatusCode != baseline.StatusCode {
		// A different status code (commonly 400/415/422) means the server
		// told the two requests apart -- the restriction is real.
		return empty
	}

	return ModuleResult{ID: id, Name: name, Severity: severity, Findings: []Finding{{
		Label: fmt.Sprintf("%s %s accepts this body under Content-Type: text/plain, same as application/json", method, req.APIURL),
		Detail: "Sent the identical body twice: once as application/json (" + httpStatus(baseline.StatusCode) + ") and once, byte-for-byte unchanged, as text/plain (" + httpStatus(bypass.StatusCode) + "). " +
			"text/plain is CORS-safelisted -- a cross-origin page can send it via a plain <form enctype=\"text/plain\"> with no preflight, no CORS headers, and no JavaScript workaround required (this is the still-exploitable descendant of crbug.com/490015, where Chrome's sendBeacon() let an arbitrary Content-Type through the same way). " +
			"If this endpoint's only real defense against CSRF was the assumption that attackers can't set Content-Type: application/json cross-origin, that assumption doesn't hold here. " +
			"Confirm manually that both requests produced the same server-side effect, not just the same status code, before treating this as confirmed.",
		Evidence: fmt.Sprintf("application/json -> %d; text/plain -> %d", baseline.StatusCode, bypass.StatusCode),
		Request:  &bypass.Request,
	}}}
}

func httpStatus(code int) string {
	return fmt.Sprintf("HTTP %d", code)
}

func hasStrongSameSite(lowerCookie string) bool {
	idx := strings.Index(lowerCookie, "samesite=")
	if idx < 0 {
		return false
	}
	rest := lowerCookie[idx+len("samesite="):]
	end := strings.IndexAny(rest, "; \t")
	if end >= 0 {
		rest = rest[:end]
	}
	return rest == "lax" || rest == "strict"
}
