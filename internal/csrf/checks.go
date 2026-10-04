package csrf

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/Indigo6415/Aperture/internal/scanprogress"
)

// formContentType is the form-encoded type the token-validation replays send.
const formContentType = "application/x-www-form-urlencoded"

// invalidTokenValue is the wrong token the token-validation check substitutes
// for the real one. It is a fixed, obviously fake string, so it can't collide
// with a real token.
const invalidTokenValue = "aperture-invalid-token"

// formGroup collects the pages one missing-token form (same method and action)
// appears on, so it is reported once rather than once per page.
type formGroup struct {
	form  discoveredForm
	pages []string
}

// formCSRFModule flags every discovered state-changing form that has neither a
// CSRF-token-looking hidden field nor a page-level meta tag a script could read
// a token from (see extractForms). The same form repeated across pages, such as
// a header logout form, is reported once with its page list rather than once per
// page. Each form is one progress check.
func formCSRFModule(cr *crawlResult, rep scanprogress.Reporter) ModuleResult {
	items := make([]indexedForm, len(cr.Forms))
	for i, f := range cr.Forms {
		items[i] = indexedForm{idx: i, form: f}
	}
	// missing[i] is set by the judgement below, one slot per form, so the
	// concurrent judgements never write the same element.
	missing := make([]bool, len(cr.Forms))
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
		missing[it.idx] = true
		return 1, nil
	})

	// Group the missing forms by method and action, keeping crawl order.
	var order []string
	groups := map[string]*formGroup{}
	for i, f := range cr.Forms {
		if !missing[i] {
			continue
		}
		key := f.Method + " " + f.Action
		g, ok := groups[key]
		if !ok {
			g = &formGroup{form: f}
			groups[key] = g
			order = append(order, key)
		}
		g.pages = append(g.pages, f.PageURL)
	}

	out := []Finding{}
	for _, key := range order {
		g := groups[key]
		f := g.form
		// Note the other pages the same form appears on, if any.
		more := ""
		if len(g.pages) > 1 {
			more = fmt.Sprintf(" (and on %d other page(s))", len(g.pages)-1)
		}
		out = append(out, Finding{
			Label: fmt.Sprintf("%s form at %s has no CSRF-token-looking field", f.Method, f.Action),
			Detail: fmt.Sprintf(
				"Found on %s%s: a %s submission to %s with no hidden input named like a CSRF/authenticity token, and no page-level csrf-token meta tag either. Confirm it isn't relying on a header-based token this static check can't see (e.g. one a script attaches from a cookie) before treating this as confirmed.",
				f.PageURL, more, f.Method, f.Action,
			),
			Evidence: f.Method + " " + f.Action,
			Request:  &CapturedRequest{Method: "GET", URL: f.PageURL},
			// Heuristic: the token may be set by script or a header that this
			// static check cannot see, so this is a lead, not a confirmed defect.
			Confidence: ConfidenceHeuristic,
		})
	}
	return ModuleResult{ID: "form-csrf-token", Name: "Form CSRF tokens", Severity: "medium", Findings: out}
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

// cookieSameSiteModule checks the SameSite attribute of every cookie the crawl
// saw. SameSite is the attribute that stops a browser from attaching a cookie
// to a cross-site request, so a session cookie without it is what CSRF rides on.
//
// Only SameSite is judged here. Secure and HttpOnly have nothing to do with
// CSRF and are left to the password-reset scanner's form checks. Analytics and
// consent cookies are skipped. A cookie with SameSite=None is flagged as likely,
// since that value sends it cross-site on purpose. A cookie with no SameSite
// attribute is flagged as heuristic only when its name looks like a session or
// auth cookie, since modern browsers default such cookies to Lax.
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
		if isTrackingCookie(c.Name) {
			return 0, nil
		}
		sameSite := parseSetCookie(c.RawValue).SameSite
		switch {
		case sameSite == "lax" || sameSite == "strict":
			// Already protected: the browser withholds this cookie cross-site.
			return 0, nil
		case sameSite == "none":
			found[it.idx] = &Finding{
				Label:    fmt.Sprintf("Cookie %q is set with SameSite=None", c.Name),
				Detail:   fmt.Sprintf("First seen on %s. SameSite=None sends this cookie on cross-site requests by design, so a cross-site form POST carries it and CSRF defense rests entirely on a token check. Expected only for a cookie that must work inside cross-site embeds.", c.SeenOn),
				Evidence: c.RawValue,
				Request:  &CapturedRequest{Method: "GET", URL: c.SeenOn},
				// Explicit None is a stated fact in the response header, so it is
				// stronger than a missing attribute.
				Confidence: ConfidenceLikely,
			}
			return 1, nil
		case looksLikeAuthCookie(c.Name):
			found[it.idx] = &Finding{
				Label:    fmt.Sprintf("Cookie %q has no SameSite attribute", c.Name),
				Detail:   fmt.Sprintf("First seen on %s. Modern browsers default a cookie without SameSite to Lax, which blocks most cross-site POSTs, so this is a defense-in-depth gap rather than a confirmed open path. Older browsers and non-browser clients do not apply that default.", c.SeenOn),
				Evidence: c.RawValue,
				Request:  &CapturedRequest{Method: "GET", URL: c.SeenOn},
				// The missing attribute is observed, but its real effect depends on
				// the client's default, so this is heuristic.
				Confidence: ConfidenceHeuristic,
			}
			return 1, nil
		}
		// A missing SameSite on a non-auth cookie carries no CSRF impact.
		return 0, nil
	})
	return ModuleResult{ID: "samesite-cookies", Name: "Cookie SameSite attributes", Severity: "medium", Findings: collectFindings(found)}
}

// contentTypeBypassModule checks whether a JSON API endpoint's Content-Type
// requirement is an actual server-side check or just an unenforced assumption
// the operator may be relying on for CSRF protection. The requirement matters
// because only a CORS-"non-simple" Content-Type like application/json forces a
// browser to send a preflight first.
//
// That assumption has a well-documented history of not holding:
//   - Chrome's navigator.sendBeacon() let a page send a POST with a Blob of
//     *any* Content-Type -- including application/json -- without a preflight,
//     for two years before being fixed in M60 (crbug.com/490015).
//   - text/plain and application/x-www-form-urlencoded are CORS-safelisted, so
//     a cross-origin <form enctype="text/plain"> (or a plain form POST) can already
//     deliver an arbitrary body with no preflight. If the target parses that body
//     as JSON without checking the Content-Type it received, the assumption was
//     never true.
//
// This replays req.APIBody against req.APIURL: once as application/json (the
// legitimate request), then unchanged under each CORS-safelisted type. A bypass
// is reported only when the replay answers the same way as the baseline, judged
// by outcomeDiffers: no error status, the same status and redirect, no rejection
// wording, and a similar body length.
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

	client := newSubmitClient()
	baseline, err := submitAPIRequest(ctx, client, target, method, body, "application/json", req.Headers)
	if err != nil || baseline.StatusCode >= 400 {
		// Either the request itself failed, or the server didn't even accept
		// its own expected Content-Type for this body. Nothing meaningful to
		// compare the bypass attempts against.
		return empty
	}

	// Each CORS-safelisted type that a cross-origin page can send without a
	// preflight is tried in turn, against the same baseline.
	bypassTypes := []string{"text/plain;charset=UTF-8", "application/x-www-form-urlencoded"}
	var accepted []*apiResult
	var labels, evidence []string
	evidence = append(evidence, fmt.Sprintf("application/json -> HTTP %d", baseline.StatusCode))
	for _, ct := range bypassTypes {
		bypass, err := submitAPIRequest(ctx, client, target, method, body, ct, req.Headers)
		if err != nil {
			continue
		}
		mediaType := strings.TrimSpace(strings.SplitN(ct, ";", 2)[0])
		differs, why := outcomeDiffers(baseline, bypass)
		if differs {
			// The server told the two requests apart, so the restriction is real
			// for this type.
			evidence = append(evidence, fmt.Sprintf("%s -> HTTP %d (rejected: %s)", mediaType, bypass.StatusCode, why))
			continue
		}
		accepted = append(accepted, bypass)
		labels = append(labels, mediaType)
		evidence = append(evidence, fmt.Sprintf("%s -> HTTP %d (accepted)", mediaType, bypass.StatusCode))
	}
	if len(accepted) == 0 {
		return empty
	}

	return ModuleResult{ID: id, Name: name, Severity: severity, Findings: []Finding{{
		Label: fmt.Sprintf("%s %s accepts this body under Content-Type: %s, same as application/json", method, req.APIURL, strings.Join(labels, " and ")),
		Detail: fmt.Sprintf("Sent the identical body as application/json (HTTP %d) and then, byte-for-byte unchanged, under %s. The replays got the same response as the baseline, with no rejection wording or redirect change. "+
			"Those types are CORS-safelisted: a cross-origin page can send them with a plain <form> and no preflight, no CORS headers, and no JavaScript. "+
			"If this endpoint's only real defense against CSRF was the assumption that attackers can't set Content-Type: application/json cross-origin, that assumption doesn't hold here. "+
			"This check replays state-changing requests, so confirm manually that the replays produced the same server-side effect, not just the same status code, before treating this as confirmed.",
			baseline.StatusCode, strings.Join(labels, " and ")),
		Evidence:   strings.Join(evidence, "; "),
		Request:    &accepted[0].Request,
		Confidence: ConfidenceLikely,
	}}}
}

// tokenValidationModule checks whether a form endpoint enforces its anti-CSRF
// token at all. It is the one module that sends a tampered state-changing request
// to a target, and it only ever does so to the endpoint the operator named in
// req.TokenProbe. Per request it sends:
//   - the valid body twice, to confirm the baseline is stable and successful;
//   - the body with the token field removed, emptied, and set to a wrong value;
//   - a control body with no fields at all.
//
// A token is reported as not validated only when a tampered variant is accepted
// (same outcome as the baseline) and the control is answered differently from the
// baseline. The control separates "this endpoint ignores its input and says ok
// to everything" from "this endpoint checks its input, but not the token".
// Without the control, an endpoint that always returns the same success page would
// look like a token bypass.
func tokenValidationModule(ctx context.Context, probe *TokenProbe, headers map[string]string) ModuleResult {
	const id, name, severity = "token-validation", "CSRF token validation", "high"
	empty := ModuleResult{ID: id, Name: name, Severity: severity, Findings: []Finding{}}

	if probe == nil || strings.TrimSpace(probe.URL) == "" || probe.Field == "" {
		return empty
	}
	target, err := parseTarget(probe.URL)
	if err != nil {
		return empty
	}
	method := strings.ToUpper(strings.TrimSpace(probe.Method))
	if method == "" {
		method = "POST"
	}
	values, err := url.ParseQuery(probe.Body)
	if err != nil {
		return empty
	}
	// The token field must be present in the body. Otherwise the "removed" variant
	// would equal the valid request, and a server that accepts it would look like
	// a token bypass when it's really just a mis-named field.
	if _, ok := values[probe.Field]; !ok {
		return empty
	}

	client := newSubmitClient()
	send := func(body string) (*apiResult, error) {
		return submitAPIRequest(ctx, client, target, method, body, formContentType, headers)
	}

	// Baseline: the valid request must succeed, and must answer the same way
	// twice, so every later comparison is against a stable reference.
	valid := values.Encode()
	base, err := send(valid)
	if err != nil || base.StatusCode >= 400 {
		return empty
	}
	repeat, err := send(valid)
	if err != nil {
		return empty
	}
	if differs, _ := outcomeDiffers(base, repeat); differs {
		return empty
	}

	variants := []struct{ short, body string }{
		{"removed", withoutField(values, probe.Field)},
		{"empty", withField(values, probe.Field, "")},
		{"wrong", withField(values, probe.Field, invalidTokenValue)},
	}
	var accepted []*apiResult
	var labels, evidence []string
	for _, v := range variants {
		// A variant identical to the valid body tests nothing, e.g. "empty" when
		// the field was already empty.
		if v.body == valid {
			continue
		}
		res, err := send(v.body)
		if err != nil {
			evidence = append(evidence, fmt.Sprintf("token %s: request failed", v.short))
			continue
		}
		if differs, why := outcomeDiffers(base, res); differs {
			evidence = append(evidence, fmt.Sprintf("token %s: rejected (%s)", v.short, why))
			continue
		}
		accepted = append(accepted, res)
		labels = append(labels, v.short)
		evidence = append(evidence, fmt.Sprintf("token %s: accepted (HTTP %d)", v.short, res.StatusCode))
	}
	if len(accepted) == 0 {
		return empty
	}

	// The control. An endpoint that answers an empty request the same as the
	// valid one doesn't inspect its input, so accepting a tampered token there
	// proves nothing about token enforcement.
	control, err := send("")
	if err != nil {
		return empty
	}
	if differs, _ := outcomeDiffers(base, control); !differs {
		return empty
	}

	first := accepted[0]
	return ModuleResult{ID: id, Name: name, Severity: severity, Findings: []Finding{{
		Label: fmt.Sprintf("%s %s accepted a submission with the %q token %s", method, probe.URL, probe.Field, strings.Join(labels, " and ")),
		Detail: fmt.Sprintf("The valid request answered the same way twice (HTTP %d), so it is a stable baseline. Replays with the token %s still got that same response, with no rejection wording or redirect change. "+
			"A request with no fields at all was answered differently, so the endpoint does inspect its input, and the token check is not simply being skipped. "+
			"A CSRF token that is enforced would reject these replays. This check changes state on the target, so confirm the tampered requests had no real effect before treating this as confirmed.",
			base.StatusCode, strings.Join(labels, " and ")),
		Evidence:   strings.Join(evidence, "; "),
		Request:    &first.Request,
		Confidence: ConfidenceLikely,
	}}}
}

// withField returns values encoded with field set to value. values itself is
// not changed.
func withField(values url.Values, field, value string) string {
	c := cloneValues(values)
	c.Set(field, value)
	return c.Encode()
}

// withoutField returns values encoded with field removed. values itself is not
// changed.
func withoutField(values url.Values, field string) string {
	c := cloneValues(values)
	c.Del(field)
	return c.Encode()
}

// cloneValues returns a deep copy of v, so a replay variant can change a field
// without touching the others.
func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	// Copy each key's slice so later edits to one variant can't reach another.
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}
