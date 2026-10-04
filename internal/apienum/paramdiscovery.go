package apienum

import (
	"bytes"
	"context"
	"net/url"
	"strings"

	"github.com/Indigo6415/Aperture/internal/fingerprint"
)

// discoveryParams is a short list of query parameter names that show up on
// real endpoints far more often than chance: pagination, filtering, output
// format, debug switches, redirect targets, and identifiers. It is not a full
// wordlist; the point is to catch a handful of undocumented switches per route
// at a cost of a few requests.
var discoveryParams = []string{
	"id", "user_id", "userId", "page", "per_page", "limit", "offset", "cursor", "size", "sort", "order",
	"filter", "q", "query", "search", "fields", "include", "expand", "format", "output", "lang", "locale",
	"callback", "jsonp", "debug", "verbose", "test", "dev", "admin", "raw", "pretty", "export", "download",
	"type", "status", "state", "role", "scope", "token", "key", "api_key", "access_token", "auth",
	"redirect", "redirect_uri", "return", "next", "url", "file", "path", "template", "dir", "name",
	"version", "v", "tenant", "org_id", "account", "email", "username",
}

// paramProbeChunk is how many candidate names one request carries. Each chunk
// is one request when nothing changes, and a bisection when something does.
const paramProbeChunk = 12

// paramCanary is the value every probed parameter is set to. It is a plain
// word with no digits or symbols, so a reflection check can find it and it
// isn't mistaken for a numeric ID or a boolean.
const paramCanary = "aperturecanary"

// discoverQueryParams sweeps discoveryParams against resolvedPath's GET and
// returns the names whose presence changes the response, as query params. A
// name is included when its request differs from a baseline that was itself
// stable across two identical requests, so dynamic pages don't read as
// parameters. A name whose canary value comes back in the body is flagged as
// reflected.
//
// Names the route already documents are skipped. Bisection keeps the cost near
// one request per chunk for a route that responds to nothing.
func (c *apiClient) discoverQueryParams(ctx context.Context, t *Target, resolvedPath string, known []Param) []Param {
	base := strings.TrimRight(t.URL, "/") + resolvedPath

	// Two identical baseline requests. If the route doesn't answer the same way
	// twice, a difference later on tells us nothing.
	b1, err1 := c.doNoFollow(ctx, "GET", base, nil, false, nil)
	b2, err2 := c.doNoFollow(ctx, "GET", base, nil, false, nil)
	if err1 != nil || err2 != nil {
		return nil
	}
	o1 := observe(b1)
	if b1.StatusCode != b2.StatusCode || !fingerprint.Similar(o1, observe(b2)) {
		return nil
	}

	documented := map[string]bool{}
	for _, p := range known {
		if p.Location == LocationQuery {
			documented[p.Name] = true
		}
	}
	var candidates []string
	for _, name := range discoveryParams {
		if !documented[name] {
			candidates = append(candidates, name)
		}
	}

	var found []Param
	for start := 0; start < len(candidates); start += paramProbeChunk {
		if ctx.Err() != nil {
			break
		}
		end := min(start+paramProbeChunk, len(candidates))
		c.bisectParams(ctx, base, candidates[start:end], o1, &found)
	}
	return found
}

// bisectParams sends names as one request. If that request differs from the
// baseline, it splits names in half and recurses until each differing name is
// on its own. Every name that changes the response is appended to found.
func (c *apiClient) bisectParams(ctx context.Context, base string, names []string, baseline fingerprint.Observation, found *[]Param) {
	if len(names) == 0 || ctx.Err() != nil {
		return
	}
	changed, reflected := c.probeParams(ctx, base, names, baseline)
	if !changed {
		return
	}
	if len(names) == 1 {
		*found = append(*found, paramFinding(names[0], reflected))
		return
	}
	mid := len(names) / 2
	c.bisectParams(ctx, base, names[:mid], baseline, found)
	c.bisectParams(ctx, base, names[mid:], baseline, found)
}

// probeParams requests base with every name set to the canary. changed reports
// whether the answer differs from baseline, and reflected whether the canary
// itself came back in the body. A reflected canary always counts as changed.
func (c *apiClient) probeParams(ctx context.Context, base string, names []string, baseline fingerprint.Observation) (changed, reflected bool) {
	q := url.Values{}
	for _, n := range names {
		q.Set(n, paramCanary)
	}
	res, err := c.doNoFollow(ctx, "GET", base+"?"+q.Encode(), nil, false, nil)
	if err != nil {
		return false, false
	}
	reflected = bytes.Contains(res.Body, []byte(paramCanary))
	changed = res.StatusCode != baseline.Status || !fingerprint.Similar(baseline, observe(res))
	return changed || reflected, reflected
}

// paramFinding builds the Param a discovered name is recorded as. The name
// gets flagParam's name-based reason when it has one. Otherwise the reason
// says the parameter changes the response, and a reflected one says so.
func paramFinding(name string, reflected bool) Param {
	p := flagParam(Param{Name: name, Location: LocationQuery})
	switch {
	case reflected:
		p.Flagged = true
		p.Reason = "undocumented query parameter whose value is reflected in the response -- reflection candidate"
	case !p.Flagged:
		p.Flagged = true
		p.Reason = "undocumented query parameter that changes the response when set"
	}
	return p
}
