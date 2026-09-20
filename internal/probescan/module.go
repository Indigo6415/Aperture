package probescan

import (
	"context"
	"strings"
)

// Finding is one thing a module discovered -- a path that exists, a
// misconfiguration, an exposed file. Label/URL/Detail are the summary a
// finding list renders inline; Method/StatusCode/Evidence are the "how was
// this found" specifics (the request that triggered it, and the exact
// matched content -- a leaked key's value, a SQL error string, a reflected
// payload) shown when a finding is expanded for more detail.
type Finding struct {
	Label      string `json:"label"`
	URL        string `json:"url,omitempty"`
	Detail     string `json:"detail,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
	Method     string `json:"method,omitempty"`
	StatusCode int    `json:"statusCode,omitempty"`
}

// ModuleResult is one check category's outcome, shaped for direct rendering
// as a collapsible section in the UI -- always present in ScanResponse
// (possibly with zero findings) so the frontend can show "checked, nothing
// found" rather than the module having silently not run.
type ModuleResult struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Severity string    `json:"severity"` // info | low | medium | high | critical
	Findings []Finding `json:"findings"`
}

// moduleDef is one check category, ported from a modules/*.py file in the
// original probe tool. run receives the shared client every module uses
// concurrently against the same target.
type moduleDef struct {
	id       string
	name     string
	severity string
	run      func(ctx context.Context, t *Target, c *probeClient) []Finding
}

// pathCheck is a single "GET this path, decide if the response indicates a
// hit" entry -- the Go equivalent of the (path, label, validate) tuples the
// Python modules build their CHECKS tables from.
type pathCheck struct {
	path  string
	label string
	valid func(r *httpResult) bool
}

// --- Shared response-validator helpers, mirroring the small predicates
// the Python modules inline as lambdas. ---

func nonEmptyBody(r *httpResult) bool { return len(r.Text) > 0 }

func containsAny(subs ...string) func(r *httpResult) bool {
	return func(r *httpResult) bool {
		body := r.textLower()
		for _, s := range subs {
			if strings.Contains(body, s) {
				return true
			}
		}
		return false
	}
}

func containsAll(subs ...string) func(r *httpResult) bool {
	return func(r *httpResult) bool {
		body := r.textLower()
		for _, s := range subs {
			if !strings.Contains(body, s) {
				return false
			}
		}
		return true
	}
}

// containsCase is a case-sensitive contains check, for the handful of
// Python checks that test the raw (non-lowercased) body -- e.g. "{" in
// r.text, "FROM " in r.text, "DB_" in r.text.
func containsCase(subs ...string) func(r *httpResult) bool {
	return func(r *httpResult) bool {
		for _, s := range subs {
			if strings.Contains(r.Text, s) {
				return true
			}
		}
		return false
	}
}

func bodyPrefix(prefix []byte) func(r *httpResult) bool {
	return func(r *httpResult) bool {
		return len(r.Body) >= len(prefix) && string(r.Body[:len(prefix)]) == string(prefix)
	}
}

// runPathChecks runs every check in checks concurrently (bounded by the
// shared client's semaphore) against base+check.path, appending
// "<label> <verb> at <url>" findings for hits. verb lets a module phrase the
// finding the way its Python original did ("exposed at", "accessible at",
// "found at", ...).
func runPathChecks(ctx context.Context, c *probeClient, base string, checks []pathCheck, follow bool, verb string) []Finding {
	type hit struct {
		idx     int
		finding Finding
	}
	results := make(chan hit, len(checks))
	// Every check fires its own GET concurrently -- the shared client's
	// semaphore (not this loop) is what actually bounds how many are ever
	// in flight at once.
	for i, chk := range checks {
		go func(i int, chk pathCheck) {
			url := base + chk.path
			r, err := c.get(ctx, url, follow)
			if err != nil || r.StatusCode != 200 || !chk.valid(r) {
				results <- hit{idx: i}
				return
			}
			results <- hit{idx: i, finding: Finding{
				Label:      chk.label + " " + verb + " " + url,
				URL:        url,
				Method:     "GET",
				StatusCode: r.StatusCode,
			}}
		}(i, chk)
	}

	found := make([]*Finding, len(checks))
	for range checks {
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
}
