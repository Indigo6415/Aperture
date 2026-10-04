package probescan

import (
	"context"
	"strconv"
	"strings"

	"github.com/Indigo6415/Aperture/internal/fingerprint"
)

// Confidence levels for a Finding. "confirmed" means the response was parsed
// as the file it claims to be; "likely" means it passed a plain-text or
// content-presence check only; "heuristic" is reserved for findings that rest
// on a guess (for example a bare directory name).
const (
	ConfidenceConfirmed = "confirmed"
	ConfidenceLikely    = "likely"
	ConfidenceHeuristic = "heuristic"
)

// Finding is one thing a module discovered -- a path that exists, a
// misconfiguration, an exposed file. Label/URL/Detail are the summary a
// finding list renders inline; Method/StatusCode/Evidence are the "how was
// this found" specifics (the request that triggered it, and the matched
// content, redacted where it could be a credential) shown when a finding is
// expanded for more detail. Confidence says how strongly the response
// supports the claim.
type Finding struct {
	Label      string `json:"label"`
	URL        string `json:"url,omitempty"`
	Detail     string `json:"detail,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
	Method     string `json:"method,omitempty"`
	StatusCode int    `json:"statusCode,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	// Headers and Body are the request headers and body that triggered the
	// finding, set only by checks that send one (a POST). GET checks leave both empty.
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
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
// the Python modules inline as lambdas. These are substring checks and are
// only appropriate where the content itself is distinctive; file checks
// should prefer the structural validators in validate.go. ---

func nonEmptyBody(r *httpResult) bool { return len(r.Text) > 0 }

// containsAny passes when any substring appears, compared case-insensitively.
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

// containsAll passes only when every substring appears, compared
// case-insensitively.
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

// bodyPrefix passes when the raw body starts with prefix (a magic number).
func bodyPrefix(prefix []byte) func(r *httpResult) bool {
	return func(r *httpResult) bool {
		return len(r.Body) >= len(prefix) && string(r.Body[:len(prefix)]) == string(prefix)
	}
}

// observation summarizes r for comparison with the host's catch-all profile.
func (r *httpResult) observation() fingerprint.Observation {
	return fingerprint.Observe(r.StatusCode, r.Header.Get("Content-Type"), r.Body)
}

// isCatchAll reports whether r is the host's soft-404 page. A scan without a
// profile (the probe that builds it failed) never treats anything as one.
func (c *probeClient) isCatchAll(r *httpResult) bool {
	obs := r.observation()
	if c.profile.Matches(obs) {
		return true
	}
	// Without a stable profile the random-path samples disagree, so filtering
	// by them is unsafe. The homepage is then the only baseline left, and a 200
	// identical to it is treated as the front end answering for any path. A
	// stable profile is authoritative, so it is never overridden here.
	// A nil profile (the probe that builds it failed) counts as unstable here.
	unstable := c.profile == nil || !c.profile.Stable
	if c.home != nil && unstable && obs.Status == 200 && fingerprint.Similar(*c.home, obs) {
		return true
	}
	return false
}

// runPathChecks runs every check in checks concurrently (bounded by the
// shared client's semaphore) against base+check.path, appending
// "<label> <verb> at <url>" findings for hits. A response that matches the
// host's catch-all profile is never a hit, whatever its body says. verb lets
// a module phrase the finding the way its Python original did ("exposed at",
// "accessible at", "found at", ...).
func runPathChecks(ctx context.Context, c *probeClient, base string, checks []pathCheck, follow bool, verb string) []Finding {
	return runChecks(ctx, c, base, checks, follow, verb, "", false)
}

// runFileChecks is the strict path for file-disclosure checks. On top of
// runPathChecks' catch-all gate it rejects any HTML response, since a
// configuration, key, or dump is never legitimately served as a web page, and
// it records confidence on each finding. Pass ConfidenceConfirmed for lists
// of structural validators and ConfidenceLikely for plain-text-only lists.
func runFileChecks(ctx context.Context, c *probeClient, base string, checks []pathCheck, confidence string) []Finding {
	return runChecks(ctx, c, base, checks, false, "exposed at", confidence, true)
}

// runChecks is the shared engine behind runPathChecks and runFileChecks.
// strictFile adds the non-HTML rule and fills Confidence and Evidence.
func runChecks(ctx context.Context, c *probeClient, base string, checks []pathCheck, follow bool, verb, confidence string, strictFile bool) []Finding {
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
			if err != nil || r.StatusCode != 200 || c.isCatchAll(r) || !chk.valid(r) {
				results <- hit{idx: i}
				return
			}
			if strictFile && looksHTML(r) {
				results <- hit{idx: i}
				return
			}
			f := Finding{
				Label:      chk.label + " " + verb + " " + url,
				URL:        url,
				Method:     "GET",
				StatusCode: r.StatusCode,
			}
			if strictFile {
				f.Confidence = confidence
				f.Evidence = evidenceFor(r)
			}
			results <- hit{idx: i, finding: f}
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

// evidenceFor describes a file hit for the finding's evidence field. Text
// files are shown with secret-looking values masked; binary files are
// summarized by size, since their bytes are not useful inline.
func evidenceFor(r *httpResult) string {
	if validPlainText(r) {
		return maskEvidence(r.Text)
	}
	return "binary content, " + strconv.Itoa(len(r.Body)) + " bytes"
}
