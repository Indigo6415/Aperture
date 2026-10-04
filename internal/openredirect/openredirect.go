// Package openredirect tests an endpoint for unvalidated-redirect
// vulnerabilities: anywhere the app takes a "where to send the user next"
// value -- a query parameter (a post-login destination, a "continue" link,
// an SSO callback), a path segment ("/go/<destination>"), the Referer
// header ("back where you came from"), or a host the app builds its own
// absolute URLs from (the Host header, X-Forwarded-Host, Forwarded) -- and
// uses it to build a redirect without checking it stays on-site lets an
// attacker send a link that *looks* like it points at the real target but
// bounces the victim to an attacker-hosted page. That's useful for
// phishing, and for laundering an OAuth/SSO token through a trusted
// domain's own redirect.
//
// Every probe is confirmed the same way: its redirect (or client-side
// redirect) has to actually reach a live callback listener under that
// probe's own identifier. A response that merely *mentions* the callback is
// never a finding on its own. See checks.go for the vector families and how
// each one is attributed, and openRedirectModules there for the full list.
// Shaped like internal/pwreset/internal/corsscan: a baseline plus a battery
// of check modules, each with fixed severity and findings present even when
// empty.
package openredirect

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"sync/atomic"
	"time"

	"github.com/Indigo6415/Aperture/internal/collaborator"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
)

// Finding is one confirmed redirect. Label names the vector, Detail
// explains what was sent and what the callback saw, and Request is the
// exact request that triggered it.
type Finding struct {
	Label      string `json:"label"`
	Detail     string `json:"detail,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
	Method     string `json:"method,omitempty"`
	StatusCode int    `json:"statusCode,omitempty"`
	// Request is the exact request this finding's check sent (see
	// CapturedRequest in client.go) -- lets the frontend's "Send to Tester"
	// action replay precisely what triggered the finding.
	Request *CapturedRequest `json:"request,omitempty"`
	// Chain is every request made from the probe to the callback, in order:
	// the probe itself, each redirect followed along the way, and the
	// confirming request to the callback address. See ChainHop.
	Chain []ChainHop `json:"chain,omitempty"`
}

// ChainHop is one request on the path from a probe to the callback. Kind is
// "probe" (the payload request), "redirect" (a followed Location hop short of
// the callback), or "callback" (the request that confirmed the hit). OffsetMs
// is when the request went out, measured from the probe's first request, and
// DurationMs is how long it took on the wire -- a slot wait behind other
// probes is excluded, so a slow number reflects the target, not the scanner's
// own concurrency limit.
type ChainHop struct {
	Step       int               `json:"step"`
	Kind       string            `json:"kind"`
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	StatusCode int               `json:"statusCode,omitempty"`
	Location   string            `json:"location,omitempty"`
	OffsetMs   float64           `json:"offsetMs"`
	DurationMs float64           `json:"durationMs"`
	Headers    map[string]string `json:"headers,omitempty"`
	// Error is set when the request failed (timeout, connection refused, ...);
	// such a hop has no status code.
	Error string `json:"error,omitempty"`
	// started is when the request actually went out, kept so finalizeChain can
	// compute OffsetMs from it. Not part of the JSON shape.
	started time.Time
}

// ModuleResult is one vector family's outcome for this run.
type ModuleResult struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Severity string    `json:"severity"`
	Findings []Finding `json:"findings"`
}

// Request is one run's configuration.
type Request struct {
	// URL is the endpoint under test. Any query parameters it already
	// carries are tested too (in addition to commonRedirectParams and
	// Params below), since the operator pointing this at
	// "https://target/login?returnTo=/dashboard" almost certainly wants
	// returnTo itself tried even if it weren't already on the common list.
	URL string `json:"url"`
	// Params are extra parameter names to test beyond commonRedirectParams
	// and whatever URL's own query string already carries.
	Params  []string          `json:"params,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	// CallbackBase is a live callback server's bare "host[:port]/path" (no
	// scheme, no trailing slash -- e.g. "aperture.example.com/collab/deadbeef0123"
	// or "webhook.site/9f2e1234-…"), built by the HTTP handler either from an
	// operator-picked Callback field in its own request body, or -- when the
	// operator didn't pick one -- a fresh token minted against Aperture's own
	// collaborator registry by default (see internal/collaborator.Ref and
	// handlers_openredirect.go). Required: a probe only ever reports a
	// Finding once the redirect is confirmed to have reached this host, never
	// from response heuristics alone -- leaving it empty gets an explanatory
	// notice instead of a scan.
	CallbackBase string `json:"-"`
	// CallbackPoll is how the run confirms candidate hits before ever
	// reporting them as Findings -- see CallbackPollConfig and Run.
	CallbackPoll CallbackPollConfig `json:"-"`
	// FollowRedirects makes confirmation walk the full Location chain (up to
	// maxRedirectHops) looking for the callback, so a redirect that reaches it
	// through an intermediate page still counts. Off inspects only the first
	// hop. The handler defaults this to on.
	FollowRedirects bool `json:"-"`
	// Progress, when set, receives one check per module. Nil means nobody is
	// watching.
	Progress scanprogress.Reporter `json:"-"`
}

// CallbackPollConfig carries what's needed to poll an operator-picked
// callback server for confirmed interactions, once the probes (and any
// confirmation requests) have had a chance to land -- built by
// handlers_openredirect.go from the same internal/collaborator.Ref that
// produced Request.CallbackBase.
type CallbackPollConfig struct {
	Registry *collaborator.Registry
	Token    string
	// Provider is "aperture" (poll via Registry) or "webhooksite" (poll via
	// collaborator.PollWebhookSite).
	Provider string
}

// Baseline is the unmodified endpoint's response, so the operator can see
// what a probe is being compared against.
type Baseline struct {
	URL        string `json:"url"`
	StatusCode int    `json:"statusCode"`
	Location   string `json:"location,omitempty"`
	// Error is set when every baseline attempt failed. The run still goes ahead
	// with its probes, and StatusCode and Location are left empty.
	Error string `json:"error,omitempty"`
}

// Result is one full run's outcome.
type Result struct {
	Baseline Baseline       `json:"baseline"`
	Modules  []ModuleResult `json:"modules"`
	// ParamsTested is every query parameter name actually tried -- lets the
	// operator see what was covered without needing to know
	// commonRedirectParams by heart.
	ParamsTested []string `json:"paramsTested"`
	// ProbesSent is how many distinct requests the run fired across every
	// module (baseline excluded), so coverage is visible at a glance.
	ProbesSent int `json:"probesSent"`
	// Requests is every request the run sent (baseline attempts, probes and
	// callback confirmations), and TimedOut is how many of them ran out of their
	// time budget. Together they show how responsive the host was.
	Requests int `json:"requests"`
	TimedOut int `json:"timedOut"`
	// FollowRedirects reports whether the run walked redirect chains, so a
	// result can be read knowing how deep confirmation looked.
	FollowRedirects bool `json:"followRedirects"`
}

// maxConcurrentRequests bounds how many requests this scanner has in
// flight at once, across every module and probe combined -- hundreds of
// probes would otherwise all fire at essentially the same instant. Same
// reasoning as internal/ssrf.maxConcurrentRequests: needlessly aggressive
// against the target, and prone to the target itself throttling/erroring
// under the burst in a way that reads as "nothing found" rather than any
// real signal.
const maxConcurrentRequests = 16

// moduleConcurrency is how many modules run at once. Probes from every module
// still share maxConcurrentRequests and the scan's rate limit, so this only
// sets the order modules start and finish in: a small number keeps the rest
// visibly queued while the first ones run, and the probe pipe stays full.
const moduleConcurrency = 2

// confirmModule waits for the callback listener to record hits for cands and
// returns one Finding per candidate whose own identifier was seen. A module
// with no candidates skips the wait entirely.
func confirmModule(ctx context.Context, rep scanprogress.Reporter, cb CallbackPollConfig, cands []candidate) []Finding {
	findings := []Finding{}
	if len(cands) == 0 {
		return findings
	}
	// Identifiers this module's own candidates were sent with. Hits recorded
	// for other modules are ignored here, since those modules confirm their own.
	mine := make(map[string]bool, len(cands))
	for _, c := range cands {
		mine[c.spec.identifier] = true
	}
	rep.Phase("Waiting for callbacks to confirm redirects")
	polled, _ := collaborator.WaitForCallbacks(ctx, func(context.Context) ([]collaborator.Interaction, error) {
		return pollCallback(cb), nil
	}, collaborator.DefaultPollInterval, collaborator.DefaultQuietPeriod, collaborator.DefaultMaxWait)
	byIdentifier := map[string][]collaborator.Interaction{}
	for _, h := range polled {
		if mine[h.Identifier] {
			byIdentifier[h.Identifier] = append(byIdentifier[h.Identifier], h)
		}
	}
	// Only a candidate whose own identifier was actually polled counts.
	for _, c := range cands {
		hits := byIdentifier[c.spec.identifier]
		if len(hits) == 0 {
			continue
		}
		findings = append(findings, findingFor(c, hits))
	}
	return findings
}

// Run resolves req.URL, takes a plain baseline request (no payload), then
// runs every module concurrently, confirms candidate hits against the
// callback listener, and assembles one ModuleResult per vector family.
func Run(ctx context.Context, req Request) (*Result, error) {
	rep := scanprogress.Or(req.Progress)

	target, err := parseTarget(req.URL)
	if err != nil {
		return nil, err
	}

	// The baseline is informational only: probes and callback confirmation do
	// not depend on it, so a failure is recorded on the result and the run
	// carries on rather than aborting.
	stats := &runStats{}
	baseline := Baseline{URL: req.URL}
	baselineRes, err := baselineRequest(ctx, withParam(target, "aperture-openredirect-baseline", "1"), req.Headers, stats)
	if err != nil {
		baseline.Error = fmt.Sprintf("baseline request failed, continuing without it: %v", err)
	} else {
		baseline.StatusCode = baselineRes.StatusCode
		baseline.Location = baselineRes.Location
	}

	params := candidateParams(target, req.Params)
	origin := target.Scheme + "://" + target.Host
	deps := runDeps{target: target, req: req, params: params, origin: origin, sem: make(chan struct{}, maxConcurrentRequests), nonce: newRunNonce(), stats: stats}

	mods := openRedirectModules
	results := make([]ModuleResult, len(mods))
	// Without a callback server nothing can be confirmed, so every module
	// reports the same notice and no probes are sent.
	if req.CallbackBase == "" {
		// One progress check per module, each reported finished straight away.
		for i, m := range mods {
			rep.Plan(scanprogress.Check{ID: m.id, Label: m.name})
			rep.Start(m.id)
			rep.Done(m.id, 0, nil)
			results[i] = ModuleResult{ID: m.id, Name: m.name, Severity: m.severity, Findings: []Finding{{
				Label:  "Callback listener not configured",
				Detail: "This module only reports a redirect once following it actually reaches a live callback server -- a response that merely contains an attacker-controlled host in its Location header or body isn't enough on its own, since many apps echo an unrecognized value back without ever redirecting to it. No callback server was configured for this run.",
			}}}
		}
		sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })
		return &Result{Baseline: baseline, Modules: results, ParamsTested: params, FollowRedirects: req.FollowRedirects, Requests: int(stats.requests.Load()), TimedOut: int(stats.timedOut.Load())}, nil
	}

	// sent is shared by every module goroutine, so it has to be atomic.
	var sent atomic.Int64
	// Every module is its own progress check. Each plans them all up front and
	// only marks a module running once it holds one of moduleConcurrency slots,
	// so modules still waiting read as queued (grey) instead of all turning
	// orange at once. A module is reported done as soon as its own probes and
	// callback confirmation finish, rather than when the whole run ends.
	idx := make([]int, len(mods))
	for i := range idx {
		idx[i] = i
	}
	scanprogress.Each(rep, moduleConcurrency, idx, func(i int) scanprogress.Check {
		return scanprogress.Check{ID: mods[i].id, Label: mods[i].name}
	}, func(i int) (int, error) {
		cands := runModule(ctx, deps, mods[i], &sent)
		findings := confirmModule(ctx, rep, req.CallbackPoll, cands)
		results[i] = ModuleResult{ID: mods[i].id, Name: mods[i].name, Severity: mods[i].severity, Findings: findings}
		return len(findings), nil
	})

	sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })
	return &Result{
		Baseline:        baseline,
		Modules:         results,
		ParamsTested:    params,
		ProbesSent:      int(sent.Load()),
		FollowRedirects: req.FollowRedirects,
		Requests:        int(stats.requests.Load()),
		TimedOut:        int(stats.timedOut.Load()),
	}, nil
}

// newRunNonce returns a fresh random suffix for one run's identifiers. Eight
// random bytes is far more than a single run needs to stay distinct from every
// other run sharing a callback token.
func newRunNonce() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		panic("openredirect: system entropy source failed: " + err.Error())
	}
	return hex.EncodeToString(buf)
}

// candidateParams unions commonRedirectParams, target's own existing query
// keys, and whatever the operator supplied in extra -- deduplicated,
// case-sensitive (query param names are), sorted for a stable/readable
// ParamsTested list.
func candidateParams(target *url.URL, extra []string) []string {
	set := map[string]bool{}
	for _, p := range commonRedirectParams {
		set[p] = true
	}
	for k := range target.Query() {
		set[k] = true
	}
	for _, p := range extra {
		if p != "" {
			set[p] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
