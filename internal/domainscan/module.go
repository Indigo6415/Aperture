// Package domainscan is Aperture's "master" vulnerability/misconfiguration
// scanner: unlike internal/probescan (which fires a battery of individual
// GET/POST checks at one already-known route), every module here is a
// whole external scanner pointed at an entire domain, responsible for its
// own crawling/fetching. The first module wraps retire.js
// (https://github.com/RetireJS/retire.js), which only knows how to scan a
// local directory of files, not a live site -- so this package's job is to
// go collect whatever a module needs from the target (here: every JS file
// referenced anywhere on the domain) and hand it off. Modeled closely on
// probescan's own module/run split so the two stay easy to compare, but
// kept a separate package since the two operate at different altitudes:
// probescan checks paths, domainscan runs tools.
package domainscan

import (
	"context"
	"sync"
)

// crawlMemoKey is the context key under which one scan stores its shared crawl.
type crawlMemoKey struct{}

// crawlMemo runs the domain crawl at most once per scan. Every module that
// needs the site's scripts asks for the same result, so a scan does not walk
// the target twice (retire.js and the library module both need it).
type crawlMemo struct {
	once sync.Once
	res  crawlResult
}

// withCrawlMemo returns ctx carrying a fresh crawl memo. RunScanStreaming calls
// it once per scan, before any module starts.
func withCrawlMemo(ctx context.Context) context.Context {
	return context.WithValue(ctx, crawlMemoKey{}, &crawlMemo{})
}

// sharedCrawl returns the scan's crawl of t, running it on the first call only.
// Without a memo in ctx (a module invoked directly) it crawls on each call.
func sharedCrawl(ctx context.Context, t *Target, opts Options) crawlResult {
	memo, ok := ctx.Value(crawlMemoKey{}).(*crawlMemo)
	if !ok {
		return crawlDomain(ctx, t, opts.CrawlDepth, opts.MaxPages, opts.Headers)
	}
	// once.Do blocks the other modules until the first crawl finishes, so each
	// of them then reads the same result.
	memo.once.Do(func() {
		memo.res = crawlDomain(ctx, t, opts.CrawlDepth, opts.MaxPages, opts.Headers)
	})
	return memo.res
}

// Finding is one thing a module discovered. Unlike probescan.Finding, this
// carries its own Severity -- a module here wraps a whole external tool
// (retire.js today) whose own findings span the full severity range in one
// run, rather than probescan's one-check-one-fixed-severity model.
type Finding struct {
	Label    string `json:"label"`
	URL      string `json:"url,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Evidence string `json:"evidence,omitempty"`
	Severity string `json:"severity"` // info | low | medium | high | critical
}

// ModuleResult is one module's outcome, shaped for direct rendering as a
// collapsible section in the UI -- always present in ScanResponse (possibly
// with zero findings) so the frontend can show "checked, nothing found"
// rather than the module having silently not run. Severity is the worst of
// Findings' own severities ("info" when there are none), computed once the
// module finishes rather than fixed at registration time.
type ModuleResult struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Severity string    `json:"severity"`
	Findings []Finding `json:"findings"`
	// Error is set when the module itself couldn't run at all -- most
	// commonly its external tool isn't installed -- as distinct from
	// running cleanly and finding nothing. The frontend surfaces this
	// instead of an empty findings list so "retire isn't on PATH" doesn't
	// look identical to "scanned, found no vulnerable libraries".
	Error string `json:"error,omitempty"`
}

// moduleDef is one registered module: an external tool run against the
// whole target domain. run is responsible for gathering whatever it needs
// from the target itself (a crawl, a download, ...) before invoking its
// tool -- there's no shared per-path client the way probescan's modules
// share a probeClient, since every module here works at domain scale on
// its own terms.
type moduleDef struct {
	id   string
	name string
	run  func(ctx context.Context, t *Target, opts Options) ([]Finding, error)
}

// ModuleInfo is a registered module's identity with no findings yet -- for
// listing every scanner a run will invoke before it's actually started.
type ModuleInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// severityRank/maxSeverity mirror api.severityRank/maxSeverity exactly (see
// internal/api/handlers_scans.go) -- duplicated here rather than imported
// since api already depends on this package and importing back would be a
// cycle; both copies are small enough that keeping them in step by hand is
// not a real maintenance burden.
func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func maxSeverity(a, b string) string {
	if severityRank(b) > severityRank(a) {
		return b
	}
	return a
}
