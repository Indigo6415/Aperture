package probescan

import (
	"context"
	"sort"
	"sync"

	"github.com/Indigo6415/Aperture/internal/fingerprint"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
)

// defaultConcurrency bounds how many probe requests are ever in flight at
// once across every module running in parallel -- fast (all 12 modules run
// concurrently, each firing its own paths concurrently too) while staying a
// reasonably-paced burst rather than a request flood, in the same spirit as
// the original CLI's per-request delay. Used whenever a caller's Options
// doesn't specify its own Concurrency (see RunScanStreaming).
const defaultConcurrency = 16

// Options tunes a scan beyond the fixed reachability + module checks:
// Concurrency overrides defaultConcurrency (e.g. from a launched job's
// intensity preset -- see api.handleProbeScan), and Headers are applied to
// every request the scan's shared client issues (e.g. a saved credential's
// Authorization/Cookie -- see api's credential vault). Both are optional;
// the zero value behaves exactly as a scan did before this existed.
type Options struct {
	Concurrency int
	Headers     map[string]string
	// Progress, when set, receives one check per module as it starts and
	// finishes. Nil means nobody is watching.
	Progress scanprogress.Reporter `json:"-"`
}

// registeredModules is every check category, ported one-for-one from a
// modules/*.py file in the original probe tool -- sorted by name at
// response time, same as module.py's summary().
var registeredModules = []moduleDef{
	versionControlModule,
	sensitiveFilesModule,
	directoriesModule,
	adminPanelsModule,
	devArtifactsModule,
	apiEndpointsModule,
	flaskDjangoModule,
	wordpressModule,
	miscellaneousModule,
	certificateModule,
	injectionsModule,
	secretsModule,
}

// ScanResponse is one probe scan's full result: the resolved target, a
// non-blocking reachability summary, and every module's findings (present
// even when empty, so the UI can show "checked, nothing found" instead of a
// module having silently not run).
type ScanResponse struct {
	Target  *Target        `json:"target"`
	Health  HealthSummary  `json:"health"`
	Modules []ModuleResult `json:"modules"`
}

// ModuleInfo is a registered module's identity without its findings -- for
// listing every test a scan will run (e.g. to render them before the scan
// has produced any results) without actually running anything.
type ModuleInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
}

// Modules lists every registered check module, sorted by name to match the
// order ScanResponse.Modules ends up in once a scan completes.
func Modules() []ModuleInfo {
	out := make([]ModuleInfo, len(registeredModules))
	// Strip each module down to just its identity -- no findings to copy,
	// since this lists what a scan would run rather than running one.
	for i, m := range registeredModules {
		out[i] = ModuleInfo{ID: m.id, Name: m.name, Severity: m.severity}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// withRequestHeaders gives every finding that names a URL the headers its
// request was actually sent with: the scan's own headers (a saved
// credential's Authorization/Cookie, the domain cookie) overlaid by the
// finding's headers (such as a POST's Content-Type), so the finding can be
// replayed authenticated. Findings without a URL have no request to replay.
func withRequestHeaders(findings []Finding, scanHeaders map[string]string) []Finding {
	// Visit each finding once and stamp its request headers onto it.
	for i := range findings {
		// No URL means no request to attach headers to, so leave the finding alone.
		if findings[i].URL == "" {
			continue
		}
		merged := make(map[string]string, len(scanHeaders)+len(findings[i].Headers))
		for k, v := range scanHeaders {
			merged[k] = v
		}
		// The finding's own headers win over the scan's, since they describe its exact request.
		for k, v := range findings[i].Headers {
			merged[k] = v
		}
		// An empty merge would serialize as an empty object, so keep the field nil instead.
		if len(merged) > 0 {
			findings[i].Headers = merged
		}
	}
	return findings
}

// primeCatchAll fills in the soft-404 baselines a client judges hits against:
// the random-path profile (from fingerprint.BuildProfile) and the homepage
// fingerprint used when that profile is unstable. Each step is best effort, so
// a failed probe only reduces filtering and never aborts the scan.
func primeCatchAll(ctx context.Context, c *probeClient, t *Target, headers map[string]string) {
	if profile, err := fingerprint.BuildProfile(ctx, c.follow, t.URL, headers); err == nil {
		c.profile = profile
	}
	// The homepage is fetched through the client so it shares the probe's
	// semaphore, headers, and redirect policy. Only a 200 is a usable baseline.
	if r, err := c.get(ctx, t.URL, true); err == nil && r.StatusCode == 200 {
		obs := r.observation()
		c.home = &obs
	}
}

// RunScan resolves rawTarget, runs a quick reachability check, then runs
// every registered module concurrently against it, returning one aggregated
// response. Modeled on jwtscan.RunScan's shape: an error here means the
// scan couldn't proceed at all, not that a module found nothing.
func RunScan(ctx context.Context, rawTarget string) (*ScanResponse, error) {
	return RunScanStreaming(ctx, rawTarget, Options{}, nil)
}

// RunScanStreaming behaves like RunScan, except onModule (when non-nil) is
// called once per module as it finishes -- in completion order, which isn't
// the name-sorted order the final response's Modules slice ends up in --
// letting a caller report live progress instead of waiting for every module
// to finish. opts tunes concurrency/headers -- see Options' doc comment.
func RunScanStreaming(ctx context.Context, rawTarget string, opts Options, onModule func(ModuleResult)) (*ScanResponse, error) {
	t := ResolveTarget(rawTarget)
	health := checkHealth(ctx, t)

	rep := scanprogress.Or(opts.Progress)
	checks := make([]scanprogress.Check, len(registeredModules))
	for i, m := range registeredModules {
		checks[i] = scanprogress.Check{ID: m.id, Label: m.name}
	}
	rep.Plan(checks...)

	conc := opts.Concurrency
	if conc <= 0 {
		conc = defaultConcurrency
	}
	client := newProbeClient(conc, opts.Headers)
	// Build the catch-all baseline before any module runs, so every module
	// judges its hits against the same reference. A failure here only means
	// less gets filtered as a soft-404; the scan itself still proceeds.
	primeCatchAll(ctx, client, t, opts.Headers)

	results := make([]ModuleResult, len(registeredModules))
	var wg sync.WaitGroup
	// Every module runs concurrently against the same target, each
	// reporting through onModule (if given) the moment its own findings are
	// ready rather than waiting for the slowest module to finish too.
	for i, m := range registeredModules {
		wg.Add(1)
		go func(i int, m moduleDef) {
			defer wg.Done()
			rep.Start(m.id)
			findings := withRequestHeaders(m.run(ctx, t, client), opts.Headers)
			if findings == nil {
				// A nil slice would otherwise serialize to JSON `null`
				// instead of `[]`, which the frontend treats as an
				// always-present array (see ProbeModuleResult.findings).
				findings = []Finding{}
			}
			rep.Done(m.id, len(findings), nil)
			res := ModuleResult{ID: m.id, Name: m.name, Severity: m.severity, Findings: findings}
			results[i] = res
			if onModule != nil {
				onModule(res)
			}
		}(i, m)
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })

	return &ScanResponse{Target: t, Health: health, Modules: results}, nil
}
