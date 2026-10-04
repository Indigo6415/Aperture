package domainscan

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/Indigo6415/Aperture/internal/scanprogress"
)

// registeredModules is every domain-wide scanner this master tool wraps,
// populated by each module's own init() (see retire.go) rather than listed
// here directly -- the same self-registration pattern internal/adapters
// uses (see adapters.register), so adding a new module never means editing
// this file.
var registeredModules []moduleDef

// Options tunes a scan: Headers is applied to every request the crawl
// makes (e.g. a saved credential's Authorization/Cookie), CrawlDepth/
// MaxPages bound how far the domain-wide crawl a module like retire's goes
// before handing its tool whatever it found -- see crawl.go's own defaults/
// caps, which every zero value here falls back to.
type Options struct {
	Headers    map[string]string
	CrawlDepth int
	MaxPages   int
	// Progress, when set, receives one check per module as it starts and
	// finishes. Nil means nobody is watching.
	Progress scanprogress.Reporter `json:"-"`
}

// ScanResponse is one domain scan's full result: the resolved target and
// every module's findings (present even when empty, so the UI can show
// "ran, found nothing" instead of a module having silently not run).
type ScanResponse struct {
	Target  *Target        `json:"target"`
	Modules []ModuleResult `json:"modules"`
}

// Modules lists every registered module's identity, sorted by name to match
// the order ScanResponse.Modules ends up in once a scan completes -- for
// rendering the full tool list (greyed out) before a scan has run anything,
// same role as probescan.Modules.
func Modules() []ModuleInfo {
	out := make([]ModuleInfo, len(registeredModules))
	for i, m := range registeredModules {
		out[i] = ModuleInfo{ID: m.id, Name: m.name}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// RunScanStreaming resolves rawTarget and runs every registered module
// concurrently against it, calling onModule (when non-nil) as each one
// finishes -- in completion order, not the name-sorted order the final
// response's Modules slice ends up in -- so a caller can stream live
// progress instead of waiting for every module (some of which crawl the
// whole site before their tool even starts) to finish together.
func RunScanStreaming(ctx context.Context, rawTarget string, opts Options, onModule func(ModuleResult)) (*ScanResponse, error) {
	// A blank target would otherwise start every module and have each one fail
	// on its own, which buries the real problem in a page of per-module errors.
	if strings.TrimSpace(rawTarget) == "" {
		return nil, fmt.Errorf("domainscan: target is required")
	}
	t := ResolveTarget(rawTarget)
	// One crawl per scan: every module that needs the site's scripts shares it.
	ctx = withCrawlMemo(ctx)

	rep := scanprogress.Or(opts.Progress)
	checks := make([]scanprogress.Check, len(registeredModules))
	for i, m := range registeredModules {
		checks[i] = scanprogress.Check{ID: m.id, Label: m.name}
	}
	rep.Plan(checks...)

	results := make([]ModuleResult, len(registeredModules))
	var wg sync.WaitGroup
	for i, m := range registeredModules {
		wg.Add(1)
		go func(i int, m moduleDef) {
			defer wg.Done()
			rep.Start(m.id)
			findings, err := m.run(ctx, t, opts)
			res := ModuleResult{ID: m.id, Name: m.name, Severity: "info"}
			if err != nil {
				res.Error = err.Error()
				res.Findings = []Finding{}
			} else {
				if findings == nil {
					findings = []Finding{}
				}
				res.Findings = findings
				for _, f := range findings {
					res.Severity = maxSeverity(res.Severity, f.Severity)
				}
			}
			results[i] = res
			rep.Done(m.id, len(res.Findings), err)
			if onModule != nil {
				onModule(res)
			}
		}(i, m)
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })

	return &ScanResponse{Target: t, Modules: results}, nil
}
