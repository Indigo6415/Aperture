// Package corsscan tests an endpoint's Cross-Origin Resource Sharing
// response headers for the misconfigurations that let a malicious web page
// read another origin's authenticated responses -- CORS exists precisely to
// *prevent* that, so a server that reflects an arbitrary Origin back in
// Access-Control-Allow-Origin (optionally paired with
// Access-Control-Allow-Credentials: true) has effectively turned it off for
// anyone who asks. See PortSwigger's "CORS vulnerabilities" methodology,
// which this scanner's module list follows fairly closely: arbitrary-origin
// reflection, the `null` origin trick (achievable via a sandboxed iframe or
// a `data:` URI, both of which send `Origin: null`), naive substring/prefix/
// suffix trust of a related-looking domain, protocol downgrade, and an
// invalid-but-still-seen `*` + credentials combination.
//
// Shaped like internal/pwreset: a fixed baseline request plus a battery of
// check modules, each with its own severity and a list of findings, present
// even when empty (see Result).
package corsscan

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"sync"

	"github.com/Indigo6415/Aperture/internal/scanprogress"
)

// Finding/ModuleResult mirror pwreset.Finding/pwreset.ModuleResult field for
// field -- see that package's own doc comment for why each scanner keeps its
// own copy of this shape rather than sharing one type.
type Finding struct {
	Label      string `json:"label"`
	Detail     string `json:"detail,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
	Method     string `json:"method,omitempty"`
	StatusCode int    `json:"statusCode,omitempty"`
	// Request is the exact request this finding's check sent (see
	// CapturedRequest in client.go) -- lets the frontend's "Send to Tester"
	// action replay precisely what triggered the finding, not just the bare
	// target URL.
	Request *CapturedRequest `json:"request,omitempty"`
	// Confidence is "confirmed" for every CORS finding: each is read from a response
	// header the target actually sent. Exploitability is a separate question and
	// is explained in Detail.
	Confidence string `json:"confidence,omitempty"`
	// Exploitation says how an attacker would turn this finding into a real
	// attack. It is the per-finding text where one is set, and otherwise the
	// owning module's default (see runWithClient). Kept apart from Detail,
	// which explains what the header shows.
	Exploitation string `json:"exploitation,omitempty"`
}

type ModuleResult struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Severity string    `json:"severity"`
	Findings []Finding `json:"findings"`
}

// Request is one run's configuration.
type Request struct {
	// URL is the endpoint under test -- ideally one that actually varies its
	// response based on Origin (an API/XHR endpoint, not a plain static
	// page), though every check here still runs regardless.
	URL string `json:"url"`
	// Method is the HTTP method the non-preflight checks use; defaults to
	// GET.
	Method  string            `json:"method,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	// Progress, when set, receives one check per module. Nil means nobody is
	// watching.
	Progress scanprogress.Reporter `json:"-"`
}

// Baseline is a plain request with no Origin header at all -- what the
// endpoint does by default, absent any cross-origin request in play.
type Baseline struct {
	URL                string `json:"url"`
	Method             string `json:"method"`
	StatusCode         int    `json:"statusCode"`
	AllowOriginPresent bool   `json:"allowOriginPresent"`
	AllowOrigin        string `json:"allowOrigin,omitempty"`
}

type Result struct {
	Baseline Baseline       `json:"baseline"`
	Modules  []ModuleResult `json:"modules"`
}

type moduleDef struct {
	id, name, severity string
	// exploitation is the module's default attack write-up, applied to any of
	// its findings that did not set their own.
	exploitation string
	run          func(ctx context.Context, deps runDeps) []Finding
}

// runDeps is what every module needs -- bundled into one struct (rather than
// pwreset's longer positional-argument list) since every module here needs
// the same inputs.
type runDeps struct {
	target *url.URL
	req    Request
	// client is the HTTP client every module sends through -- the shared netgov
	// client in production (see newClient), injectable only by tests.
	client *http.Client
	// attacker is the response to the plain (non-preflight) request sent with
	// Origin: attackerOrigin. It is fetched once in runWithClient and shared by
	// every module that reads it, so the same request is not sent several times.
	// Nil when that request failed.
	attacker *corsResult
}

// registeredModules lists every module in the order they are reported. The
// order does not affect results, since each module's findings are independent.
func registeredModules() []moduleDef {
	return []moduleDef{
		reflectedOriginModule,
		credentialedReflectionModule,
		varyOriginModule,
		nullOriginModule,
		wildcardWithCredentialsModule,
		wildcardOriginModule,
		thirdPartyOriginModule,
		insecureProtocolModule,
		relatedDomainTrustModule,
		parserBypassModule,
		preflightPermissivenessModule,
	}
}

// Run resolves req.URL, takes an Origin-less baseline request, then runs
// every check module concurrently against the same endpoint.
func Run(ctx context.Context, req Request) (*Result, error) {
	return runWithClient(ctx, req, newClient())
}

// runWithClient is Run with the HTTP client supplied by the caller. Run passes
// the shared netgov client; tests pass a client that points at an httptest
// server.
func runWithClient(ctx context.Context, req Request, client *http.Client) (*Result, error) {
	rep := scanprogress.Or(req.Progress)

	target, err := parseTarget(req.URL)
	if err != nil {
		return nil, err
	}

	baselineRes, err := doRequest(ctx, client, target, req.method(), "", false, "", "", req.Headers)
	if err != nil {
		return nil, fmt.Errorf("corsscan: baseline request failed: %w", err)
	}
	baseline := Baseline{
		URL: req.URL, Method: req.method(), StatusCode: baselineRes.StatusCode,
		AllowOriginPresent: baselineRes.AllowOriginPresent, AllowOrigin: baselineRes.AllowOrigin,
	}

	// The attacker-origin response is shared by several modules; a failure here
	// just leaves those modules with nothing to report, as before.
	attackerRes, err := doRequest(ctx, client, target, req.method(), attackerOrigin, false, "", "", req.Headers)
	if err != nil {
		attackerRes = nil
	}

	deps := runDeps{target: target, req: req, client: client, attacker: attackerRes}
	mods := registeredModules()
	// One progress check per module -- each module is a whole battery of its
	// own probes, so the module is the unit a user can follow.
	checks := make([]scanprogress.Check, len(mods))
	for i, m := range mods {
		checks[i] = scanprogress.Check{ID: m.id, Label: m.name}
	}
	rep.Plan(checks...)
	results := make([]ModuleResult, len(mods))
	var wg sync.WaitGroup
	// Every module fires its own independent batch of requests -- run
	// concurrently, same reasoning as pwreset.Run's non-enumeration modules
	// (nothing here depends on another module's timing the way pwreset's
	// enumeration check does).
	for i, m := range mods {
		wg.Add(1)
		go func(i int, m moduleDef) {
			defer wg.Done()
			rep.Start(m.id)
			findings := m.run(ctx, deps)
			rep.Done(m.id, len(findings), nil)
			// Every CORS finding is read from a header the target sent, so its
			// evidence is confirmed even when its exploitability is not. A
			// finding that set no exploitation of its own inherits the module's.
			for j := range findings {
				if findings[j].Confidence == "" {
					findings[j].Confidence = ConfidenceConfirmed
				}
				if findings[j].Exploitation == "" {
					findings[j].Exploitation = m.exploitation
				}
			}
			if findings == nil {
				findings = []Finding{}
			}
			results[i] = ModuleResult{ID: m.id, Name: m.name, Severity: m.severity, Findings: findings}
		}(i, m)
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })
	return &Result{Baseline: baseline, Modules: results}, nil
}

// ConfidenceConfirmed marks a finding whose evidence is a response header the
// target actually sent.
const ConfidenceConfirmed = "confirmed"
