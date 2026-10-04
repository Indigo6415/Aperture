package apienum

import (
	"bytes"
	"context"
	"github.com/Indigo6415/Aperture/internal/netgov"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

const (
	// requestTimeout bounds a single request -- same posture as every other
	// scanner's own client (see probescan/jwtscan's identical constants):
	// a full run can mean hundreds of round-trips across spec discovery,
	// crawling, brute forcing, and per-route characterization.
	requestTimeout = 8 * time.Second
	// maxBodyBytes caps how much of a response body a check will read, so a
	// misconfigured target serving a huge body can't blow up scan memory.
	maxBodyBytes = 2 << 20 // 2 MiB
	// defaultConcurrency bounds how many requests are ever in flight at
	// once when the caller's Options doesn't specify its own -- see
	// probescan's identical default and reasoning.
	defaultConcurrency = 10
	// maxParamDiscoveryRoutes caps how many routes per run get the
	// undocumented-parameter sweep (see paramdiscovery.go). The sweep costs
	// several requests per route, so it is budgeted per run, not per route.
	maxParamDiscoveryRoutes = 25
)

// apiResult is the trimmed-down response shape every phase of a run works
// from.
type apiResult struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	Text       string
}

// apiClient is the shared transport every phase of one run issues requests
// through: a concurrency semaphore, an optional rate limiter (see
// ratelimit.go), and a baseline header set (e.g. a saved credential's
// Authorization/Cookie) applied to the "authenticated" side of every
// request unless a caller explicitly asks to skip it.
//
// Two HTTP clients are kept. Discovery (spec documents, the crawl) follows
// redirects, because the page it lands on is what it's after. Everything that
// judges a route -- characterization, brute forcing, auth probes, parameter
// discovery -- uses the no-redirect client, so a 302 to a login page is seen
// as the 302 it is rather than as whatever the login page returns.
type apiClient struct {
	http     *http.Client
	noFollow *http.Client
	sem      chan struct{}
	limiter  *rateLimiter
	headers  map[string]string
	// allowWrites is this run's Options.AllowWriteMethods. It is false unless
	// the operator opted in, and characterizeRoute reads it before sending any
	// PUT, PATCH or DELETE.
	allowWrites bool
	// profiles holds the per-directory catch-all fingerprints (see catchall.go).
	profiles *profileCache
	// sent counts every request this client has actually put on the wire,
	// so a run's Stats report real traffic rather than a derived estimate.
	sent atomic.Int64
	// paramBudget is how many more routes may get the parameter sweep.
	paramBudget atomic.Int32
}

// newClient never verifies TLS -- this tool routinely targets self-signed
// lab/CTF/internal boxes, same posture as every other scanner in Aperture.
func newClient(concurrency int, limiter *rateLimiter, headers map[string]string) *apiClient {
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}
	c := &apiClient{
		http:     netgov.NewClient(requestTimeout, true),
		noFollow: netgov.NewClient(requestTimeout, false),
		sem:      make(chan struct{}, concurrency),
		limiter:  limiter,
		headers:  headers,
		profiles: newProfileCache(),
	}
	c.paramBudget.Store(maxParamDiscoveryRoutes)
	return c
}

// do issues method against target through the redirect-following client,
// honoring this client's rate limit and concurrency cap. skipBaseline omits
// the client's own baseline headers entirely -- used by the unauthenticated
// half of an auth probe, and by every crawl/brute-force/mining request, none
// of which should carry a supplied credential. extraHeaders (applied after
// the baseline, so it can override individual baseline entries) is for a
// request that needs something beyond the baseline, e.g. a specific
// Content-Type.
func (c *apiClient) do(ctx context.Context, method, target string, extraHeaders map[string]string, skipBaseline bool, body []byte) (*apiResult, error) {
	return c.send(ctx, c.http, method, target, extraHeaders, skipBaseline, body)
}

// doNoFollow is do through the client that never follows redirects, so the
// response returned is the one the target sent for this exact request.
func (c *apiClient) doNoFollow(ctx context.Context, method, target string, extraHeaders map[string]string, skipBaseline bool, body []byte) (*apiResult, error) {
	return c.send(ctx, c.noFollow, method, target, extraHeaders, skipBaseline, body)
}

// send is the one place a request leaves this package: it takes a slot from
// the rate limiter and the concurrency cap, builds the request with the
// baseline/extra headers, reads a capped body, and counts it.
func (c *apiClient) send(ctx context.Context, httpc *http.Client, method, target string, extraHeaders map[string]string, skipBaseline bool, body []byte) (*apiResult, error) {
	if err := c.limiter.wait(ctx); err != nil {
		return nil, err
	}
	select {
	case c.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-c.sem }()

	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Aperture APIEnum)")
	if !skipBaseline {
		for k, v := range c.headers {
			req.Header.Set(k, v)
		}
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	c.sent.Add(1)
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}
	return &apiResult{StatusCode: resp.StatusCode, Header: resp.Header, Body: b, Text: string(b)}, nil
}

// get is the common case: GET through the redirect-following client, baseline
// headers included, no body.
func (c *apiClient) get(ctx context.Context, target string) (*apiResult, error) {
	return c.do(ctx, http.MethodGet, target, nil, false, nil)
}

// getNoFollow is get through the no-redirect client -- the one brute forcing
// uses, so a redirect answer is recorded as itself.
func (c *apiClient) getNoFollow(ctx context.Context, target string) (*apiResult, error) {
	return c.doNoFollow(ctx, http.MethodGet, target, nil, false, nil)
}

// takeParamBudget spends one of the run's parameter-sweep routes, reporting
// false once the budget is gone.
func (c *apiClient) takeParamBudget() bool {
	return c.paramBudget.Add(-1) >= 0
}

// hasBaseline reports whether this run was given a credential to test
// with -- callers use this to decide whether an authenticated-side auth
// probe is even possible.
func (c *apiClient) hasBaseline() bool { return len(c.headers) > 0 }
