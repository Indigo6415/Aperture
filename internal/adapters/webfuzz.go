package adapters

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/Indigo6415/Aperture/internal/netgov"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/Indigo6415/Aperture/internal/fingerprint"
	"github.com/Indigo6415/Aperture/internal/model"
	"github.com/Indigo6415/Aperture/internal/wordlists"
)

func init() {
	register(&WebFuzzAdapter{})
}

// WebFuzzConfig is the node-configurable shape for a webfuzz run. webfuzz is
// Aperture's own fuzzer and is selectable as a job tool (ToolWebFuzz). FUZZ
// must appear either in URL (content and subdomain discovery) or in a header
// value (virtual-host discovery), the same convention ffuf uses.
type WebFuzzConfig struct {
	URL           string            `json:"url"`
	Wordlist      string            `json:"wordlist"`
	Extensions    []string          `json:"extensions,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	Method        string            `json:"method,omitempty"`
	Threads       int               `json:"threads,omitempty"`
	Timeout       int               `json:"timeoutSeconds,omitempty"`
	RateLimit     int               `json:"rateLimit,omitempty"` // requests/sec across the whole run; 0 = unlimited
	AutoCalibrate bool              `json:"autoCalibrate,omitempty"`
	// Recursive enables feroxbuster-style recursion: a 2xx/3xx hit becomes a
	// new base path re-fuzzed with the same wordlist/extensions, up to
	// MaxDepth. Only meaningful when FUZZ is a path segment in URL (content
	// discovery) -- left false for subdomain/vhost bruteforce, where FUZZ
	// names the whole host and "recursing into a hit" makes no sense.
	Recursive bool `json:"recursive,omitempty"`
	MaxDepth  int  `json:"maxDepth,omitempty"` // 0 => defaultWebFuzzMaxDepth
}

// fuzzHeader returns the name of the first header whose value contains the
// FUZZ keyword, and false if none does (i.e. FUZZ lives in the URL
// instead) -- same convention adapters.FFufConfig.fuzzHeader used.
func (c WebFuzzConfig) fuzzHeader() (string, bool) {
	for k, v := range c.Headers {
		if strings.Contains(v, "FUZZ") {
			return k, true
		}
	}
	return "", false
}

const (
	defaultWebFuzzThreads    = 20
	defaultWebFuzzTimeout    = 10 * time.Second
	defaultWebFuzzMaxDepth   = 3
	webFuzzProgressEvery     = 25
	webFuzzCalibrationProbes = 3
	// maxFuzzBodyPeek caps how much of each response body is read for
	// size/word/line accounting -- generous for real content, but keeps a
	// single huge/streaming response from blowing up memory or dominating
	// run time across thousands of requests.
	maxFuzzBodyPeek = 2 * 1024 * 1024
)

type WebFuzzAdapter struct{}

func (a *WebFuzzAdapter) Name() string { return "webfuzz" }

func (a *WebFuzzAdapter) Run(ctx context.Context, config json.RawMessage, meta RunMeta, emit Emit, progress Progress) error {
	var cfg WebFuzzConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return &ErrConfig{Adapter: a.Name(), Err: err}
	}
	fuzzHeaderName, headerHasFuzz := cfg.fuzzHeader()
	if cfg.URL == "" || (!strings.Contains(cfg.URL, "FUZZ") && !headerHasFuzz) {
		return &ErrConfig{Adapter: a.Name(), Err: fmt.Errorf("FUZZ must appear in url or in a header value")}
	}
	if cfg.Wordlist == "" {
		return &ErrConfig{Adapter: a.Name(), Err: fmt.Errorf("wordlist is required")}
	}
	// Refuse a wordlist/extensions combination too large to plan for
	// upfront -- see checkFuzzRequestCount in adapter.go. Recursion can only
	// make the real total larger than this base-level estimate, so this
	// still catches it; the recursion cap below (maxFuzzRequests again)
	// bounds the rest.
	if err := checkFuzzRequestCount(a.Name(), cfg.Wordlist, cfg.Extensions); err != nil {
		return err
	}

	wordlistLines, err := wordlists.CountLines(cfg.Wordlist)
	if err != nil {
		return fmt.Errorf("webfuzz: count wordlist lines: %w", err)
	}
	if wordlistLines == 0 {
		return fmt.Errorf("webfuzz: wordlist is empty")
	}

	threads := cfg.Threads
	if threads <= 0 {
		threads = defaultWebFuzzThreads
	}
	timeout := defaultWebFuzzTimeout
	if cfg.Timeout > 0 {
		timeout = time.Duration(cfg.Timeout) * time.Second
	}
	maxDepth := cfg.MaxDepth
	if maxDepth <= 0 {
		maxDepth = defaultWebFuzzMaxDepth
	}
	method := cfg.Method
	if method == "" {
		method = "GET"
	}

	var limiter *webFuzzLimiter
	if cfg.RateLimit > 0 {
		limiter = newWebFuzzLimiter(cfg.RateLimit)
		defer limiter.stop()
	}

	run := &webFuzzRun{
		cfg:      cfg,
		meta:     meta,
		emit:     emit,
		progress: progress,
		// Per-request timeouts come from the job context (see doRequest), so
		// the client itself has none. Redirects are not followed, matching
		// ffuf and feroxbuster's default of reporting a redirect's own status.
		client:         netgov.NewClient(0, false),
		threads:        threads,
		timeout:        timeout,
		method:         method,
		limiter:        limiter,
		fuzzHeaderName: fuzzHeaderName,
		headerHasFuzz:  headerHasFuzz,
		wordlistLines:  wordlistLines,
		extCount:       1 + len(cfg.Extensions),
		visited:        map[string]bool{},
	}

	if progress != nil {
		progress(0, 0)
	}

	// Runs one level (the base wordlist sweep, then -- if Recursive -- each
	// subsequent level's newly-discovered directories) at a time rather than
	// recursing opportunistically as hits stream in. That makes both the
	// worker lifecycle (every goroutine for a level exits before the next
	// one starts) and the progress total (known exactly before a level
	// starts, never a guess) trivially correct, at the cost of recursion
	// not starting until the level that found it has fully finished.
	bases := []string{cfg.URL}
	for depth := 0; depth < maxDepth && len(bases) > 0; depth++ {
		levelJobs := len(bases) * wordlistLines * run.extCount
		if run.total+levelJobs > maxFuzzRequests {
			break // recursion cap -- see maxFuzzRequests in adapter.go
		}
		run.total += levelJobs
		run.reportProgress()

		next, err := run.runLevel(ctx, bases)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("webfuzz: %w", err)
		}
		if !cfg.Recursive {
			break
		}
		bases = next
	}

	// Surface request failures in the server log. A run where most requests
	// failed usually means the target is blocking or unreachable, which the
	// operator needs to know even though no finding was produced.
	if run.failed > 0 {
		log.Printf("webfuzz: %d of %d requests failed (timeouts, resets, or refused connections) for %s", run.failed, run.done, cfg.URL)
	}
	return nil
}

// webFuzzRun holds the state and configuration shared across every level of
// one adapter Run -- done/total/visited are only ever touched by the
// sequential level loop in Run and, within a level, the single
// results-consuming goroutine runLevel starts (see runLevel), so none of it
// needs its own lock.
type webFuzzRun struct {
	cfg            WebFuzzConfig
	meta           RunMeta
	emit           Emit
	progress       Progress
	client         *http.Client
	threads        int
	timeout        time.Duration
	method         string
	limiter        *webFuzzLimiter
	fuzzHeaderName string
	headerHasFuzz  bool
	wordlistLines  int
	extCount       int // 1 (bare word) + len(Extensions)

	done    int
	total   int
	visited map[string]bool // recursion dedup, across every level of this run
	// failed counts requests that errored (timeouts, resets, refused). They are
	// reported once at the end of the run instead of silently dropped.
	failed int
}

func (f *webFuzzRun) reportProgress() {
	if f.progress != nil {
		f.progress(f.done, f.total)
	}
}

type webfuzzJob struct {
	base string // URL template containing FUZZ (URL-fuzz mode) or the constant target URL (header-fuzz mode)
	word string // already has any extension appended
}

type webfuzzResult struct {
	job           webfuzzJob
	statusCode    int
	contentLength int
	words         int
	lines         int
	contentType   string
	redirectLoc   string
	headers       map[string]string
	// obs is the body fingerprint used for catch-all comparison.
	obs fingerprint.Observation
	err error // request-level failure (timeout, connection refused, ...) -- counted toward done, never emitted
}

// runLevel runs the full wordlist x extensions sweep against every base in
// bases, wiring a bounded worker pool (producer -> jobs channel -> N
// workers -> results channel -> one consumer) so cancellation and shutdown
// only need to reason about a handful of well-defined stages instead of an
// open-ended opportunistic recursion. It returns the URLs recursion should
// expand into next (empty/nil when Recursive is false or nothing qualified).
func (f *webFuzzRun) runLevel(ctx context.Context, bases []string) ([]string, error) {
	var baselines map[string]*fingerprint.Profile
	if f.cfg.AutoCalibrate {
		baselines = make(map[string]*fingerprint.Profile, len(bases))
		for _, base := range bases {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			baselines[base] = f.calibrate(ctx, base)
		}
	}

	jobs := make(chan webfuzzJob, f.threads*4)
	results := make(chan webfuzzResult, f.threads*4)

	var workersWG sync.WaitGroup
	workersWG.Add(f.threads)
	for i := 0; i < f.threads; i++ {
		go func() {
			defer workersWG.Done()
			for job := range jobs {
				results <- f.doRequest(ctx, job)
			}
		}()
	}
	go func() {
		workersWG.Wait()
		close(results)
	}()

	produceErrCh := make(chan error, 1)
	go func() {
		defer close(jobs)
		for _, base := range bases {
			if err := f.produceWords(ctx, base, jobs); err != nil {
				produceErrCh <- err
				return
			}
		}
		produceErrCh <- nil
	}()

	// The only goroutine that calls emit/progress or mutates f.done/nextBases
	// -- keeps both plain, unsynchronized state.
	var nextBases []string
	for res := range results {
		f.done++
		if f.done%webFuzzProgressEvery == 0 {
			f.reportProgress()
		}
		if res.err != nil {
			f.failed++
			continue
		}
		if baselines[res.job.base].Matches(res.obs) {
			continue
		}
		resultURL := f.resultURL(res.job.base, res.job.word)
		f.emit(model.Finding{
			ID:            newFindingID(),
			URL:           resultURL,
			StatusCode:    res.statusCode,
			ContentLength: res.contentLength,
			Words:         res.words,
			Lines:         res.lines,
			ContentType:   res.contentType,
			RedirectLoc:   res.redirectLoc,
			Method:        f.method,
			Headers:       res.headers,
			SourceTool:    f.emitSourceTool(),
			SourceNodeID:  f.meta.NodeID,
			RunID:         f.meta.RunID,
			Timestamp:     time.Now(),
		})
		if f.cfg.Recursive && isDirectoryHit(res, resultURL) {
			next := strings.TrimRight(resultURL, "/") + "/FUZZ"
			if !f.visited[next] {
				f.visited[next] = true
				nextBases = append(nextBases, next)
			}
		}
	}
	f.reportProgress()

	if err := <-produceErrCh; err != nil && ctx.Err() == nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nextBases, nil
}

func (f *webFuzzRun) emitSourceTool() string { return "webfuzz" }

// produceWords streams base's wordlist file line by line (never loading it
// fully into memory, same approach as wordlists.CountLines), emitting one
// job per line plus one per extension. Stops promptly on ctx cancellation
// instead of blocking forever trying to hand a job to workers that have
// already stopped reading.
func (f *webFuzzRun) produceWords(ctx context.Context, base string, jobs chan<- webfuzzJob) error {
	file, err := os.Open(f.cfg.Wordlist)
	if err != nil {
		return fmt.Errorf("open wordlist: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word == "" {
			continue
		}
		if err := sendJob(ctx, jobs, webfuzzJob{base: base, word: word}); err != nil {
			return err
		}
		for _, ext := range f.cfg.Extensions {
			if err := sendJob(ctx, jobs, webfuzzJob{base: base, word: word + "." + strings.TrimPrefix(ext, ".")}); err != nil {
				return err
			}
		}
	}
	return scanner.Err()
}

func sendJob(ctx context.Context, jobs chan<- webfuzzJob, job webfuzzJob) error {
	select {
	case jobs <- job:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// doRequest performs one fuzzed request. Errors (timeout, connection
// refused, ...) are reported on the result rather than returned, since one
// failed request in a run of thousands shouldn't abort the whole level.
func (f *webFuzzRun) doRequest(ctx context.Context, job webfuzzJob) webfuzzResult {
	if f.limiter != nil {
		if err := f.limiter.wait(ctx); err != nil {
			return webfuzzResult{job: job, err: err}
		}
	}

	reqCtx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()

	reqURL := job.base
	if !f.headerHasFuzz {
		reqURL = strings.Replace(job.base, "FUZZ", job.word, 1)
	}
	req, err := http.NewRequestWithContext(reqCtx, f.method, reqURL, nil)
	if err != nil {
		return webfuzzResult{job: job, err: err}
	}
	// Substitute this job's word into a FUZZ header, then apply every header
	// through netgov.ApplyHeaders. Setting Host via req.Header.Set does
	// nothing in Go, which silently broke header-based vhost fuzzing.
	reqHeaders := make(map[string]string, len(f.cfg.Headers))
	for k, v := range f.cfg.Headers {
		if f.headerHasFuzz && k == f.fuzzHeaderName {
			v = strings.Replace(v, "FUZZ", job.word, 1)
		}
		reqHeaders[k] = v
	}
	netgov.ApplyHeaders(req, reqHeaders)

	resp, err := f.client.Do(req)
	if err != nil {
		return webfuzzResult{job: job, err: err}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxFuzzBodyPeek))
	words, lines := countWordsLines(body)
	size := len(body)
	if resp.ContentLength >= 0 {
		size = int(resp.ContentLength)
	}

	headers := make(map[string]string, len(resp.Header))
	for k := range resp.Header {
		headers[k] = resp.Header.Get(k)
	}

	// Fingerprint the body for catch-all comparison. Simhash only reads the
	// first chunk, which is enough to identify a page, but Length must keep the
	// real size: otherwise every page over the cap would look the same size.
	obs := fingerprint.Observe(resp.StatusCode, resp.Header.Get("Content-Type"), body[:min(len(body), observationBodyCap)])
	obs.Length = size

	return webfuzzResult{
		job:           job,
		statusCode:    resp.StatusCode,
		contentLength: size,
		words:         words,
		lines:         lines,
		contentType:   resp.Header.Get("Content-Type"),
		redirectLoc:   resp.Header.Get("Location"),
		headers:       headers,
		obs:           obs,
	}
}

// resultURL reconstructs the URL a job's result is "about" -- itself for
// URL-fuzz mode, or (mirroring ffuf's own vhost-mode handling) a synthetic
// URL with the fuzzed header value standing in for the host when FUZZ lives
// in a header instead.
func (f *webFuzzRun) resultURL(base, word string) string {
	if !f.headerHasFuzz {
		return strings.Replace(base, "FUZZ", word, 1)
	}
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	u.Host = strings.Replace(f.cfg.Headers[f.fuzzHeaderName], "FUZZ", word, 1)
	return u.String()
}

func countWordsLines(body []byte) (words, lines int) {
	if len(body) == 0 {
		return 0, 0
	}
	return len(strings.Fields(string(body))), strings.Count(string(body), "\n") + 1
}

// observationBodyCap bounds how much of a response body is fingerprinted.
// Identity is carried by the start of a page, so a larger read adds cost
// without adding discrimination.
const observationBodyCap = 64 << 10

// calibrate probes base with random nonsense words before its real sweep
// starts, mirroring ffuf -ac's intent. The answers become a catch-all profile:
// a hit whose body looks like those answers is the host's soft-404, not a
// discovery. Samples that disagree with each other produce an unstable profile,
// which never filters anything.
func (f *webFuzzRun) calibrate(ctx context.Context, base string) *fingerprint.Profile {
	var samples []fingerprint.Observation
	for i := 0; i < webFuzzCalibrationProbes; i++ {
		word, err := randomWord()
		if err != nil {
			continue
		}
		res := f.doRequest(ctx, webfuzzJob{base: base, word: word})
		if res.err != nil {
			continue
		}
		samples = append(samples, res.obs)
	}
	return fingerprint.NewProfile(samples)
}

// isDirectoryHit reports whether a hit is a directory worth walking into.
// Recursing into every 2xx/3xx, as before, walked into plain files such as
// robots.txt. A directory is a redirect to its slash form, a forbidden path
// (existing directories are often 403), or an extensionless path that answered
// with content.
func isDirectoryHit(res webfuzzResult, resultURL string) bool {
	switch res.statusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return strings.HasSuffix(res.redirectLoc, "/")
	case http.StatusForbidden:
		return true
	case http.StatusOK:
		return strings.HasSuffix(resultURL, "/") || !strings.Contains(path.Base(resultURL), ".")
	}
	return false
}

func randomWord() (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 12)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		b[i] = charset[n.Int64()]
	}
	return "aperture-calib-" + string(b), nil
}

// webFuzzLimiter is a minimal ticker-fed token bucket bounding requests/sec
// across a whole run -- no external dependency, standing in for what
// ffuf/feroxbuster's own -rate/--rate-limit flags did.
type webFuzzLimiter struct {
	tokens chan struct{}
	stopCh chan struct{}
}

func newWebFuzzLimiter(perSecond int) *webFuzzLimiter {
	l := &webFuzzLimiter{tokens: make(chan struct{}, perSecond), stopCh: make(chan struct{})}
	interval := time.Second / time.Duration(perSecond)
	if interval <= 0 {
		interval = time.Millisecond
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				select {
				case l.tokens <- struct{}{}:
				default: // bucket already full -- drop the tick rather than block
				}
			case <-l.stopCh:
				return
			}
		}
	}()
	return l
}

func (l *webFuzzLimiter) wait(ctx context.Context) error {
	select {
	case <-l.tokens:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *webFuzzLimiter) stop() { close(l.stopCh) }
