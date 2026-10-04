// Package xxe tests endpoints that accept XML for XML External Entity
// injection (CWE-611). An XXE makes the parser itself read a local file, or
// fetch a URL, while it parses a document the attacker sent, so the attacker
// can see a file's contents or reach a server only the target can see.
//
// The operator supplies the endpoint and, optionally, an XML part of their
// own. Every text value in that XML is an injection point: a run rewrites the
// document with a DOCTYPE and an entity reference in place of each value, and
// sends the result. Without an XML part, a small well-formed probe document is
// used. In AutoDiscover mode the scanner first looks for XML-capable endpoints
// on the same origin (see discover.go) and runs the same checks against each
// one that answers XML.
//
// Checks run in order of how much they prove, and each finding carries a
// confidence that says which kind of proof it has:
//   - entity-canary: a DOCTYPE entity with no network or file access. If the
//     parser expands it, the endpoint is XML-capable and the rest is worth
//     trying. It works without any collaborator listener.
//   - file-read: an external entity read of /etc/passwd or win.ini, confirmed
//     only by a file signature that the baseline lacks.
//   - error-based: an external entity pointing at a missing path. When the
//     parser reports that path back, it has tried to open it. Confidence is
//     "likely", not "confirmed", because a parser error can prove the
//     resolution without proving a read.
//   - local-dtd-error: a DTD already on the server, redefined from the
//     DOCTYPE so that a missing-file error carries /etc/passwd's first line.
//     The file's contents in the response prove the read, so it is confirmed.
//   - xinclude: an XInclude element, for when the operator cannot add a DOCTYPE.
//   - ssrf-metadata: an external entity pointing at a cloud metadata service.
//   - oob-callback: a blind XXE. Payloads point at Aperture's collaborator
//     listener, and a callback is the only proof that works when nothing
//     reaches the response. Variants are a general entity, a parameter entity,
//     an external DTD named in the DOCTYPE, and an out-of-band file read whose
//     callback carries /etc/passwd (confirmed as a file read), plus a DNS
//     hostname when a DNS domain is set. Confidence is "confirmed".
//
// Every text value and every attribute value of the operator's XML is an
// injection point. Payloads that reference an external entity from a value
// are skipped on attribute values, since XML forbids that in an attribute.
//
// Denial-of-service variants (billion-laughs-style entity expansion) are
// deliberately left out, since their only effect is to exhaust the target.
//
// Shaped like the other scanners: a battery of check modules, each with fixed
// severity and findings present even when empty.
package xxe

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Indigo6415/Aperture/internal/collaborator"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
)

// Confidence levels for a Finding.
const (
	ConfidenceConfirmed = "confirmed"
	ConfidenceLikely    = "likely"
)

// maxPointsPerEndpoint caps how many text values a run injects into per
// endpoint. Every point runs every module, so a large operator-supplied
// document would otherwise multiply the request count without limit.
const maxPointsPerEndpoint = 25

// checkConcurrency bounds how many points one module tests at once. Requests
// are throttled by the run's shared semaphore; this only keeps the progress
// grid moving steadily instead of every square flipping at once.
const checkConcurrency = 8

// defaultContentType is what the request is sent as when the operator doesn't
// choose one. text/xml is the other common choice, and an operator can set it.
const defaultContentType = "application/xml"

// Finding is one confirmed or likely XXE on one injection point. Request is
// the exact XML document that caused it, so "Send to Tester" can replay it.
type Finding struct {
	Label      string `json:"label"`
	Detail     string `json:"detail,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
	Method     string `json:"method,omitempty"`
	StatusCode int    `json:"statusCode,omitempty"`
	// Confidence is "confirmed" or "likely" (see the constants above).
	Confidence string `json:"confidence,omitempty"`
	// Callback is true when the parser called back to Aperture's collaborator
	// listener, which proves the finding out-of-band. The frontend shows a
	// CALLBACK tag for it.
	Callback bool             `json:"callback,omitempty"`
	Request  *CapturedRequest `json:"request,omitempty"`
}

// ModuleResult is one check module's outcome across every endpoint tested.
type ModuleResult struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Severity string    `json:"severity"`
	Findings []Finding `json:"findings"`
}

// Request is one run's configuration.
type Request struct {
	// URL is the endpoint under test. In AutoDiscover mode it is also the
	// origin and the seed page the crawl starts from.
	URL string `json:"url"`
	// Method is POST or PUT. Empty means POST.
	Method string `json:"method,omitempty"`
	// Body is an optional XML part supplied by the operator. Every text value
	// in it is tested. Empty means a built-in probe document is used.
	Body string `json:"body,omitempty"`
	// ContentType is sent with the request. Empty means application/xml.
	ContentType string            `json:"contentType,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	// AutoDiscover, when true, first looks for same-origin endpoints that
	// accept XML (see discover.go) and tests each one that does, instead of
	// only URL.
	AutoDiscover bool `json:"autoDiscover,omitempty"`
	// RecursionDepth is how many hops of same-origin links the discovery
	// crawl follows beyond URL. Ignored when AutoDiscover is false.
	RecursionDepth int `json:"recursionDepth,omitempty"`
	// MaxPages overrides the discovery crawl's page limit. Ignored when
	// AutoDiscover is false.
	MaxPages int `json:"maxPages,omitempty"`
	// Progress, when set, receives one check per (endpoint, module, injection
	// point) as it happens. See internal/scanprogress.
	Progress scanprogress.Reporter `json:"-"`
}

// OOBConfig is how Run reaches Aperture's collaborator listener for the
// blind-XXE module. The zero value (nil Registry) skips that module without
// failing the rest of the run.
type OOBConfig struct {
	Registry *collaborator.Registry
	// CallbackBaseURL is this Aperture instance's externally reachable
	// scheme://host[:port], used to build each callback address.
	CallbackBaseURL string
	// DNSDomain, when set, adds a DNS-hostname payload per point, which
	// catches parsers whose outbound HTTP is blocked but whose DNS lookup is
	// not.
	DNSDomain string
	// SharedToken/SharedProvider, when set, name a callback server the
	// operator picked from their Callback picker (see collaborator.Ref)
	// instead of minting one throwaway token per point. Every point's payloads
	// then share that token, and each (point, variant) probe is told apart by
	// its own identifier. SharedProvider is "aperture" (poll via Registry) or
	// "webhooksite" (poll via collaborator.PollWebhookSite). SharedToken==""
	// mints a fresh token per point instead.
	SharedToken    string
	SharedProvider string
}

// oobConfigured reports whether oob names a usable callback listener. A
// webhook.site server needs no Aperture listener, since it is hosted elsewhere.
func oobConfigured(oob OOBConfig) bool {
	if oob.SharedToken != "" && oob.SharedProvider == "webhooksite" {
		return true
	}
	return oob.Registry != nil && oob.CallbackBaseURL != ""
}

// Baseline is the first tested endpoint's untouched response.
type Baseline struct {
	URL        string `json:"url"`
	StatusCode int    `json:"statusCode"`
}

// EndpointResult says what one tested endpoint was and why it was tested.
type EndpointResult struct {
	URL    string `json:"url"`
	Method string `json:"method"`
	// Source says where the endpoint came from: "seed", "form action",
	// "script reference", or "common path".
	Source string `json:"source"`
	// Evidence says why an auto-discovered endpoint counts as XML-capable.
	// Empty for the seed of a manual run, which is tested as given.
	Evidence     string `json:"evidence,omitempty"`
	PointsTested int    `json:"pointsTested"`
}

// Result is one full run's outcome.
type Result struct {
	Baseline  Baseline         `json:"baseline"`
	Modules   []ModuleResult   `json:"modules"`
	Endpoints []EndpointResult `json:"endpoints"`
	// PointsTested is the number of injection points summed across endpoints.
	PointsTested int `json:"pointsTested"`
	// OOBEnabled reports whether the blind-XXE module had a callback listener.
	// When false, that module ran nothing, so its absence isn't a clean result.
	OOBEnabled bool `json:"oobEnabled"`
}

// endpointRun is everything the checks need for one target.
type endpointRun struct {
	client      *http.Client
	sem         chan struct{}
	target      *url.URL
	method      string
	contentType string
	headers     map[string]string
	tpl         template
	// baseline is the endpoint's response to the unmodified document. Any
	// signature present in it can't count as proof of a later read.
	baseline *sendResult
	// nonce is random per run, so every marker is unique to this run.
	nonce string
	// label is the endpoint as shown on a check's square and in finding labels.
	label string
	key   string
	// ordinal is this endpoint's position in the run. A shared callback token
	// is reused across endpoints, so identifiers include it to keep one
	// endpoint's late hits from being credited to another.
	ordinal int
	rep     scanprogress.Reporter
}

// post sends body to this endpoint, under the run's shared throttle.
func (e *endpointRun) post(ctx context.Context, body string) *sendResult {
	return send(ctx, e.sem, e.client, e.method, e.target, e.contentType, body, e.headers)
}

// checkID is the progress key for one (module, point) on this endpoint. It is
// stable for a run, so Plan, Start and Done all refer to the same square.
func (e *endpointRun) checkID(mod moduleMeta, pt leaf) string {
	return fmt.Sprintf("%s|%s|%d", e.key, mod.id, pt.index)
}

// check builds the progress entry for (module, point) on this endpoint.
func (e *endpointRun) check(mod moduleMeta, pt leaf) scanprogress.Check {
	return scanprogress.Check{
		ID:    e.checkID(mod, pt),
		Label: pt.describe() + " on " + e.label,
		Group: mod.name,
	}
}

// Run tests req.URL, or in AutoDiscover mode every same-origin endpoint that
// answers XML, and returns one ModuleResult per module across all of them.
// It returns an error only for a bad request, or when a manual run's endpoint
// can't be reached at all.
func Run(ctx context.Context, req Request, oob OOBConfig) (*Result, error) {
	rep := scanprogress.Or(req.Progress)

	seed, err := parseTarget(req.URL)
	if err != nil {
		return nil, err
	}
	method, err := normalizeMethod(req.Method)
	if err != nil {
		return nil, err
	}
	tpl, err := parseTemplate(bodyOrDefault(req.Body))
	if err != nil {
		return nil, err
	}
	contentType := req.ContentType
	if contentType == "" {
		contentType = defaultContentType
	}
	nonce, err := newNonce()
	if err != nil {
		return nil, err
	}

	client := newClient()
	sem := make(chan struct{}, maxConcurrentRequests)

	var targets []discovered
	if req.AutoDiscover {
		rep.Phase("Looking for XML-capable endpoints")
		targets = discoverEndpoints(ctx, client, sem, seed, req.Headers, contentType, method, req.RecursionDepth, req.MaxPages, rep)
	} else {
		targets = []discovered{{target: seed, source: "seed"}}
	}

	// Endpoints starts as an empty slice, not nil, so a run that tests no
	// endpoint still serializes as [] rather than null for the frontend.
	res := &Result{OOBEnabled: oobConfigured(oob), Endpoints: []EndpointResult{}}
	merged := map[string]*ModuleResult{}
	var order []string
	baselineSet := false

	// Endpoints run one after another. Each endpoint already fans its checks
	// out, and running endpoints together as well would multiply that load
	// against a single host.
	for i, d := range targets {
		if ctx.Err() != nil {
			break
		}
		points := tpl.leaves
		if len(points) > maxPointsPerEndpoint {
			points = points[:maxPointsPerEndpoint]
		}
		e := &endpointRun{
			client:      client,
			sem:         sem,
			target:      d.target,
			method:      method,
			contentType: contentType,
			headers:     req.Headers,
			tpl:         tpl,
			nonce:       nonce,
			label:       d.target.String(),
			key:         method + " " + d.target.String(),
			ordinal:     i,
			rep:         rep,
		}
		e.tpl.leaves = points

		// The untouched document is sent first as the baseline. A manual run
		// fails when the endpoint can't be reached, since there is nothing to
		// test. An auto run just skips that endpoint.
		e.baseline = e.post(ctx, tpl.text)
		if e.baseline.Err != nil {
			if !req.AutoDiscover {
				return nil, fmt.Errorf("xxe: baseline request failed: %w", e.baseline.Err)
			}
			continue
		}
		if !baselineSet {
			res.Baseline = Baseline{URL: req.URL, StatusCode: e.baseline.StatusCode}
			baselineSet = true
		}

		for _, m := range e.run(ctx, oob) {
			if existing, ok := merged[m.ID]; ok {
				existing.Findings = append(existing.Findings, m.Findings...)
				continue
			}
			cp := m
			merged[m.ID] = &cp
			order = append(order, m.ID)
		}

		res.Endpoints = append(res.Endpoints, EndpointResult{
			URL:          d.target.String(),
			Method:       method,
			Source:       d.source,
			Evidence:     d.evidence,
			PointsTested: len(points),
		})
		res.PointsTested += len(points)
	}

	results := make([]ModuleResult, 0, len(order))
	for _, id := range order {
		results = append(results, *merged[id])
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })
	res.Modules = results
	return res, nil
}

// run executes every module against this endpoint and returns one result per
// module. The in-band modules and the blind module run side by side, all
// sharing the same request throttle.
func (e *endpointRun) run(ctx context.Context, oob OOBConfig) []ModuleResult {
	points := e.tpl.leaves
	oobOn := oobConfigured(oob)
	mods := inbandModules(e.nonce)

	// Every check is planned before any runs, so the whole grid appears at
	// once. The blind module is left out when no listener is configured, since
	// it runs nothing then and its squares would stay grey.
	var checks []scanprogress.Check
	for _, m := range mods {
		for _, pt := range points {
			checks = append(checks, e.check(m.meta, pt))
		}
	}
	if oobOn {
		for _, pt := range points {
			checks = append(checks, e.check(oobModule, pt))
		}
	}
	e.rep.Plan(checks...)
	e.rep.Phase(fmt.Sprintf("Testing %d injection point(s) on %s", len(points), e.label))

	results := make([]ModuleResult, len(mods)+1)
	var wg sync.WaitGroup
	for i, m := range mods {
		wg.Add(1)
		go func(i int, m inbandModule) {
			defer wg.Done()
			findings := e.runPoints(m.meta, points, func(pt leaf) []Finding {
				return e.runInband(ctx, m, pt)
			})
			results[i] = ModuleResult{ID: m.meta.id, Name: m.meta.name, Severity: m.meta.severity, Findings: nonNil(findings)}
		}(i, m)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		var findings []Finding
		if oobOn {
			findings = e.runOOB(ctx, oob, points)
		}
		results[len(mods)] = ModuleResult{ID: oobModule.id, Name: oobModule.name, Severity: oobModule.severity, Findings: nonNil(findings)}
	}()
	wg.Wait()
	return results
}

// runPoints runs check once per point, with at most checkConcurrency in
// flight, bracketing each with progress Start/Done. A point's square only turns
// "testing" once it gets a slot, so anything still waiting correctly reads as
// queued.
func (e *endpointRun) runPoints(mod moduleMeta, points []leaf, check func(pt leaf) []Finding) []Finding {
	var mu sync.Mutex
	var out []Finding
	var wg sync.WaitGroup
	slots := make(chan struct{}, checkConcurrency)
	for _, pt := range points {
		wg.Add(1)
		go func(pt leaf) {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()

			id := e.checkID(mod, pt)
			e.rep.Start(id)
			found := check(pt)
			e.rep.Done(id, len(found), nil)

			mu.Lock()
			out = append(out, found...)
			mu.Unlock()
		}(pt)
	}
	wg.Wait()
	return out
}

// runInband sends each of m's payloads at pt in turn and returns the first
// that is confirmed. Later payloads aren't tried once one succeeds, since
// they would only repeat the same read.
func (e *endpointRun) runInband(ctx context.Context, m inbandModule, pt leaf) []Finding {
	for _, p := range m.payloads {
		// A text-only payload cannot go in an attribute value, and the parser
		// would reject the whole document for it. Skip it on that point.
		if pt.attr != "" && p.needsText {
			continue
		}
		// The signature is already in the untouched response, so a match
		// here says nothing about this point. Skip the payload.
		if p.pattern.MatchString(e.baseline.Body) {
			continue
		}

		res := e.post(ctx, p.build(e.tpl, pt))
		if res.Err != nil {
			continue
		}
		match := p.pattern.FindString(res.Body)
		if match == "" {
			continue
		}

		// Same DOCTYPE with the entity reference removed. If the match shows
		// up here too, the response only echoed the DOCTYPE back.
		if p.control != nil {
			ctl := e.post(ctx, p.control(e.tpl, pt))
			if ctl.Err == nil && p.pattern.MatchString(ctl.Body) {
				continue
			}
		}

		return []Finding{{
			Label:      fmt.Sprintf("%s on %s: %s", pt.describe(), e.label, p.label),
			Detail:     p.detail,
			Evidence:   truncateEvidence(match),
			Method:     e.method,
			StatusCode: res.StatusCode,
			Confidence: p.confidence,
			Request:    &res.Request,
		}}
	}
	return nil
}

// runOOB is the blind-XXE module. It mints one callback token per point, sends
// every variant at that point, waits for callbacks to settle, then reports any
// point whose token was hit. The variant that fired is recorded as the hit's
// Identifier, which is the URL path segment the payload used.
func (e *endpointRun) runOOB(ctx context.Context, oob OOBConfig, points []leaf) []Finding {
	// A picked shared server takes its own path, since its hits are told apart
	// by identifier rather than by token.
	if oob.SharedToken != "" {
		return e.runOOBShared(ctx, oob, points)
	}

	variants := oobVariants(oob)
	base := strings.TrimRight(oob.CallbackBaseURL, "/")

	tokens := make([]string, len(points))
	for i := range points {
		tokens[i] = oob.Registry.NewToken()
	}
	for _, pt := range points {
		e.rep.Start(e.checkID(oobModule, pt))
	}

	// sent records the exact request behind each token and variant pair, so
	// a hit can show the payload that caused it.
	var mu sync.Mutex
	sent := map[string]CapturedRequest{}
	var wg sync.WaitGroup
	for i, pt := range points {
		for _, v := range variants {
			// A variant that references its callback through &xxe; cannot sit in an
			// attribute value, so it is not sent on that point.
			if pt.attr != "" && v.needsText {
				continue
			}
			wg.Add(1)
			go func(pt leaf, token string, v oobVariant) {
				defer wg.Done()
				cb := callbackURL(base, token, v, oob.DNSDomain)
				r := e.post(ctx, v.build(e.tpl, pt, cb))
				mu.Lock()
				sent[token+"|"+v.name] = r.Request
				mu.Unlock()
			}(pt, tokens[i], v)
		}
	}
	wg.Wait()

	e.rep.Phase("Waiting for out-of-band callbacks")
	collaborator.WaitForRegistry(ctx, oob.Registry, tokens, collaborator.DefaultPollInterval, collaborator.DefaultQuietPeriod, collaborator.DefaultMaxWait)

	var out []Finding
	for i, pt := range points {
		id := e.checkID(oobModule, pt)
		hits := oob.Registry.Poll(tokens[i])
		if len(hits) == 0 {
			e.rep.Done(id, 0, nil)
			continue
		}
		h := preferredHit(hits)
		r, ok := sent[tokens[i]+"|"+h.Identifier]
		var req *CapturedRequest
		if ok {
			req = &r
		}
		out = append(out, e.blindFinding(pt, hits, h.Identifier, req))
		e.rep.Done(id, 1, nil)
	}
	return out
}

// runOOBShared is runOOB's path for a callback server the operator picked. Each
// point sends every variant at that one shared token, with an identifier that
// names the endpoint, the point, and the variant. Hits are then matched back to
// their point by that identifier.
func (e *endpointRun) runOOBShared(ctx context.Context, oob OOBConfig, points []leaf) []Finding {
	for _, pt := range points {
		e.rep.Start(e.checkID(oobModule, pt))
	}

	// sent records the exact request behind each identifier, so a hit can show
	// the payload that caused it.
	var mu sync.Mutex
	sent := map[string]CapturedRequest{}
	var wg sync.WaitGroup
	for _, pt := range points {
		for _, v := range oobVariants(oob) {
			// webhook.site has no DNS side, so its DNS variant is skipped.
			if v.dns && oob.SharedProvider == "webhooksite" {
				continue
			}
			// Same attribute-value restriction as runOOB.
			if pt.attr != "" && v.needsText {
				continue
			}
			ident := sharedIdentifier(e.ordinal, pt, v)
			wg.Add(1)
			go func(pt leaf, v oobVariant, ident string) {
				defer wg.Done()
				cb := sharedCallbackURL(oob, ident, v)
				r := e.post(ctx, v.build(e.tpl, pt, cb))
				mu.Lock()
				sent[ident] = r.Request
				mu.Unlock()
			}(pt, v, ident)
		}
	}
	wg.Wait()

	e.rep.Phase("Waiting for out-of-band callbacks")
	hits := waitSharedHits(ctx, oob)

	var out []Finding
	for _, pt := range points {
		id := e.checkID(oobModule, pt)
		prefix := sharedPrefix(e.ordinal, pt)
		var matched []collaborator.Interaction
		for _, h := range hits {
			if strings.HasPrefix(h.Identifier, prefix) {
				matched = append(matched, h)
			}
		}
		if len(matched) == 0 {
			e.rep.Done(id, 0, nil)
			continue
		}
		h := preferredHit(matched)
		r, ok := sent[h.Identifier]
		var req *CapturedRequest
		if ok {
			req = &r
		}
		out = append(out, e.blindFinding(pt, matched, strings.TrimPrefix(h.Identifier, prefix), req))
		e.rep.Done(id, 1, nil)
	}
	return out
}

// passwdEvidencePattern captures the passwd line that an exfiltrating callback
// carries in its query string, so it can be shown as the finding's evidence.
var passwdEvidencePattern = regexp.MustCompile(`root:[x*!]:0:0:[^&\n]{0,160}`)

// exfiltratedPasswd returns the /etc/passwd line that one of hits carried in its
// query string, and whether any did. The file-exfil variant puts the file there,
// so a hit with it proves the read, not only that the parser made a request.
func exfiltratedPasswd(hits []collaborator.Interaction) (string, bool) {
	for _, h := range hits {
		// The query may be percent-encoded, so decode it before matching. A
		// value that won't decode is matched as it arrived.
		q := h.Query
		if dec, err := url.QueryUnescape(h.Query); err == nil {
			q = dec
		}
		if m := passwdEvidencePattern.FindString(q); m != "" {
			return m, true
		}
	}
	return "", false
}

// preferredHit returns the interaction that names the request behind a
// finding: the one that carried exfiltrated file contents if any did, else the
// first hit. A finding's request then replays the exact payload that worked.
func preferredHit(hits []collaborator.Interaction) collaborator.Interaction {
	for _, h := range hits {
		if _, ok := exfiltratedPasswd([]collaborator.Interaction{h}); ok {
			return h
		}
	}
	return hits[0]
}

// blindFinding builds the confirmed blind-XXE finding for pt. hits is every
// interaction the point drew, and variant names the probe that fired first. A
// callback that carried /etc/passwd is reported as a file read through the
// callback, which is stronger than a fetch alone.
func (e *endpointRun) blindFinding(pt leaf, hits []collaborator.Interaction, variant string, req *CapturedRequest) Finding {
	h := hits[0]
	if passwd, ok := exfiltratedPasswd(hits); ok {
		return Finding{
			Label: fmt.Sprintf("%s on %s: blind XXE read /etc/passwd through a callback", pt.describe(), e.label),
			Detail: fmt.Sprintf(
				"Injected a parameter entity that loads /etc/passwd and sends its contents as the query string of a request to Aperture's callback listener (%s variant). The parser's %s callback carried the file's first line, which proves the file was read by the target's parser even though nothing came back in the HTTP response.",
				variant, h.Protocol,
			),
			Evidence:   truncateEvidence(passwd),
			Method:     e.method,
			Confidence: ConfidenceConfirmed,
			Callback:   true,
			Request:    req,
		}
	}
	return Finding{
		Label: fmt.Sprintf("%s on %s: blind XXE callback", pt.describe(), e.label),
		Detail: fmt.Sprintf(
			"Injected an external entity (%s variant) pointing at Aperture's callback listener, and the target's parser called back: %d %s interaction(s), the first from %s. The server itself fetched an attacker-chosen address while parsing the XML, which a response-based check cannot see.",
			variant, len(hits), h.Protocol, h.RemoteAddr,
		),
		Evidence:   fmt.Sprintf("%s callback from %s at %s", h.Protocol, h.RemoteAddr, h.Timestamp.Format(time.RFC3339)),
		Method:     e.method,
		Confidence: ConfidenceConfirmed,
		Callback:   true,
		Request:    req,
	}
}

// sharedPrefix is the identifier prefix every probe for pt on this endpoint
// carries. The trailing dash keeps point 1 from matching point 10.
func sharedPrefix(ordinal int, pt leaf) string {
	return fmt.Sprintf("xxe-%d-%d-", ordinal, pt.index)
}

// sharedIdentifier names one (endpoint, point, variant) probe. It is a single
// DNS-safe label, so it works in both the HTTP path and the DNS hostname.
func sharedIdentifier(ordinal int, pt leaf, v oobVariant) string {
	return sharedPrefix(ordinal, pt) + v.name
}

// sharedCallbackURL builds the address one probe calls back to on a shared
// server. Webhook.site and HTTP use the identifier as a path segment, and the
// DNS variant puts it in front of the shared token's hostname.
func sharedCallbackURL(oob OOBConfig, ident string, v oobVariant) string {
	if oob.SharedProvider == "webhooksite" {
		return collaborator.WebhookSiteCallbackURL(oob.SharedToken) + "/" + ident + "/"
	}
	if v.dns {
		return "http://" + ident + "." + oob.SharedToken + "." + oob.DNSDomain + "/"
	}
	return strings.TrimRight(oob.CallbackBaseURL, "/") + "/collab/" + oob.SharedToken + "/" + ident + "/"
}

// waitSharedHits waits for the shared server to settle, then returns every hit
// it recorded. A failed webhook.site poll discards what it returned, so the
// run reads as no callbacks rather than as a partial result.
func waitSharedHits(ctx context.Context, oob OOBConfig) []collaborator.Interaction {
	if oob.SharedProvider == "webhooksite" {
		hits, err := collaborator.WaitForCallbacks(ctx, func(c context.Context) ([]collaborator.Interaction, error) {
			return collaborator.PollWebhookSite(c, oob.SharedToken)
		}, collaborator.DefaultPollInterval, collaborator.DefaultQuietPeriod, collaborator.DefaultMaxWait)
		if err != nil {
			return nil
		}
		return hits
	}
	collaborator.WaitForRegistry(ctx, oob.Registry, []string{oob.SharedToken}, collaborator.DefaultPollInterval, collaborator.DefaultQuietPeriod, collaborator.DefaultMaxWait)
	return oob.Registry.Poll(oob.SharedToken)
}

// callbackURL builds the address one variant calls back to. HTTP variants
// name the variant as the path segment after the token. The DNS variant
// prefixes the hostname with its name, so the lookup carries the same
// identifier.
func callbackURL(base, token string, v oobVariant, dnsDomain string) string {
	if v.dns {
		return "http://" + v.name + "." + token + "." + dnsDomain + "/"
	}
	return base + "/collab/" + token + "/" + v.name + "/"
}

// normalizeMethod returns POST or PUT, defaulting to POST. Anything else is
// rejected, since an XML body only has a meaning for those two.
func normalizeMethod(m string) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(m)) {
	case "", http.MethodPost:
		return http.MethodPost, nil
	case http.MethodPut:
		return http.MethodPut, nil
	default:
		return "", fmt.Errorf("xxe: unsupported method %q (use POST or PUT)", m)
	}
}

// bodyOrDefault returns the operator's XML, or the built-in probe document
// when none was supplied.
func bodyOrDefault(body string) string {
	if strings.TrimSpace(body) == "" {
		return defaultBody
	}
	return body
}

// newNonce returns a random tag used to make every marker unique to this run.
func newNonce() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("xxe: generating run nonce: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// nonNil returns s, or an empty slice when s is nil. JSON then shows [] rather
// than null, which the frontend expects.
func nonNil(s []Finding) []Finding {
	if s == nil {
		return []Finding{}
	}
	return s
}

// truncateEvidence shortens long matches so one huge response can't bloat the
// stored result.
func truncateEvidence(s string) string {
	const max = 300
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
