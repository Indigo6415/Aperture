package xss

// Ported from dalfox (https://github.com/hahwul/dalfox, MIT License, Copyright (c)
// 2020 hahwul). This file ports dalfox's functional XSS corpus (its tests/functional/mock_cases
// TOML files and the xss_mock_server.rs harness that serves them) into a Go test.
//
// testdata/dalfox_corpus.json is generated from dalfox's TOML by a one-off
// converter; each case records a reflection template (or transform name), a
// server-side filter chain, the handler type that serves it, and whether dalfox
// expects the scanner to detect it. The harness below serves each case the way
// dalfox's mock server does, runs Run against it, and scores the static
// detector against dalfox's expectations: recall on the cases that should be
// found, and false positives on the cases that should stay clean.
//
// Handler types the scanner has no injection point for (cookie, header with a
// custom name, and path segments) are counted as skipped rather than scored.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
)

// corpusCase is one row of dalfox's corpus, as written to testdata/dalfox_corpus.json.
type corpusCase struct {
	ID                int      `json:"id"`
	File              string   `json:"file"`
	Category          string   `json:"category"`
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	HandlerType       string   `json:"handler_type"`
	Reflection        string   `json:"reflection"`
	ExpectedDetection bool     `json:"expected_detection"`
	Filter            string   `json:"filter"`
	ParamName         string   `json:"param_name"`
	StatusCode        int      `json:"status_code"`
	ContentType       string   `json:"content_type"`
	ResponseHeaders   []string `json:"response_headers"`
	PageTemplate      string   `json:"page_template"`
}

// corpusFile is the whole fixture: the page templates the realworld cases pick
// from by key, plus every case.
type corpusFile struct {
	Source    string            `json:"source"`
	Templates map[string]string `json:"templates"`
	Cases     []corpusCase      `json:"cases"`
}

// corpusRegexes are the regular expressions dalfox's mock server uses for its
// WAF and tag-stripping simulations, ported verbatim. Rust's \w and \b are
// Unicode-aware while Go's are ASCII; none of the corpus payloads depend on that.
var (
	corpusStripTags        = regexp.MustCompile(`<[^>]*>`)
	corpusStripScript      = regexp.MustCompile(`(?i)<script[^>]*>.*?</script>|<script[^>]*>|</script>`)
	corpusStripOnEvents    = regexp.MustCompile(`(?i)\bon\w+\s*=`)
	corpusWAFBasic         = regexp.MustCompile(`(?i)</?script`)
	corpusWAFModerate      = regexp.MustCompile(`(?i)</?script|on\w+\s*=|</?iframe|</?object|</?embed`)
	corpusWAFStrict        = regexp.MustCompile(`(?i)</?script|on\w+\s*=|javascript:|alert|confirm|prompt|<|>`)
	corpusStripIframe      = regexp.MustCompile(`(?i)</?iframe[^>]*>`)
	corpusStripImg         = regexp.MustCompile(`(?i)<img[^>]*>`)
	corpusStripSvg         = regexp.MustCompile(`(?i)</?svg[^>]*>`)
	corpusWAFSVGAware      = regexp.MustCompile(`(?i)</?script|</?svg|</?math|on\w+\s*=`)
	corpusWAFURLProtocol   = regexp.MustCompile(`(?i)javascript\s*:|data\s*:`)
	corpusReplaceScript    = regexp.MustCompile(`(?i)<(/?script)`)
	corpusAllowedTags      = regexp.MustCompile(`(?i)<(/?(?:p|b|i|em|strong|br|ul|ol|li|a))\b[^>]*>`)
	corpusStripStyle       = regexp.MustCompile(`(?i)<style[^>]*>.*?</style>|</?style[^>]*>`)
	corpusStripDangerAttrs = regexp.MustCompile(`(?i)\bon\w+\s*=|href\s*=\s*["']?\s*javascript:|src\s*=\s*["']?\s*data:`)
	corpusWAFCloudflare    = regexp.MustCompile(`(?i)</?script|</?svg|</?iframe|on\w+\s*=|javascript:|alert\s*\(|eval\s*\(|document\.(cookie|write|domain)`)
	corpusWAFAkamai        = regexp.MustCompile(`(?i)<script|on(error|load|click|mouse)\s*=|javascript:|<img[^>]+onerror|<svg|alert\(|String\.fromCharCode`)
	corpusNormalizeWS      = regexp.MustCompile(`\s+`)
)

// corpusReflect mirrors apply_reflection in the mock server: a named transform
// encodes the input, anything else is treated as a template with {input} in it.
func corpusReflect(pattern, input string) string {
	switch pattern {
	case "encoded_html_named":
		return corpusHTMLNamedEncode(input)
	case "encoded_html_hex_lower":
		return corpusHTMLHexEncode(input, "x")
	case "encoded_html_hex_upper":
		return corpusHTMLHexEncode(input, "X")
	case "percent_to_entity":
		return strings.ReplaceAll(input, "%", "&#37;")
	case "encoded_url":
		return corpusURLEncode(input)
	default:
		return strings.ReplaceAll(pattern, "{input}", input)
	}
}

// corpusHTMLNamedEncode replaces the five characters that have named HTML
// entities, mirroring html_named_encode_all.
func corpusHTMLNamedEncode(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '&':
			b.WriteString("&amp;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&apos;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// corpusHTMLHexEncode writes every rune as a numeric character reference in hex.
// marker is "x" for the lowercase form and "X" for the uppercase one.
func corpusHTMLHexEncode(s, marker string) string {
	var b strings.Builder
	for _, r := range s {
		if marker == "x" {
			fmt.Fprintf(&b, "&#x%02x;", r)
		} else {
			fmt.Fprintf(&b, "&#X%02X;", r)
		}
	}
	return b.String()
}

// corpusURLEncode percent-encodes every byte outside the RFC 3986 unreserved set,
// matching the urlencoding crate the mock server uses.
func corpusURLEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		// Unreserved bytes pass through unchanged; everything else becomes %XX.
		if ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// corpusFilter mirrors apply_filter: a pipe-separated chain of sanitizers and
// WAF simulations applied in order to the raw parameter value. An unknown
// filter name is a no-op, the same as in the mock server.
func corpusFilter(input, chain string) string {
	result := input
	for _, f := range strings.Split(chain, "|") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		result = corpusApplyOne(result, f)
	}
	return result
}

// corpusApplyOne applies a single named filter. Each WAF-style branch blanks the
// whole value when its pattern matches, and passes the value through otherwise.
func corpusApplyOne(s, f string) string {
	// blockIf returns "" when pattern matches s (a blocked request) and s otherwise.
	blockIf := func(re *regexp.Regexp) string {
		if re.MatchString(s) {
			return ""
		}
		return s
	}
	switch f {
	case "strip_tags":
		return corpusStripTags.ReplaceAllString(s, "")
	case "strip_script":
		return corpusStripScript.ReplaceAllString(s, "")
	case "strip_on_events":
		return corpusStripOnEvents.ReplaceAllString(s, "")
	case "remove_angles":
		return strings.NewReplacer("<", "", ">", "").Replace(s)
	case "remove_quotes":
		return strings.NewReplacer(`"`, "", "'", "").Replace(s)
	case "remove_parens":
		return strings.NewReplacer("(", "", ")", "").Replace(s)
	case "remove_semicolons":
		return strings.ReplaceAll(s, ";", "")
	case "encode_angles":
		return strings.NewReplacer("<", "&lt;", ">", "&gt;").Replace(s)
	case "encode_quotes":
		return strings.NewReplacer(`"`, "&quot;", "'", "&#39;").Replace(s)
	case "encode_double_quotes":
		return strings.ReplaceAll(s, `"`, "&quot;")
	case "encode_single_quotes":
		return strings.ReplaceAll(s, "'", "&#39;")
	case "escape_quotes":
		return strings.NewReplacer(`"`, `\"`, "'", `\'`).Replace(s)
	case "waf_basic":
		return blockIf(corpusWAFBasic)
	case "waf_moderate":
		return blockIf(corpusWAFModerate)
	case "waf_strict":
		return blockIf(corpusWAFStrict)
	case "remove_newlines":
		return strings.NewReplacer("\n", "", "\r", "").Replace(s)
	case "remove_backslash":
		return strings.ReplaceAll(s, `\`, "")
	case "remove_colon":
		return strings.ReplaceAll(s, ":", "")
	case "remove_equals":
		return strings.ReplaceAll(s, "=", "")
	case "alphanumeric_only":
		return strings.Map(func(r rune) rune {
			if unicode.IsLetter(r) || unicode.IsDigit(r) || r == ' ' {
				return r
			}
			return -1
		}, s)
	case "strip_iframe":
		return corpusStripIframe.ReplaceAllString(s, "")
	case "strip_img":
		return corpusStripImg.ReplaceAllString(s, "")
	case "strip_svg":
		return corpusStripSvg.ReplaceAllString(s, "")
	case "encode_ampersand":
		return strings.ReplaceAll(s, "&", "&amp;")
	case "encode_full_html":
		return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;").Replace(s)
	case "waf_svg_aware":
		return blockIf(corpusWAFSVGAware)
	case "waf_url_protocol":
		return corpusWAFURLProtocol.ReplaceAllString(s, "")
	case "replace_script_text":
		return corpusReplaceScript.ReplaceAllString(s, "&lt;${1}")
	case "allow_basic_html":
		return corpusAllowBasicHTML(s)
	case "strip_style":
		return corpusStripStyle.ReplaceAllString(s, "")
	case "strip_dangerous_attrs":
		return corpusStripDangerAttrs.ReplaceAllString(s, "")
	case "remove_backtick":
		return strings.ReplaceAll(s, "`", "")
	case "remove_dollar":
		return strings.ReplaceAll(s, "$", "")
	case "remove_curly_braces":
		return strings.NewReplacer("{", "", "}", "").Replace(s)
	case "waf_cloudflare_sim":
		return blockIf(corpusWAFCloudflare)
	case "waf_akamai_sim":
		return blockIf(corpusWAFAkamai)
	case "normalize_whitespace":
		return strings.TrimSpace(corpusNormalizeWS.ReplaceAllString(s, " "))
	case "double_encode_angles":
		return strings.NewReplacer("<", "&amp;lt;", ">", "&amp;gt;").Replace(s)
	case "lowercase":
		return strings.ToLower(s)
	case "uppercase":
		return strings.ToUpper(s)
	}
	if kw, ok := strings.CutPrefix(f, "remove_keyword:"); ok {
		return regexp.MustCompile("(?i)"+regexp.QuoteMeta(kw)).ReplaceAllString(s, "")
	}
	if n, ok := strings.CutPrefix(f, "truncate:"); ok {
		var limit int
		if _, err := fmt.Sscanf(n, "%d", &limit); err == nil && limit >= 0 {
			// Truncate by runes so a multi-byte character is never split.
			if r := []rune(s); len(r) > limit {
				return string(r[:limit])
			}
		}
	}
	return s
}

// corpusAllowBasicHTML keeps only a fixed set of harmless tags. It swaps each
// allowed tag for a placeholder, strips every remaining tag, then restores the
// allowed tags, so a disallowed tag cannot hide inside an allowed one.
func corpusAllowBasicHTML(s string) string {
	var kept []string
	withPlaceholders := corpusAllowedTags.ReplaceAllStringFunc(s, func(m string) string {
		kept = append(kept, m)
		return fmt.Sprintf("\x00ALLOWED_%d\x00", len(kept)-1)
	})
	out := corpusStripTags.ReplaceAllString(withPlaceholders, "")
	for i, tag := range kept {
		out = strings.ReplaceAll(out, fmt.Sprintf("\x00ALLOWED_%d\x00", i), tag)
	}
	return out
}

// corpusRenderTemplate fills a page template with the reflected value. The
// fixture stores templates in Rust format! syntax, so {{ and }} are literal
// braces. The value is substituted after unescaping, so it is never re-scanned.
func corpusRenderTemplate(templates map[string]string, key, reflected string) string {
	tpl, ok := templates[key]
	if !ok {
		tpl = templates["_"]
	}
	parts := strings.Split(tpl, "{reflected}")
	for i, p := range parts {
		parts[i] = strings.NewReplacer("{{", "{", "}}", "}").Replace(p)
	}
	return strings.Join(parts, reflected)
}

// corpusServer serves the corpus the way dalfox's mock server does. Each case is
// addressed by its index in the fixture, because dalfox's own IDs repeat across
// handler types.
type corpusServer struct {
	cases     []corpusCase
	templates map[string]string
}

// corpusDefaultPage is the body the query, body, and default realworld handlers
// wrap a reflection in when a case names no page template.
func corpusDefaultPage(reflected string) string {
	return "<html><head><title>mock</title></head><body><div id=out>" + reflected + "</div></body></html>"
}

// handler returns the mux that serves every handler type. Case indexes come from
// the URL path, so /query/3 is cases[3].
func (s *corpusServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /query/{idx}", s.serveQuery)
	mux.HandleFunc("GET /realworld/query/{idx}", s.serveRealworld)
	mux.HandleFunc("GET /body-page/{idx}", s.serveBodyPage)
	mux.HandleFunc("POST /body/{idx}", s.serveBody)
	mux.HandleFunc("GET /dom/{idx}", s.serveDOM)
	return mux
}

// caseFor resolves the {idx} path value to its case, or nil when it is out of range.
func (s *corpusServer) caseFor(r *http.Request) *corpusCase {
	var idx int
	if _, err := fmt.Sscanf(r.PathValue("idx"), "%d", &idx); err != nil || idx < 0 || idx >= len(s.cases) {
		return nil
	}
	return &s.cases[idx]
}

// serveQuery reflects the "query" parameter through the case's transform, with
// no filter chain, mirroring query_handler_v2.
func (s *corpusServer) serveQuery(w http.ResponseWriter, r *http.Request) {
	c := s.caseFor(r)
	if c == nil {
		http.NotFound(w, r)
		return
	}
	reflected := corpusReflect(c.Reflection, r.URL.Query().Get("query"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, corpusDefaultPage(reflected))
}

// serveRealworld applies the case's filter chain, then its reflection, then its
// page template, and sets the case's status, content type, and extra headers.
// It mirrors realworld_handler.
func (s *corpusServer) serveRealworld(w http.ResponseWriter, r *http.Request) {
	c := s.caseFor(r)
	if c == nil {
		http.NotFound(w, r)
		return
	}
	filtered := r.URL.Query().Get("query")
	if c.Filter != "" {
		filtered = corpusFilter(filtered, c.Filter)
	}
	reflected := corpusReflect(c.Reflection, filtered)
	body := corpusDefaultPage(reflected)
	if c.PageTemplate != "" {
		body = corpusRenderTemplate(s.templates, c.PageTemplate, reflected)
	}
	ct := c.ContentType
	if ct == "" {
		ct = "text/html; charset=utf-8"
	}
	w.Header().Set("Content-Type", ct)
	for _, h := range c.ResponseHeaders {
		// Each entry is "Name: value"; anything without a colon is ignored.
		if name, value, ok := strings.Cut(h, ":"); ok {
			w.Header().Set(strings.TrimSpace(name), strings.TrimSpace(value))
		}
	}
	if c.StatusCode != 0 {
		w.WriteHeader(c.StatusCode)
	}
	fmt.Fprint(w, body)
}

// serveBodyPage is the seed page for form-body cases. It holds one POST form
// whose single field is the case's parameter, so the crawler finds it.
func (s *corpusServer) serveBodyPage(w http.ResponseWriter, r *http.Request) {
	c := s.caseFor(r)
	if c == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<html><body><form method="POST" action="/body/%s"><input name="%s" value=""></form></body></html>`,
		r.PathValue("idx"), corpusParamName(c))
}

// serveBody reflects the form field named by the case's param_name (default
// "query") through the case's transform. It mirrors body_handler_v2.
func (s *corpusServer) serveBody(w http.ResponseWriter, r *http.Request) {
	c := s.caseFor(r)
	if c == nil {
		http.NotFound(w, r)
		return
	}
	reflected := corpusReflect(c.Reflection, r.PostFormValue(corpusParamName(c)))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, corpusDefaultPage(reflected))
}

// serveDOM serves a DOM-XSS case's page as-is. The page's script is what the
// static DOM sink check reads, so nothing about it is rewritten.
func (s *corpusServer) serveDOM(w http.ResponseWriter, r *http.Request) {
	c := s.caseFor(r)
	if c == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, c.Reflection)
}

// corpusParamName returns the case's form field name, falling back to "query".
func corpusParamName(c *corpusCase) string {
	if c.ParamName != "" {
		return c.ParamName
	}
	return "query"
}

// corpusSupported reports whether the scanner has an injection point for a
// handler type. Cookie, path, and header cases are skipped.
func corpusSupported(handler string) bool {
	switch handler {
	case "query", "realworld", "body", "dom_xss":
		return true
	}
	return false
}

// corpusTarget returns the URL the scanner should start from for a case, and the
// query parameters to test on it.
func corpusTarget(base string, idx int, c corpusCase) (string, []string) {
	switch c.HandlerType {
	case "query":
		return fmt.Sprintf("%s/query/%d", base, idx), []string{"query"}
	case "realworld":
		return fmt.Sprintf("%s/realworld/query/%d", base, idx), []string{"query"}
	case "body":
		// The form is discovered by crawling the seed page, so no names are passed in.
		return fmt.Sprintf("%s/body-page/%d", base, idx), nil
	default:
		return fmt.Sprintf("%s/dom/%d", base, idx), nil
	}
}

// corpusOutOfScope reports whether a case tests something other than XSS. The
// vulnerable-library cases check for outdated JavaScript libraries, so their
// expectation is about the library, not about reflected input.
func corpusOutOfScope(c corpusCase) bool {
	return strings.HasSuffix(c.File, "vuln_libs.toml")
}

// corpusEncodedReflection reports whether a case's reflection is encoded, so the
// value comes back as text the browser does not run. An encoding filter does the
// same thing: it turns the markup into references the browser shows as text. The
// scanner reports these as "reflected but not executable", not as XSS, so they
// are scored apart.
func corpusEncodedReflection(c corpusCase) bool {
	switch c.Reflection {
	case "encoded_html_named", "encoded_html_hex_lower", "encoded_html_hex_upper",
		"encoded_url", "percent_to_entity", "encoded_base64":
		return true
	}
	return strings.Contains(c.Filter, "encode")
}

// corpusDisputed lists cases whose expectation this scanner does not share, with
// the reason. They are scored apart, so the XSS numbers are not padded by them.
// The uppercase filter rewrites alert to ALERT, which is undefined, so no payload
// in the set runs; dalfox expects a detection because it models the reflection.
var corpusDisputed = map[string]string{
	"realworld/encoding_variations.toml#5304":  "uppercase filter turns alert into ALERT (undefined); no payload runs",
	"realworld/search_pages.toml#5007":         "uppercase filter turns alert into ALERT (undefined); no payload runs",
	"realworld/waf_bypass_scenarios.toml#5186": "iframe src=javascript:prompt() passes the filter and runs in browsers; dalfox does not model iframe URL schemes",
}

// corpusDisputedKey identifies a case across the fixture's files, since dalfox's
// IDs repeat between files.
func corpusDisputedKey(c corpusCase) string {
	return fmt.Sprintf("%s#%d", c.File, c.ID)
}

// corpusDetected reports what a run found for a case. xss is true for an
// executable reflection, or a static DOM flow for a DOM-XSS case. reflected is
// true when the scanner saw the input echoed back without executing. Both
// findings below are heuristic-free: the "reflected but not executable" note
// is only read here, never counted as XSS.
func corpusDetected(res *Result, handler string) (xss, reflected bool, hit string) {
	for _, m := range res.Modules {
		for _, f := range m.Findings {
			if handler == "dom_xss" {
				if m.ID == "dom-xss-sink" {
					return true, false, f.Label
				}
				continue
			}
			if m.ID == "reflected-escaped" {
				reflected = true
				continue
			}
			if m.ID == "dom-xss-sink" {
				continue
			}
			if f.Confidence != ConfidenceHeuristic {
				return true, reflected, f.Label + " | evidence: " + f.Evidence
			}
		}
	}
	return false, reflected, ""
}

// corpusOutcome is one case's scored result.
type corpusOutcome struct {
	idx       int
	xss       bool
	reflected bool
	// hit describes the finding that counted as a detection, for the log.
	hit string
	err error
}

// corpusScore tallies one bucket's results against dalfox's expectations.
type corpusScore struct {
	tp, fn, fp, tn, errs int
	missed, falsePos     []string
}

// TestDalfoxCorpus runs dalfox's functional corpus against the scanner and
// reports how often it agrees with dalfox's expected detections.
//
// Scoring has three buckets, so the XSS numbers are not padded with cases the
// scanner should not report as XSS:
//   - XSS cases: a reflection or DOM flow the scanner rates above heuristic.
//   - Encoded reflections: a value echoed back encoded. A hit is the
//     "reflected but not executable" note.
//   - Out of scope: vulnerable-library cases, not scored.
func TestDalfoxCorpus(t *testing.T) {
	raw, err := os.ReadFile("testdata/dalfox_corpus.json")
	if err != nil {
		t.Fatalf("read corpus fixture: %v", err)
	}
	var corpus corpusFile
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatalf("parse corpus fixture: %v", err)
	}

	srv := &corpusServer{cases: corpus.Cases, templates: corpus.Templates}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	// Each scan is independent, so run them through a small worker pool. Each Run
	// also fans out internally, so the pool stays modest.
	const workers = 8
	outcomes := make([]corpusOutcome, len(corpus.Cases))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	skipped := map[string]int{}
	outOfScope := 0
	for idx, c := range corpus.Cases {
		if corpusOutOfScope(c) {
			outOfScope++
			continue
		}
		if !corpusSupported(c.HandlerType) {
			skipped[c.HandlerType]++
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, c corpusCase) {
			defer wg.Done()
			defer func() { <-sem }()
			target, params := corpusTarget(ts.URL, idx, c)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			res, err := Run(ctx, Request{URL: target, Params: params, SkipBrowser: true}, OOBConfig{})
			outcomes[idx] = corpusOutcome{idx: idx, err: err}
			if err == nil {
				outcomes[idx].xss, outcomes[idx].reflected, outcomes[idx].hit = corpusDetected(res, c.HandlerType)
			}
		}(idx, c)
	}
	wg.Wait()

	// Tally each bucket, and keep the mismatched case names for the log.
	scores := map[string]*corpusScore{}
	var disputed []string
	for idx, c := range corpus.Cases {
		if corpusOutOfScope(c) || !corpusSupported(c.HandlerType) {
			continue
		}
		if reason, ok := corpusDisputed[corpusDisputedKey(c)]; ok {
			disputed = append(disputed, fmt.Sprintf("#%d %s: %s", c.ID, c.Name, reason))
			continue
		}
		bucket := c.HandlerType
		detected := outcomes[idx].xss
		if corpusEncodedReflection(c) {
			bucket = "encoded " + c.HandlerType
			// An expected reflection counts the informational note too. An expected
			// clean case counts only an executable finding, since the note is
			// informational and not a claim of XSS.
			if c.ExpectedDetection {
				detected = outcomes[idx].reflected || outcomes[idx].xss
			}
		}
		s := scores[bucket]
		if s == nil {
			s = &corpusScore{}
			scores[bucket] = s
		}
		label := fmt.Sprintf("#%d %s (%s)", c.ID, c.Name, c.File)
		if detected && !c.ExpectedDetection {
			label += " <- " + outcomes[idx].hit
		}
		switch {
		case outcomes[idx].err != nil:
			s.errs++
		case c.ExpectedDetection && detected:
			s.tp++
		case c.ExpectedDetection && !detected:
			s.fn++
			s.missed = append(s.missed, label)
		case !c.ExpectedDetection && detected:
			s.fp++
			s.falsePos = append(s.falsePos, label)
		default:
			s.tn++
		}
	}

	for _, bucket := range []string{"query", "realworld", "body", "dom_xss", "encoded query", "encoded realworld", "encoded body"} {
		s := scores[bucket]
		if s == nil {
			continue
		}
		total := s.tp + s.fn + s.fp + s.tn
		recall := ratio(s.tp, s.tp+s.fn)
		precision := ratio(s.tp, s.tp+s.fp)
		t.Logf("%-18s cases=%3d  recall=%5.1f%% (%d/%d)  precision=%5.1f%% (%d FP)  errors=%d",
			bucket, total, recall, s.tp, s.tp+s.fn, precision, s.fp, s.errs)
		for _, m := range s.missed {
			t.Logf("  missed: %s", m)
		}
		for _, m := range s.falsePos {
			t.Logf("  false positive: %s", m)
		}
	}
	t.Logf("skipped (no injection point in scanner): %v; out of scope (vulnerable-library cases): %d", skipped, outOfScope)
	for _, d := range disputed {
		t.Logf("disputed (not scored): %s", d)
	}
}

// ratio returns num/den as a percentage, or 100 when there is nothing to score.
func ratio(num, den int) float64 {
	if den == 0 {
		return 100
	}
	return 100 * float64(num) / float64(den)
}
