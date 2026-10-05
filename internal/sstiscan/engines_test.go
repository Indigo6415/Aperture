package sstiscan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// arithTag matches the inside of a {{ a*b }} tag that the tag engine below
// will evaluate. It is anchored, so a tag that also holds other text is not
// evaluated.
var arithTag = regexp.MustCompile(`^\s*(\d+)\s*\*\s*(\d+)\s*$`)

// renderArithTags is a minimal Jinja-like renderer. It walks the template one
// {{ ... }} tag at a time, from the first "{{" to the next "}}", and evaluates
// a tag only when its inside is a bare product. Anything else is kept as
// written. That makes it behave like a real engine for the cases these tests
// care about: a payload sent bare sits inside a longer tag and is not
// evaluated, while the same payload after a closing escape is.
func renderArithTags(src string) string {
	var b strings.Builder
	// Each pass consumes one tag, so the loop ends when no "{{" is left.
	for {
		start := strings.Index(src, "{{")
		if start < 0 {
			break
		}
		end := strings.Index(src[start+2:], "}}")
		if end < 0 {
			break
		}
		end += start + 2
		b.WriteString(src[:start])
		inner := src[start+2 : end]
		if m := arithTag.FindStringSubmatch(inner); m != nil {
			fmt.Fprint(&b, atoi(m[1])*atoi(m[2]))
		} else {
			b.WriteString(src[start : end+2])
		}
		src = src[end+2:]
	}
	b.WriteString(src)
	return b.String()
}

// tagEngine serves tpl with the query value put where "%s" sits, then renders
// the result with renderArithTags. The output is wrapped in <p> so it looks
// like a real page.
func tagEngine(tpl string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		in := r.URL.Query().Get("q")
		body := strings.Replace(tpl, "%s", in, 1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<p>%s</p>", renderArithTags(body))
	}
}

// contextPoint returns a query point on srv, plus a baseline fetched from it,
// the same way Run prepares a scan before any module runs.
func contextPoint(t *testing.T, srv *httptest.Server) (injectionPoint, string) {
	t.Helper()
	pt := injectionPoint{Kind: kindQuery, URL: srv.URL + "/render", Method: "GET", Param: "q", Defaults: url.Values{"q": {"x"}}}
	base := fetchPlain(context.Background(), newClient(), srv.URL+"/render?q=x", nil)
	if base.Err != nil {
		t.Fatalf("baseline fetch failed: %v", base.Err)
	}
	return pt, base.Body
}

// TestExpandClosuresShortestFirst checks the level-1 closure matrix against
// tplmap's: six escapes, the shortest first, and no duplicates.
func TestExpandClosuresShortestFirst(t *testing.T) {
	got := expandClosures(level1Closures)
	want := []string{"1", "1'", `1"`, "1)", "1')", `1")`}
	if len(got) != len(want) {
		t.Fatalf("got %d closures %q, want %d", len(got), got, len(want))
	}
	if got[0] != "1" {
		t.Errorf("first closure = %q, want the shortest %q", got[0], "1")
	}
	// Compare as sets, since the order within one length is not part of the
	// contract.
	have := map[string]bool{}
	for _, c := range got {
		have[c] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("closure %q missing from %q", w, got)
		}
	}
}

// TestExpandClosuresEmpty checks that a context with no closure matrix still
// yields one empty escape, so its prefix is sent exactly once.
func TestExpandClosuresEmpty(t *testing.T) {
	if got := expandClosures(nil); len(got) != 1 || got[0] != "" {
		t.Errorf("expandClosures(nil) = %q, want one empty escape", got)
	}
}

// TestJinjaVariantsCarryEscapeIntoPrefix checks that every variant for a
// Jinja2 probe has its closure written into the prefix, and that the text
// context is still first.
func TestJinjaVariantsCarryEscapeIntoPrefix(t *testing.T) {
	var jinja tplProbe
	for _, p := range tplProbes() {
		if p.jinjaFamily {
			jinja = p
			break
		}
	}
	vs := jinja.variants()
	if len(vs) == 0 || vs[0].prefix != "" || vs[0].closure != "" {
		t.Fatalf("first variant must be the text context, got %+v", vs)
	}
	wantPrefixes := map[string]bool{"1}}": false, "1'}}": false, "1)%}": false}
	for _, v := range vs {
		if _, ok := wantPrefixes[v.prefix]; ok {
			wantPrefixes[v.prefix] = true
		}
		if strings.Contains(v.prefix, closureSlot) {
			t.Errorf("prefix %q still holds the unfilled closure slot", v.prefix)
		}
	}
	for prefix, seen := range wantPrefixes {
		if !seen {
			t.Errorf("no variant with prefix %q", prefix)
		}
	}
}

// TestContextPayloadEvaluatesOnlyAfterEscape checks the property the context
// table exists for: the same expression is inert as bare text, but evaluates
// once the injected value closes the tag around it.
func TestContextPayloadEvaluatesOnlyAfterEscape(t *testing.T) {
	const bare = "{{1234*5678}}"
	if got := renderArithTags("{{ '" + bare + "' }}"); strings.Contains(got, "7006652") {
		t.Fatalf("bare payload inside a string literal was evaluated: %q", got)
	}
	if got := renderArithTags("{{ '1'}}" + bare + "' }}"); !strings.Contains(got, "7006652") {
		t.Fatalf("payload after a closing escape was not evaluated: %q", got)
	}
}

// TestContextEscapeFindsEvaluationInsideTag runs the math-eval module against
// engines that only evaluate an expression after the input closes the tag it
// was placed in. Plain text injection cannot find these, which is why the
// context table exists.
func TestContextEscapeFindsEvaluationInsideTag(t *testing.T) {
	cases := []struct {
		name, tpl string
	}{
		{"inside a function call", `{{ "1"|join(%s) }}`},
		{"inside a single-quoted string", `{{ '%s' }}`},
		{"inside a double-quoted string", `{{ "%s" }}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(tagEngine(c.tpl))
			t.Cleanup(srv.Close)
			pt, baseline := contextPoint(t, srv)
			deps := runDeps{points: []injectionPoint{pt}, sem: make(chan struct{}, 4), baseline: baseline}
			findings := runMathEvalModule(context.Background(), deps)
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
			}
			if !strings.Contains(findings[0].Detail, "from inside an existing template tag") {
				t.Errorf("detail does not name the escaped context: %q", findings[0].Detail)
			}
			if findings[0].Confidence != ConfidenceConfirmed {
				t.Errorf("confidence = %q, want confirmed", findings[0].Confidence)
			}
		})
	}
}

// TestContextEscapeNotReportedWhenBracesStripped checks the negative side: a
// server that removes braces from input can't evaluate anything in any
// context, so no escape should be reported.
func TestContextEscapeNotReportedWhenBracesStripped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		in := strings.NewReplacer("{", "", "}", "").Replace(r.URL.Query().Get("q"))
		fmt.Fprintf(w, "<p>%s</p>", renderArithTags(strings.Replace(`{{ '%s' }}`, "%s", in, 1)))
	}))
	t.Cleanup(srv.Close)
	pt, baseline := contextPoint(t, srv)
	deps := runDeps{points: []injectionPoint{pt}, sem: make(chan struct{}, 4), baseline: baseline}
	if findings := runMathEvalModule(context.Background(), deps); len(findings) != 0 {
		t.Errorf("brace-stripping server was reported: %+v", findings)
	}
}

// TestContextEscapeNotReportedForPlainEcho checks that a page that echoes the
// input inside a tag without evaluating anything is not reported, even though
// the input can reach a tag.
func TestContextEscapeNotReportedForPlainEcho(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<p>{{ '%s' }}</p>", r.URL.Query().Get("q"))
	}))
	t.Cleanup(srv.Close)
	pt, baseline := contextPoint(t, srv)
	deps := runDeps{points: []injectionPoint{pt}, sem: make(chan struct{}, 4), baseline: baseline}
	if findings := runMathEvalModule(context.Background(), deps); len(findings) != 0 {
		t.Errorf("plain echo inside a tag was reported: %+v", findings)
	}
}

// echoingShellServer simulates an engine whose command-execution payload runs:
// when the query holds a popen("echo WORD") call it prints WORD back. Any
// other input is reflected verbatim, so a reflected payload is not a shell.
func echoingShellServer(execute bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if _, after, found := strings.Cut(q, "echo "); execute && strings.Contains(q, "popen(") && found {
			fmt.Fprintf(w, "<p>%s</p>", leadingLetters(after))
			return
		}
		fmt.Fprintf(w, "<p>%s</p>", q)
	}
}

// leadingLetters returns the run of ASCII letters at the start of s, which is
// how the marker word ends inside the surrounding payload.
func leadingLetters(s string) string {
	// Stop at the first character that is not a letter.
	for i, c := range s {
		if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') {
			return s[:i]
		}
	}
	return s
}

// TestInBandRCEConfirmsEchoedCommandOutput checks that an engine running the
// echo command and printing its output is confirmed in-band, with no callback.
func TestInBandRCEConfirmsEchoedCommandOutput(t *testing.T) {
	srv := httptest.NewServer(echoingShellServer(true))
	t.Cleanup(srv.Close)
	pt, baseline := contextPoint(t, srv)
	deps := runDeps{points: []injectionPoint{pt}, sem: make(chan struct{}, 4), baseline: baseline}
	findings := runInBandRCEModule(context.Background(), deps)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	if findings[0].Confidence != ConfidenceConfirmed || findings[0].Evidence == "" {
		t.Errorf("finding = %+v, want confirmed with the marker as evidence", findings[0])
	}
}

// TestInBandRCENotReportedForReflection checks the marker rule: a page that
// only reflects the payload also contains the marker, and must not pass.
func TestInBandRCENotReportedForReflection(t *testing.T) {
	srv := httptest.NewServer(echoingShellServer(false))
	t.Cleanup(srv.Close)
	pt, baseline := contextPoint(t, srv)
	deps := runDeps{points: []injectionPoint{pt}, sem: make(chan struct{}, 4), baseline: baseline}
	if findings := runInBandRCEModule(context.Background(), deps); len(findings) != 0 {
		t.Errorf("reflected payload was reported as command output: %+v", findings)
	}
}

// TestNewProbesKeepLabels checks that the table port kept every engine label
// the existing finding names and tests rely on.
func TestNewProbesKeepLabels(t *testing.T) {
	want := map[string]bool{}
	for _, p := range sstiProbes() {
		want[p.engine] = true
	}
	for _, p := range tplProbes() {
		if !want[p.engine] {
			t.Errorf("tplProbes label %q has no sstiProbes counterpart", p.engine)
		}
	}
	if len(tplProbes()) != len(sstiProbes()) {
		t.Errorf("tplProbes has %d entries, sstiProbes has %d", len(tplProbes()), len(sstiProbes()))
	}
}
