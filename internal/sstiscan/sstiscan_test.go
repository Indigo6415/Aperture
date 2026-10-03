package sstiscan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
	body := "TemplateSyntaxError from jinja2.exceptions and PebbleException"
	first, _ := firstErrorSignature(body, "")
	for i := 0; i < 200; i++ {
		if got, _ := firstErrorSignature(body, ""); got != first {
			t.Fatalf("engine changed between calls: %q then %q", first, got)
		}
	}
}

// renderServer evaluates the math payloads the way a vulnerable template engine
// would, and echoes everything else. Set static to make the page print the
// product regardless of input, which is the false-positive case.
func renderServer(static bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		if static {
			fmt.Fprint(w, "<p>Order total: 9801547</p>")
			return
		}
		switch q {
		case "{{1337*7331}}":
			fmt.Fprint(w, "<p>9801547</p>")
		case "{{11*'7'}}":
			fmt.Fprint(w, "<p>77777777777</p>")
		default:
			fmt.Fprintf(w, "<p>%s</p>", q)
		}
	}))
}

// mathPoint is a query-parameter injection point on the given server.
func mathPoint(srv *httptest.Server) injectionPoint {
	return injectionPoint{Kind: kindQuery, URL: srv.URL + "/render", Method: "GET", Param: "q", Defaults: url.Values{"q": {"x"}}}
}

// TestMathEvalConfirmsRealEvaluation checks that an engine which evaluates the
// expression is confirmed, and that the Jinja2 string-multiply probe relabels it.
func TestMathEvalConfirmsRealEvaluation(t *testing.T) {
	srv := renderServer(false)
	defer srv.Close()
	deps := runDeps{points: []injectionPoint{mathPoint(srv)}, sem: make(chan struct{}, 4), baseline: "<p>x</p>"}

	findings := runMathEvalModule(context.Background(), deps)
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

// TestMathEvalIgnoresPagesThatPrintTheNumber checks the two false-positive
// controls: a number already on the original page, and a page that prints the
// product for any input.
func TestMathEvalIgnoresPagesThatPrintTheNumber(t *testing.T) {
	srv := renderServer(true)
	defer srv.Close()

	// The number is on the baseline page, so it is not evaluated output.
	deps := runDeps{points: []injectionPoint{mathPoint(srv)}, sem: make(chan struct{}, 4), baseline: "<p>9801547</p>"}
	if got := runMathEvalModule(context.Background(), deps); len(got) != 0 {
		t.Errorf("number on the baseline was reported: %+v", got)
	}

	// The baseline does not show it, but the neutral control does: the page
	// prints the product on its own, so it is not template evaluation either.
	deps.baseline = "<p>nothing</p>"
	if got := runMathEvalModule(context.Background(), deps); len(got) != 0 {
		t.Errorf("page that prints the number regardless of input was reported: %+v", got)
	}
}
