package xss

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPayloadExecutesByContext checks the central decision: a payload that
// appears verbatim only executes where the browser parses it as code.
func TestPayloadExecutesByContext(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		payload string
		want    bool
	}{
		{"markup in text executes", `<p>hi <script>alert(1)</script></p>`, `<script>alert(1)</script>`, true},
		{"markup inside a comment is inert", `<!-- note: <script>alert(1)</script> -->`, `<script>alert(1)</script>`, false},
		{"markup inside textarea is inert", `<textarea><script>alert(1)</script></textarea>`, `<script>alert(1)</script>`, false},
		{"markup inside title is inert", `<title><script>alert(1)</script></title>`, `<script>alert(1)</script>`, false},
		{"breakout closes the attribute", `<input value="" autofocus onfocus=alert(1) x="">`, `" autofocus onfocus=alert(1) x="`, true},
		{"script stays inside a quoted attribute", `<input value="<script>alert(1)</script>">`, `<script>alert(1)</script>`, false},
		{"string breakout inside script runs", `<script>var q = "";alert(1);"";</script>`, `";alert(1);"`, true},
		{"plain text in script without quotes runs", `<script>var q = ;alert(1);</script>`, `alert(1)`, true},
		{"text payload without markup stays text", `<p>javascript:alert(1)</p>`, `javascript:alert(1)`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := payloadExecutes(tc.body, tc.payload); got != tc.want {
				t.Errorf("payloadExecutes = %v, want %v (context %s)", got, tc.want, locateContext(tc.body, tc.payload))
			}
		})
	}
}

// TestHTMLResponseGate checks the content-type gate: only HTML executes.
func TestHTMLResponseGate(t *testing.T) {
	for ct, want := range map[string]bool{
		"text/html; charset=utf-8": true,
		"application/xhtml+xml":    true,
		"":                         true,
		"application/json":         false,
		"text/plain":               false,
		"image/png":                false,
	} {
		if got := htmlResponse(ct); got != want {
			t.Errorf("htmlResponse(%q) = %v, want %v", ct, got, want)
		}
	}
}

// TestVerifyPayloadSetsMarkerInsteadOfAlert checks the browser-replay rewrite:
// the breakout is kept, and alert() becomes a DOM write carrying the canary.
func TestVerifyPayloadSetsMarkerInsteadOfAlert(t *testing.T) {
	const canary = "apxss123abc"
	got := verifyPayload(`<script>/*apxss123abc*/alert(document.domain)</script>`, canary)
	if strings.Contains(got, "alert(") {
		t.Errorf("alert survived the rewrite: %s", got)
	}
	want := fmt.Sprintf("document.documentElement.setAttribute(`%s`,`%s`)", verifyMarkerAttr, canary)
	if !strings.Contains(got, want) {
		t.Errorf("rewrite missing marker write; got %s", got)
	}
	if !strings.HasPrefix(got, "<script>") {
		t.Errorf("breakout changed: %s", got)
	}
}

// TestVerifyPayloadKeepsSingleQuotedBreakoutValid checks that the marker
// setter does not use single quotes, so a breakout out of a single-quoted JS
// string is still valid after the rewrite.
func TestVerifyPayloadKeepsSingleQuotedBreakoutValid(t *testing.T) {
	payload := `';alert(/*apxss1*/document.domain);'`
	got := verifyPayload(payload, "apxss1")
	// The payload's own quotes are the only single quotes allowed after the rewrite.
	if strings.Count(got, "'") != strings.Count(payload, "'") {
		t.Errorf("setter added single quotes that would cut the JS string short: %s", got)
	}
}

// TestVerifyPayloadRewritesTaggedTemplateAlert checks that alert`...` (no
// parentheses) is rewritten too, so the browser check can still confirm it.
func TestVerifyPayloadRewritesTaggedTemplateAlert(t *testing.T) {
	got := verifyPayload("<img src=x onerror=alert`/*apxss2*/document.domain`>", "apxss2")
	if strings.Contains(got, "alert") {
		t.Errorf("tagged-template alert survived the rewrite: %s", got)
	}
}

// TestNeutralizeRemovesEveryBreakout checks that the negative control cannot
// break out of any context.
func TestNeutralizeRemovesEveryBreakout(t *testing.T) {
	got := neutralize(`"><script>alert('x')</script>`)
	for _, bad := range []string{"<", ">", `"`, "'"} {
		if strings.Contains(got, bad) {
			t.Errorf("neutralized payload still contains %q: %s", bad, got)
		}
	}
}

// fakeChrome installs a stand-in headless browser on PATH. It writes the
// marker into its output only when the URL it was given contains the
// rewritten setter and not the neutralized markup, which is how a real
// browser would behave for a working injection and its control.
func fakeChrome(t *testing.T, canary string, emitMarker bool) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n"
	if emitMarker {
		// The last argument is the URL. The control URL carries "%26lt%3B"
		// (an encoded "&lt;") and must not produce the marker.
		script += `for last; do :; done
case "$last" in
  *%26lt%3B*) ;;
  *setAttribute*) echo "<html data-apx=\"$APX_CANARY\"></html>" ;;
esac
`
	}
	path := filepath.Join(dir, "chromium")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("APX_CANARY", canary)
}

// TestVerifyPointFindingConfirmsWithBrowser checks that a payload which runs in
// the browser, while its neutralized control does not, is upgraded to confirmed.
func TestVerifyPointFindingConfirmsWithBrowser(t *testing.T) {
	const canary = "apxss00aa11"
	fakeChrome(t, canary, true)

	payload := `<script>/*apxss00aa11*/alert(document.domain)</script>`
	pf := pointFinding{
		param:       "q",
		payload:     payload,
		browserable: true,
		finding: Finding{
			Label:      "reflected",
			Confidence: ConfidenceLikely,
			Request:    &CapturedRequest{Method: "GET", URL: "http://example.test/search?q=x"},
		},
	}
	got := verifyPointFinding(context.Background(), pf, canary)
	if got.finding.Confidence != ConfidenceConfirmed {
		t.Errorf("confidence = %q, want confirmed; detail: %s", got.finding.Confidence, got.finding.Detail)
	}
}

// TestVerifyPointFindingStaysLikelyWithoutBrowser checks the honest fallback:
// when no browser can run, the finding keeps its static confidence and says so.
func TestVerifyPointFindingStaysLikelyWithoutBrowser(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // no browser on PATH at all
	pf := pointFinding{
		param:       "q",
		payload:     `<script>alert(1)</script>`,
		browserable: true,
		finding: Finding{
			Confidence: ConfidenceLikely,
			Request:    &CapturedRequest{Method: "GET", URL: "http://example.test/?q=x"},
		},
	}
	got := verifyPointFinding(context.Background(), pf, "apxss000000")
	if got.finding.Confidence != ConfidenceLikely {
		t.Errorf("confidence = %q, want likely when no browser is available", got.finding.Confidence)
	}
	if !strings.Contains(got.finding.Detail, "Not executed in a browser") {
		t.Errorf("detail does not explain the missing browser: %s", got.finding.Detail)
	}
}

// TestNonHTMLAndTextareaReflectionsAreNotFindings runs the whole scanner
// against endpoints that echo input in ways a browser never runs: a JSON body,
// a download, and a textarea whose markup characters are encoded. None may
// produce a confirmed or likely injection.
func TestNonHTMLAndTextareaReflectionsAreNotFindings(t *testing.T) {
	withoutBrowser(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		switch r.URL.Path {
		case "/json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"echo":%q}`, q)
		case "/download":
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Disposition", "attachment; filename=out.html")
			fmt.Fprint(w, q)
		case "/encoded-textarea":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><body><textarea name="x">%s</textarea></body></html>`, htmlEscape(q))
		}
	}))
	defer srv.Close()

	for _, path := range []string{"/json", "/download", "/encoded-textarea"} {
		res, err := Run(context.Background(), Request{URL: srv.URL + path + "?q=seed", RecursionDepth: 0})
		if err != nil {
			t.Fatalf("Run(%s): %v", path, err)
		}
		for _, m := range res.Modules {
			if m.ID == "reflected-escaped" || m.ID == "dom-xss-sink" {
				continue
			}
			for _, f := range m.Findings {
				t.Errorf("%s: module %s reported %q (confidence %q) for a non-executing reflection",
					path, m.ID, f.Label, f.Confidence)
			}
		}
	}
}
