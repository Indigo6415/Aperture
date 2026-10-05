package xss

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// htmlEscape encodes a value the way a safe HTML text or attribute sink would.
var htmlEscape = html.EscapeString

// jsEscape encodes every byte that is not alphanumeric as a \xNN escape, so the
// value stays inert inside a JS string or template literal.
func jsEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isAlnum(c) {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, `\x%02x`, c)
		}
	}
	return b.String()
}

// withoutBrowser hides every headless browser from PATH, so a Run-based test
// judges findings statically and never launches Chrome.
func withoutBrowser(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
}

// TestPayloadExecutesInParserStates is the table of contexts the parser-state
// check must get right: markup, quoted and unquoted attributes, javascript:
// URLs, comments, raw-text elements, and every script sub-state. Each case
// places the payload at one exact spot in body.
func TestPayloadExecutesInParserStates(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		payload string
		want    bool
	}{
		// Comments: the payload must close the comment itself to run.
		{"comment breakout executes", `<!-- note: PAYLOAD -->`, `--><script>alert(1)</script>`, true},
		{"markup inside a comment with no closer stays inert", `<!-- note: PAYLOAD -->`, `<img src=x onerror=alert(1)>`, false},
		{"bogus comment breakout", `<!DOCTYPE html PAYLOAD>`, `><img src=x onerror=alert(1)>`, true},
		// One occurrence in a comment (inert) and one in text (live) is still a finding.
		{"second occurrence executes", `<!-- <img src=x onerror=alert(1)> --><p><img src=x onerror=alert(1)></p>`, `<img src=x onerror=alert(1)>`, true},

		// Raw-text elements: the payload must write the element's own end tag.
		{"raw-text breakout executes", `<textarea>PAYLOAD</textarea>`, `</textarea><svg onload=alert(1)>`, true},
		{"raw-text breakout matches the right element", `<title>PAYLOAD</title>`, `</textarea><svg onload=alert(1)>`, false},
		{"markup inside a title stays inert", `<title><img src=x onerror=alert(1)></title>`, `<img src=x onerror=alert(1)>`, false},
		{"end tag that is only a prefix does not close", `<textarea>PAYLOAD</textarea>`, `</textareas><svg onload=alert(1)>`, false},

		// Quoted attribute values.
		{"quote breakout adds a handler", `<input value="" autofocus onfocus=alert(1) x="">`, `" autofocus onfocus=alert(1) x="`, true},
		{"quote breakout without a handler is text", `<input value="PAYLOAD">`, `" x="y`, false},
		{"markup inside a quoted value stays inert", `<input value="PAYLOAD">`, `<img src=x onerror=alert(1)>`, false},

		// Unquoted attribute values end at whitespace.
		{"unquoted breakout adds a handler", `<input value=PAYLOAD>`, ` autofocus onfocus=alert(1) x=`, true},
		{"unquoted value with no handler is text", `<input value=PAYLOAD>`, ` class=x`, false},

		// javascript: URLs run only as the whole value of a URL attribute.
		{"javascript URL as the whole href", `<a href="PAYLOAD">x</a>`, `javascript:alert(1)`, true},
		{"javascript URL in a title is text", `<a title="PAYLOAD">x</a>`, `javascript:alert(1)`, false},
		{"javascript URL not at the start of the value", `<a href="/x?n=PAYLOAD">x</a>`, `javascript:alert(1)`, false},

		// Script bodies: string literals, template literals, comments, and end tags.
		{"string breakout inside double quotes", `<script>var q = "PAYLOAD";</script>`, `";alert(1);"`, true},
		{"single-quote breakout inside double quotes is inert", `<script>var q = "PAYLOAD";</script>`, `';alert(1);'`, false},
		{"double-quote breakout inside single quotes is inert", `<script>var q = 'PAYLOAD';</script>`, `";alert(1);"`, false},
		{"template interpolation runs in a template literal", "<script>var t = `PAYLOAD`;</script>", "${alert(1)}", true},
		{"template interpolation inert in a double-quoted string", `<script>var t = "PAYLOAD";</script>`, "${alert(1)}", false},
		{"script tag inside script code is inert", `<script>var x = PAYLOAD;</script>`, `<script>alert(1)</script>`, false},
		{"end tag breaks out of script code", `<script>var x = PAYLOAD;</script>`, `</script><img src=x onerror=alert(1)>`, true},
		{"code inside a line comment is inert", "<script>// PAYLOAD\n</script>", `alert(1)`, false},
		{"code inside a block comment is inert", `<script>/* PAYLOAD */</script>`, `alert(1)`, false},
		{"block comment breakout runs code", `<script>/* PAYLOAD */</script>`, `*/alert(1)/*`, true},

		// Plain text: only markup runs.
		{"markup in text executes", `<p>hi <script>alert(1)</script></p>`, `<script>alert(1)</script>`, true},
		{"text payload without markup stays text", `<p>PAYLOAD</p>`, `javascript:alert(1)`, false},
		{"less-than sign is not markup", `<p>PAYLOAD</p>`, `a < b`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// PAYLOAD marks where the reflection lands. Cases that already contain
			// the payload literally have no marker, so they are left as written.
			body := strings.Replace(tc.body, "PAYLOAD", tc.payload, 1)
			if got := payloadExecutes(body, tc.payload); got != tc.want {
				t.Errorf("payloadExecutes = %v, want %v (state %+v)", got, tc.want, stateAt(body, max(strings.Index(body, tc.payload), 0)))
			}
		})
	}
}

// TestStateAtTracksEscapedQuotes checks that a backslash-escaped quote inside a
// script string does not end the string, so the state stays inside it.
func TestStateAtTracksEscapedQuotes(t *testing.T) {
	body := `<script>var s = "a\"PAYLOAD";</script>`
	st := stateAt(body, strings.Index(body, "PAYLOAD"))
	if st.kind != ctxScript || st.quote != '"' {
		t.Errorf("state = %+v, want an open double-quoted string in a script", st)
	}
}

// TestStateAtClosesRawTextOnlyAtItsEndTag checks that an end tag which is only
// a prefix of the element name (</titles> for <title>) leaves the element open.
func TestStateAtClosesRawTextOnlyAtItsEndTag(t *testing.T) {
	body := `<title>a</titles>PAYLOAD`
	if st := stateAt(body, strings.Index(body, "PAYLOAD")); st.kind != ctxRawText {
		t.Errorf("state = %s, want raw-text still open", st.kind)
	}
	body = `<title>a</title>PAYLOAD`
	if st := stateAt(body, strings.Index(body, "PAYLOAD")); st.kind != ctxText {
		t.Errorf("state = %s, want text after the end tag", st.kind)
	}
}

// TestRendersAsHTMLRejectsAttachments checks the download gate: an HTML
// response sent as an attachment is saved, not rendered.
func TestRendersAsHTMLRejectsAttachments(t *testing.T) {
	cases := []struct {
		ct, disposition string
		want            bool
	}{
		{"text/html; charset=utf-8", "", true},
		{"text/html", "inline", true},
		{"text/html", "attachment; filename=x.html", false},
		{"application/json", "", false},
	}
	for _, tc := range cases {
		if got := rendersAsHTML(tc.ct, tc.disposition); got != tc.want {
			t.Errorf("rendersAsHTML(%q, %q) = %v, want %v", tc.ct, tc.disposition, got, tc.want)
		}
	}
}

// injectionTemplate is one reflection shape a page can use. raw is the
// unencoded page, which should yield a finding in one of the modules named in
// want. safe is the same shape with the input encoded for that context, which
// should yield none.
type injectionTemplate struct {
	name   string
	raw    string
	safe   string
	escape func(string) string
	want   []string
}

// injectionTemplates covers the new contexts and the older ones they extend.
var injectionTemplates = []injectionTemplate{
	{
		name: "textarea", raw: `<html><body><textarea>%s</textarea></body></html>`,
		safe: `<html><body><textarea>%s</textarea></body></html>`, escape: htmlEscape,
		want: []string{"rawtext-breakout"},
	},
	{
		name: "unquoted attribute", raw: `<html><body><input value=%s></body></html>`,
		safe: `<html><body><input value="%s"></body></html>`, escape: htmlEscape,
		want: []string{"unquoted-attribute-breakout"},
	},
	{
		name: "template literal", raw: "<html><body><script>var t = `%s`;</script></body></html>",
		safe: `<html><body><script>var t = "%s";</script></body></html>`, escape: jsEscape,
		want: []string{"js-template-literal-interpolation", "js-template-literal-breakout"},
	},
	{
		name: "html comment", raw: `<html><!-- %s --></html>`,
		safe: `<html><!-- %s --></html>`, escape: htmlEscape,
		want: []string{"html-comment-breakout"},
	},
	{
		name: "href", raw: `<html><body><a href="%s">x</a></body></html>`,
		safe: `<html><body><a href="%s">x</a></body></html>`, escape: url.QueryEscape,
		want: []string{"javascript-uri"},
	},
	{
		name: "js string", raw: `<html><body><script>var q = "%s";</script></body></html>`,
		safe: `<html><body><script>var q = "%s";</script></body></html>`, escape: jsEscape,
		want: []string{"js-string-breakout-dquote"},
	},
}

// payloadDefByID returns the payload module with id, failing the test if absent.
func payloadDefByID(t *testing.T, id string) payloadDef {
	t.Helper()
	for _, m := range payloadModules {
		if m.id == id {
			return m
		}
	}
	t.Fatalf("payload module %q missing", id)
	return payloadDef{}
}

// TestModulePayloadsExecuteInTheirContext checks each module that a reflection
// shape names, on its own: its payload, placed in that shape, must be judged
// executable and matched. This is deterministic, unlike a full Run, where a
// point one module confirms is skipped by the others.
func TestModulePayloadsExecuteInTheirContext(t *testing.T) {
	const canary = "apxss0123abcd"
	for _, tpl := range injectionTemplates {
		for _, id := range tpl.want {
			m := payloadDefByID(t, id)
			payload := m.build(canary)
			body := fmt.Sprintf(tpl.raw, payload)
			evidence, ok := m.match(body, payload, canary)
			if !ok {
				t.Errorf("%s: payload not reflected verbatim in the %s context", id, tpl.name)
				continue
			}
			if !payloadExecutes(body, payload) {
				t.Errorf("%s: payload judged inert in the %s context (evidence %q)", id, tpl.name, evidence)
			}
		}
	}
}

// TestRunFindsNewContexts runs the whole scanner against each reflection shape,
// once raw and once encoded. Raw must produce at least one executable finding,
// and encoded must produce none. A raw point is attributed to whichever module
// confirms it first, so this test checks the outcome, not the module name (see
// TestModulePayloadsExecuteInTheirContext for the per-module checks).
func TestRunFindsNewContexts(t *testing.T) {
	withoutBrowser(t)
	byPath := map[string]injectionTemplate{}
	for _, tpl := range injectionTemplates {
		byPath["/raw/"+strings.ReplaceAll(tpl.name, " ", "-")] = tpl
		byPath["/safe/"+strings.ReplaceAll(tpl.name, " ", "-")] = tpl
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tpl, ok := byPath[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		if strings.HasPrefix(r.URL.Path, "/raw/") {
			fmt.Fprintf(w, tpl.raw, q)
			return
		}
		fmt.Fprintf(w, tpl.safe, tpl.escape(q))
	}))
	defer srv.Close()

	for _, tpl := range injectionTemplates {
		slug := strings.ReplaceAll(tpl.name, " ", "-")
		t.Run("raw "+tpl.name, func(t *testing.T) {
			res, err := Run(context.Background(), Request{URL: srv.URL + "/raw/" + slug + "?q=seed"}, OOBConfig{})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if !anyFinding(res) {
				t.Errorf("no module reported the raw %s reflection (expected one of %v)", tpl.name, tpl.want)
			}
		})
		t.Run("safe "+tpl.name, func(t *testing.T) {
			res, err := Run(context.Background(), Request{URL: srv.URL + "/safe/" + slug + "?q=seed"}, OOBConfig{})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			for _, m := range res.Modules {
				if m.ID == "reflected-escaped" || m.ID == "dom-xss-sink" {
					continue
				}
				for _, f := range m.Findings {
					t.Errorf("module %s reported %q for an encoded %s reflection", m.ID, f.Label, tpl.name)
				}
			}
		})
	}
}

// anyFinding reports whether any payload module (not the informational notes)
// reported a finding in res.
func anyFinding(res *Result) bool {
	for _, m := range res.Modules {
		if m.ID != "reflected-escaped" && m.ID != "dom-xss-sink" && len(m.Findings) > 0 {
			return true
		}
	}
	return false
}

// TestDomSinkModuleReadsExternalScripts checks the DOM-sink module against
// same-origin external scripts: a tainted source reaching a sink is reported,
// a sanitized one is not, and a message-event source counts. A cross-origin
// script is never fetched.
func TestDomSinkModuleReadsExternalScripts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><script src="/app.js"></script><script src="/safe.js"></script>`+
				`<script src="/msg.js"></script><script src="https://other.example/x.js"></script></html>`)
		case "/app.js":
			fmt.Fprint(w, `var h = location.hash; document.getElementById("x").innerHTML = h;`)
		case "/safe.js":
			fmt.Fprint(w, `var h = location.hash; document.getElementById("x").innerHTML = DOMPurify.sanitize(h);`)
		case "/msg.js":
			fmt.Fprint(w, `window.addEventListener("message", function(e) { document.write(e.data); });`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	seed, _ := url.Parse(srv.URL + "/")
	cr, err := crawl(context.Background(), srv.Client(), seed, Request{URL: srv.URL + "/", MaxPages: 5})
	if err != nil {
		t.Fatalf("crawl: %v", err)
	}
	findings := runDomSinkModule(cr.Pages)

	var sawApp, sawMsg, sawSafe, sawOther bool
	for _, f := range findings {
		switch {
		case strings.Contains(f.Detail, "/app.js"):
			sawApp = true
		case strings.Contains(f.Detail, "/msg.js"):
			sawMsg = true
		case strings.Contains(f.Detail, "/safe.js"):
			sawSafe = true
		case strings.Contains(f.Detail, "other.example"):
			sawOther = true
		}
		if f.Confidence != ConfidenceHeuristic {
			t.Errorf("DOM finding confidence = %q, want heuristic", f.Confidence)
		}
	}
	if !sawApp {
		t.Errorf("location.hash into innerHTML in /app.js was not reported")
	}
	if !sawMsg {
		t.Errorf("message-event source into document.write in /msg.js was not reported")
	}
	if sawSafe {
		t.Errorf("sanitized sink in /safe.js was reported")
	}
	if sawOther {
		t.Errorf("cross-origin script was read")
	}
}
