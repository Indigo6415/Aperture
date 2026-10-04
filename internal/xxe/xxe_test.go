package xxe

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/Indigo6415/Aperture/internal/collaborator"
)

// entityRefPattern finds the entity references a payload places in the text.
var entityRefPattern = regexp.MustCompile(`&([A-Za-z_][\w.-]*);`)

// entityDeclPattern finds entity declarations in a DOCTYPE, general or
// parameter, with either a SYSTEM identifier or an inline value.
var entityDeclPattern = regexp.MustCompile(`<!ENTITY\s+(%\s+)?(\w+)\s+(?:SYSTEM\s+"([^"]+)"|"([^"]*)")\s*>`)

// fakeParser stands in for an XML endpoint whose parser resolves DOCTYPE
// entities. Go's own encoding/xml doesn't fetch external entities, so these
// tests need a stub that does the work the real parsers would. Each mode
// models one kind of target:
//   - "vuln": resolves files and echoes the result back.
//   - "echo": returns the request verbatim, so a payload only ever shows up in
//     the response as an echo.
//   - "oob": also fetches any external entity URL, the way a parser does when
//     it reaches out to the network.
//   - "hardened": rejects any DOCTYPE outright.
func fakeParser(mode string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body := string(raw)

		// The plain-text control is answered without parsing, the way a
		// generic endpoint would.
		if strings.HasPrefix(r.Header.Get("Content-Type"), "text/plain") {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "plain ok")
			return
		}
		if mode == "hardened" && strings.Contains(body, "<!DOCTYPE") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "XML parse error: DOCTYPE is not allowed")
			return
		}
		if mode == "echo" {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write(raw)
			return
		}

		noDoctype := doctypePattern.ReplaceAllString(body, "")
		// Well-formedness is checked with every entity reference replaced by
		// plain text, since the Go decoder rejects undefined references.
		if err := checkWellFormed(entityRefPattern.ReplaceAllString(noDoctype, "x")); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "XML syntax error: premature end of data")
			return
		}

		entities := map[string]string{}
		for _, m := range entityDeclPattern.FindAllStringSubmatch(body, -1) {
			if m[1] != "" {
				// Parameter entities are only resolved when the DOCTYPE
				// references them, so they are stored under a prefix.
				entities["%"+m[2]] = firstNonEmpty(m[3], m[4])
				continue
			}
			entities[m[2]] = firstNonEmpty(m[3], m[4])
			if m[3] != "" {
				entities[m[2]] = "SYSTEM:" + m[3]
			}
		}

		var out strings.Builder
		// A parameter entity referenced from the DOCTYPE is fetched on the
		// way in, just as a parser does while reading the external subset.
		for name, target := range entities {
			if strings.HasPrefix(name, "%") && strings.Contains(body, "%"+strings.TrimPrefix(name, "%")+";") && mode == "oob" {
				_, _ = http.Get(target)
			}
		}
		for _, m := range entityRefPattern.FindAllStringSubmatch(noDoctype, -1) {
			val, ok := entities[m[1]]
			if !ok {
				continue
			}
			resolved, err := resolveEntity(val, mode)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = io.WriteString(w, err.Error())
				return
			}
			out.WriteString(resolved)
		}
		// XInclude is resolved by the server building its own document, so it
		// doesn't need a DOCTYPE.
		if strings.Contains(noDoctype, `href="file:///etc/passwd"`) && mode == "vuln" {
			out.WriteString(passwdText)
		}

		w.Header().Set("Content-Type", "application/xml")
		if out.Len() == 0 {
			out.WriteString("ok")
		}
		_, _ = io.WriteString(w, "<result>"+out.String()+"</result>")
	}
}

const passwdText = "root:x:0:0:root:/root:/bin/sh\n"

// resolveEntity returns what the fake parser substitutes for one declared
// entity. val is either an inline value (returned with its character
// references decoded) or "SYSTEM:<url>" for an external one.
func resolveEntity(val, mode string) (string, error) {
	if !strings.HasPrefix(val, "SYSTEM:") {
		return strings.ReplaceAll(val, "&#65;", "A"), nil
	}
	sys := strings.TrimPrefix(val, "SYSTEM:")
	switch {
	case sys == "file:///etc/passwd":
		return passwdText, nil
	case sys == "file:///C:/Windows/win.ini":
		return "; for 16-bit app support\n[fonts]\n", nil
	case strings.HasPrefix(sys, "file:///aperture-xxe-"):
		// A path that doesn't exist: the parser reports the path it tried.
		return "", fmt.Errorf("parser error: failed to load external entity %q", sys)
	case strings.HasPrefix(sys, "http://169.254.169.254/"):
		// Canned metadata, so the tests never reach a real metadata address.
		return "ami-id\ninstance-id\n", nil
	case strings.HasPrefix(sys, "http") && mode == "oob":
		if resp, err := http.Get(sys); err == nil {
			_ = resp.Body.Close()
		}
		return "", nil
	}
	return "", nil
}

// checkWellFormed runs the Go decoder over s and reports the first syntax error.
func checkWellFormed(s string) error {
	dec := xml.NewDecoder(strings.NewReader(s))
	for {
		_, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// moduleByID finds one module's result in a run, failing the test if it's absent.
func moduleByID(t *testing.T, res *Result, id string) ModuleResult {
	t.Helper()
	for _, m := range res.Modules {
		if m.ID == id {
			return m
		}
	}
	t.Fatalf("module %q missing from result", id)
	return ModuleResult{}
}

func TestParseTemplateFindsLeaves(t *testing.T) {
	raw := "<?xml version=\"1.0\"?>\n<root>\n  <user>alice</user>\n  <note>hello <b>x</b></note>\n</root>"
	tpl, err := parseTemplate(raw)
	if err != nil {
		t.Fatalf("parseTemplate: %v", err)
	}
	// The mixed-content <note> has text before a child element, so only
	// <user> and the text inside <b> are plain leaves.
	var names []string
	for _, l := range tpl.leaves {
		names = append(names, l.element)
		if got := tpl.text[l.start:l.end]; strings.TrimSpace(got) == "" {
			t.Errorf("leaf %s has an empty range", l.element)
		}
	}
	if strings.Join(names, ",") != "user,b" {
		t.Errorf("leaves = %v, want [user b]", names)
	}
	if tpl.declEnd != len("<?xml version=\"1.0\"?>") {
		t.Errorf("declEnd = %d, want just past the declaration", tpl.declEnd)
	}
}

func TestParseTemplateStripsDoctypeAndRejectsBadInput(t *testing.T) {
	tpl, err := parseTemplate(`<!DOCTYPE root [<!ENTITY a "b">]><root>x</root>`)
	if err != nil {
		t.Fatalf("parseTemplate with DOCTYPE: %v", err)
	}
	if strings.Contains(tpl.text, "DOCTYPE") {
		t.Errorf("operator DOCTYPE was not stripped: %q", tpl.text)
	}

	if _, err := parseTemplate("<a>text</b>"); err == nil {
		t.Error("mismatched tags: want an error")
	}
	if _, err := parseTemplate("<a/>"); err == nil {
		t.Error("no text values: want an error")
	}
	// CDATA is decoded as character data but its raw bytes start with "<", so
	// it is not a leaf: replacing it would break the section.
	if _, err := parseTemplate("<a><![CDATA[x]]></a>"); err == nil {
		t.Error("CDATA-only body: want an error")
	}
}

func TestRenderKeepsDocumentWellFormed(t *testing.T) {
	tpl, err := parseTemplate(`<?xml version="1.0"?><root><a>one</a><b>two</b></root>`)
	if err != nil {
		t.Fatal(err)
	}
	for _, pt := range tpl.leaves {
		// Replacing a value with plain text and no DOCTYPE must still give a
		// well-formed document, since that's the baseline every payload is
		// compared to.
		out := tpl.render(&pt, "replaced", "")
		if err := checkWellFormed(out); err != nil {
			t.Errorf("render at %s: %v\n%s", pt.element, err, out)
		}
		if !strings.Contains(out, "replaced") {
			t.Errorf("render at %s did not replace the value: %s", pt.element, out)
		}
	}

	// The DOCTYPE must land after the declaration and before the root.
	pt := tpl.leaves[0]
	out := tpl.render(&pt, "&xxe;", `<!DOCTYPE aperture [<!ENTITY xxe "v">]>`)
	if !strings.HasPrefix(out, `<?xml version="1.0"?><!DOCTYPE`) {
		t.Errorf("DOCTYPE misplaced: %s", out)
	}
}

func TestRunManualFindsInBandReads(t *testing.T) {
	srv := httptest.NewServer(fakeParser("vuln"))
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/import"}, OOBConfig{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.OOBEnabled {
		t.Error("OOBEnabled = true with no listener configured")
	}
	if len(res.Endpoints) != 1 || res.Endpoints[0].Source != "seed" {
		t.Fatalf("endpoints = %+v, want the seed only", res.Endpoints)
	}

	for id, want := range map[string]string{
		"entity-canary": ConfidenceConfirmed,
		"file-read":     ConfidenceConfirmed,
		"error-based":   ConfidenceLikely,
		"xinclude":      ConfidenceConfirmed,
		"ssrf-metadata": ConfidenceConfirmed,
	} {
		m := moduleByID(t, res, id)
		if len(m.Findings) == 0 {
			t.Errorf("%s: no findings against a vulnerable parser", id)
			continue
		}
		if m.Findings[0].Confidence != want {
			t.Errorf("%s: confidence = %q, want %q", id, m.Findings[0].Confidence, want)
		}
		if m.Findings[0].Request == nil || !strings.Contains(m.Findings[0].Request.Body, "<!DOCTYPE") && id != "xinclude" {
			t.Errorf("%s: finding does not carry the XML that caused it", id)
		}
	}

	// The out-of-band module ran nothing, so it has no findings and must not
	// report anything it didn't test.
	if oob := moduleByID(t, res, "oob-callback"); len(oob.Findings) != 0 {
		t.Errorf("oob-callback reported %d findings with no listener", len(oob.Findings))
	}
}

func TestRunEchoDoesNotFalsePositive(t *testing.T) {
	srv := httptest.NewServer(fakeParser("echo"))
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/echo"}, OOBConfig{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// An endpoint that only repeats the request back carries every payload in
	// its response. The controls must catch that, so no module reports.
	for _, m := range res.Modules {
		if len(m.Findings) != 0 {
			t.Errorf("%s reported %d findings on an echo-only endpoint: %s", m.ID, len(m.Findings), m.Findings[0].Label)
		}
	}
}

func TestRunHardenedParserReportsNothing(t *testing.T) {
	srv := httptest.NewServer(fakeParser("hardened"))
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/hardened"}, OOBConfig{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, m := range res.Modules {
		if len(m.Findings) != 0 {
			t.Errorf("%s reported findings on a parser that rejects DOCTYPE", m.ID)
		}
	}
}

func TestRunUsesOperatorXMLPart(t *testing.T) {
	srv := httptest.NewServer(fakeParser("vuln"))
	defer srv.Close()

	// Two text values, so two points per module, and the first payload shows
	// up in the request the finding carries.
	body := `<order><id>42</id><customer>alice</customer></order>`
	res, err := Run(context.Background(), Request{URL: srv.URL + "/order", Body: body}, OOBConfig{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.PointsTested != 2 {
		t.Errorf("PointsTested = %d, want 2 (one per text value)", res.PointsTested)
	}
	m := moduleByID(t, res, "file-read")
	if len(m.Findings) != 2 {
		t.Fatalf("file-read findings = %d, want 2", len(m.Findings))
	}
	if !strings.Contains(m.Findings[0].Request.Body, "<order>") {
		t.Errorf("finding does not carry the operator's document: %s", m.Findings[0].Request.Body)
	}
}

func TestRunOOBCallbackConfirmsBlindXXE(t *testing.T) {
	reg := collaborator.NewRegistry()
	// The callback listener records hits the way Aperture's own handler does:
	// the token is the first path segment after /collab/, and the identifier
	// is the next one.
	cb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 && parts[0] == "collab" {
			reg.Record(parts[1], collaborator.Interaction{
				ID: fmt.Sprint(len(reg.Poll(parts[1]))), Protocol: "http", RemoteAddr: "203.0.113.9",
				Identifier: parts[2],
			})
		}
	}))
	defer cb.Close()

	srv := httptest.NewServer(fakeParser("oob"))
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/blind", Body: `<doc><field>x</field></doc>`},
		OOBConfig{Registry: reg, CallbackBaseURL: cb.URL})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.OOBEnabled {
		t.Fatal("OOBEnabled = false with a listener configured")
	}
	m := moduleByID(t, res, "oob-callback")
	if len(m.Findings) != 1 {
		t.Fatalf("oob-callback findings = %d, want 1", len(m.Findings))
	}
	f := m.Findings[0]
	if f.Confidence != ConfidenceConfirmed {
		t.Errorf("confidence = %q, want confirmed", f.Confidence)
	}
	if !strings.Contains(f.Detail, "entity") {
		t.Errorf("detail does not name the variant that fired: %s", f.Detail)
	}
	if f.Request == nil {
		t.Error("callback finding does not carry the request that fired it")
	}
}

// TestRunOOBSharedTokenAttributesHits covers the Callback picker path: every
// probe shares one token, so a hit must be credited to its point through the
// identifier it carries, not through its token.
func TestRunOOBSharedTokenAttributesHits(t *testing.T) {
	reg := collaborator.NewRegistry()
	const shared = "sharedtok01"
	// The listener records each hit under the shared token, with the probe's
	// identifier as the path segment after it.
	cb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 && parts[0] == "collab" {
			reg.Record(parts[1], collaborator.Interaction{
				ID: fmt.Sprint(len(reg.Poll(parts[1]))), Protocol: "http", RemoteAddr: "203.0.113.9",
				Identifier: parts[2],
			})
		}
	}))
	defer cb.Close()

	srv := httptest.NewServer(fakeParser("oob"))
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/blind", Body: `<doc><field>x</field></doc>`},
		OOBConfig{Registry: reg, CallbackBaseURL: cb.URL, SharedToken: shared, SharedProvider: "aperture"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.OOBEnabled {
		t.Fatal("OOBEnabled = false with a shared callback picked")
	}
	m := moduleByID(t, res, "oob-callback")
	if len(m.Findings) != 1 {
		t.Fatalf("oob-callback findings = %d, want 1", len(m.Findings))
	}
	f := m.Findings[0]
	if f.Confidence != ConfidenceConfirmed {
		t.Errorf("confidence = %q, want confirmed", f.Confidence)
	}
	// The variant is named without the endpoint and point prefix.
	if strings.Contains(f.Detail, "xxe-") {
		t.Errorf("detail leaks the raw identifier: %s", f.Detail)
	}
	if !strings.Contains(f.Detail, "entity") {
		t.Errorf("detail does not name the variant that fired: %s", f.Detail)
	}
	if f.Request == nil {
		t.Error("callback finding does not carry the request that fired it")
	}
}

func TestDiscoverFindsXMLEndpointsOnSameOrigin(t *testing.T) {
	mux := http.NewServeMux()
	// The home page links to an XML import endpoint through a form and
	// through a string literal in an inline script. It also links to a JSON
	// endpoint and an ordinary HTML page.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<html><body>
<form action="/api/import" method="post"><input name="doc"></form>
<a href="/about">about</a>
<script>fetch("/services/feed")</script>
</body></html>`)
	})
	mux.HandleFunc("/api/import", fakeParser("vuln"))
	mux.HandleFunc("/services/feed", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	mux.HandleFunc("/about", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html>about</html>")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/", AutoDiscover: true}, OOBConfig{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	found := map[string]EndpointResult{}
	for _, e := range res.Endpoints {
		found[e.URL] = e
	}
	imp, ok := found[srv.URL+"/api/import"]
	if !ok {
		t.Fatalf("auto mode did not find /api/import; endpoints = %+v", res.Endpoints)
	}
	if imp.Source != "form action" || imp.Evidence == "" {
		t.Errorf("/api/import source/evidence = %q/%q, want form action with evidence", imp.Source, imp.Evidence)
	}
	for _, not := range []string{"/services/feed", "/about", "/"} {
		if _, ok := found[srv.URL+not]; ok {
			t.Errorf("auto mode tested %s, which does not answer XML", not)
		}
	}
	if m := moduleByID(t, res, "file-read"); len(m.Findings) == 0 {
		t.Error("discovered XML endpoint was not tested for file reads")
	}
}

func TestNormalizeMethodRejectsOtherVerbs(t *testing.T) {
	for in, want := range map[string]string{"": http.MethodPost, "post": http.MethodPost, " PUT ": http.MethodPut} {
		got, err := normalizeMethod(in)
		if err != nil || got != want {
			t.Errorf("normalizeMethod(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := normalizeMethod("GET"); err == nil {
		t.Error("GET: want an error, since an XML body has no meaning for it")
	}
}

func TestCallbackURLNamesVariant(t *testing.T) {
	base := "http://aperture.example:8080"
	got := callbackURL(base, "tok", oobVariant{name: "entity"}, "")
	if got != base+"/collab/tok/entity/" {
		t.Errorf("HTTP callback = %q", got)
	}
	dns := callbackURL(base, "tok", oobVariant{name: "dns", dns: true}, "oob.example")
	if dns != "http://dns.tok.oob.example/" {
		t.Errorf("DNS callback = %q", dns)
	}
	if _, err := url.Parse(dns); err != nil {
		t.Errorf("DNS callback is not a valid URL: %v", err)
	}
}

// TestParserErrorRecognizesRealParsers feeds the wording real parsers use for a
// rejected document through the classifier's pattern. The plain-text and HTML
// responses must not match, or every web page would look like an XML parser.
func TestParserErrorRecognizesRealParsers(t *testing.T) {
	for _, msg := range []string{
		"parser error : Couldn't find end of Start Tag aperture-probe line 1",                 // libxml2
		`[Fatal Error] :1:1: The element type "a" must be terminated by the matching end-tag`, // Java SAX
		"Unexpected end of file. Following elements are not closed",                           // generic SAX
		"'>' expected. Line 1, position 15.",                                                  // .NET
		"Premature end of data in tag aperture-probe",                                         // PHP / expat wording
	} {
		if !parserErrorRe.MatchString(msg) {
			t.Errorf("parser error not recognized: %q", msg)
		}
	}
	for _, body := range []string{"plain ok", "<html><body>Welcome back</body></html>", `{"ok":true}`} {
		if parserErrorRe.MatchString(body) {
			t.Errorf("non-parser body matched: %q", body)
		}
	}
}

// TestErrorPathPatternIgnoresDoctypeEcho checks the error-based matcher against
// the two shapes a parser can return: a real missing-file error, and the DOCTYPE
// repeated back in the output. Only the first is evidence.
func TestErrorPathPatternIgnoresDoctypeEcho(t *testing.T) {
	var pattern *regexp.Regexp
	for _, m := range inbandModules("abc") {
		if m.meta.id == errorModule.id {
			pattern = m.payloads[0].pattern
		}
	}
	if pattern == nil {
		t.Fatal("error-based module missing")
	}

	realError := `warning: failed to load external entity "file:///aperture-xxe-abc/missing"`
	if !pattern.MatchString(realError) {
		t.Errorf("real libxml2 error not matched")
	}
	echo := `<!DOCTYPE a [` + "\n" + `<!ENTITY x SYSTEM "file:///aperture-xxe-abc/missing">` + "\n" + `]>`
	if pattern.MatchString(echo) {
		t.Errorf("DOCTYPE echo matched as an error")
	}
}

// TestClassifyUsesMalformedProbe covers the second route to "XML-capable": an
// endpoint that rejects every XML document it can't parse, and says so with a
// real parser message, while answering a well-formed document with something
// that isn't XML.
func TestClassifyUsesMalformedProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body := string(raw)
		switch {
		case strings.HasPrefix(r.Header.Get("Content-Type"), "text/plain"):
			_, _ = io.WriteString(w, "plain ok")
		case strings.Contains(body, "<aperture-probe") && !strings.Contains(body, "</aperture-probe>"):
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "parser error : Couldn't find end of Start Tag aperture-probe line 1")
		default:
			// Accepts XML of some kind but not as a document this scanner
			// would ever read back, so only the malformed route can match.
			w.WriteHeader(http.StatusUnsupportedMediaType)
			_, _ = io.WriteString(w, "unsupported")
		}
	}))
	defer srv.Close()

	target, _ := url.Parse(srv.URL + "/strict")
	reason, ok := classify(context.Background(), make(chan struct{}, 4), newClient(), http.MethodPost, target, defaultContentType, nil)
	if !ok {
		t.Fatal("endpoint rejecting malformed XML with a parser error was not classified as XML-capable")
	}
	if !strings.Contains(reason, "malformed") {
		t.Errorf("reason = %q, want the malformed-XML route", reason)
	}
}
