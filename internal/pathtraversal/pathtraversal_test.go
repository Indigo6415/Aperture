package pathtraversal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"testing"

	"github.com/Indigo6415/Aperture/internal/collaborator"
)

// passwdText is a plausible /etc/passwd, enough to match the root signature.
const passwdText = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"

// fakeFiles is the filesystem the vulnerable test servers read from, keyed by
// absolute path. Only /etc/passwd exists, so any other name is a 404.
var fakeFiles = map[string]string{
	"/etc/passwd":     passwdText,
	"/srv/etc/passwd": passwdText,
}

// readAt resolves name against base the way a naive app would (path.Join cleans
// ".." steps) and returns the file, or false when it does not exist.
func readAt(base, name string) (string, bool) {
	content, ok := fakeFiles[path.Join(base, name)]
	return content, ok
}

// phpPrefix is the php://filter value the wrapper payloads start with. The
// fake server base64-encodes what follows it, as PHP does.
const phpPrefix = "php://filter/convert.base64-encode/resource="

// vulnServer builds a test app that reads files from fakeFiles. source returns
// the file name the request asks for, or "" for an ordinary page. The
// returned servers are closed by the test.
func vulnServer(t *testing.T, base string, source func(r *http.Request, body string) string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := ""
		if r.Body != nil {
			raw, _ := io.ReadAll(r.Body)
			body = string(raw)
		}
		name := source(r, body)
		if name == "" {
			w.Write([]byte("<html><body>home</body></html>"))
			return
		}
		// The PHP wrapper returns the file base64-encoded instead of plain.
		if strings.HasPrefix(name, phpPrefix) {
			content, ok := readAt(base, strings.TrimPrefix(name, phpPrefix))
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(content))))
			return
		}
		content, ok := readAt(base, name)
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(content))
	}))
}

// findHit reports whether res has a finding in module moduleID whose label
// contains labelPart.
func findHit(res *Result, moduleID, labelPart string) (Finding, bool) {
	for _, m := range res.Modules {
		if m.ID != moduleID {
			continue
		}
		for _, f := range m.Findings {
			if strings.Contains(f.Label, labelPart) {
				return f, true
			}
		}
	}
	return Finding{}, false
}

// totalFindings counts findings across every module of res.
func totalFindings(res *Result) int {
	n := 0
	for _, m := range res.Modules {
		n += len(m.Findings)
	}
	return n
}

// TestQueryParameterRead checks that a traversal in an ordinary query
// parameter is found and confirmed by the passwd signature.
func TestQueryParameterRead(t *testing.T) {
	srv := vulnServer(t, "/srv/www/files", func(r *http.Request, _ string) string {
		return r.URL.Query().Get("file")
	})
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/download?file=report.pdf"}, OOBConfig{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	f, ok := findHit(res, "classic-traversal", `query parameter "file"`)
	if !ok {
		t.Fatalf("no classic-traversal finding on the file parameter; findings: %d", totalFindings(res))
	}
	if f.Confidence != ConfidenceConfirmed {
		t.Errorf("confidence = %q, want %q", f.Confidence, ConfidenceConfirmed)
	}
	if f.Request == nil || !strings.Contains(f.Request.URL, "file=") {
		t.Errorf("finding is missing the captured request: %+v", f.Request)
	}
}

// TestCookieRead checks that a traversal in a cookie the app reads as a file
// name is found, and that the operator's other cookies are kept.
func TestCookieRead(t *testing.T) {
	srv := vulnServer(t, "/srv/www/files", func(r *http.Request, _ string) string {
		c, err := r.Cookie("file")
		if err != nil {
			return ""
		}
		return c.Value
	})
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/", Headers: map[string]string{"Cookie": "session=abc"}}, OOBConfig{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, ok := findHit(res, "classic-traversal", `cookie "file"`); !ok {
		t.Fatalf("no cookie finding for the file cookie; findings: %d", totalFindings(res))
	}
}

// TestJSONBodyRead checks that a traversal in one string of a JSON body is
// found, and that the label names the field's JSON pointer.
func TestJSONBodyRead(t *testing.T) {
	srv := vulnServer(t, "/srv/www/files", func(r *http.Request, body string) string {
		if r.Method != http.MethodPost {
			return ""
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(body), &doc); err != nil {
			return ""
		}
		name, _ := doc["name"].(string)
		return name
	})
	defer srv.Close()

	res, err := Run(context.Background(), Request{
		URL:         srv.URL + "/api/render",
		Body:        `{"name":"report.pdf","meta":{"title":"x"}}`,
		ContentType: "application/json",
	}, OOBConfig{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, ok := findHit(res, "classic-traversal", `JSON body field "/name"`); !ok {
		t.Fatalf("no JSON body finding on /name; findings: %d", totalFindings(res))
	}
}

// TestNginxAliasRead checks the off-by-slash alias method: a request for
// "/static../etc/passwd" reaches "/srv/static/../etc/passwd".
func TestNginxAliasRead(t *testing.T) {
	srv := vulnServer(t, "/srv/static", func(r *http.Request, _ string) string {
		rest := strings.TrimPrefix(r.URL.Path, "/static")
		if rest == "" {
			return ""
		}
		// The server joins this remainder onto its alias root, /srv/static,
		// the way nginx does, so it can climb out of that directory.
		return rest
	})
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/static"}, OOBConfig{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, ok := findHit(res, "nginx-alias", `path segment "static"`); !ok {
		t.Fatalf("no alias finding on the static segment; findings: %d", totalFindings(res))
	}
}

// TestPHPWrapperRead checks that the base64-wrapped read is found only through
// the php-filter-wrapper module, which decodes the response.
func TestPHPWrapperRead(t *testing.T) {
	srv := vulnServer(t, "/srv/www/files", func(r *http.Request, _ string) string {
		return r.URL.Query().Get("file")
	})
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/download?file=report.pdf"}, OOBConfig{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	f, ok := findHit(res, "php-filter-wrapper", `query parameter "file"`)
	if !ok {
		t.Fatalf("no php-filter-wrapper finding; findings: %d", totalFindings(res))
	}
	if !strings.HasPrefix(f.Evidence, "base64-decoded:") {
		t.Errorf("evidence = %q, want a base64-decoded snippet", f.Evidence)
	}
}

// TestCatchAllIsNotReported checks the negative control. The server returns
// passwd for any request with a query string, and the seed has none, so the
// baseline is clean. Every probe then reads passwd, and the control reads it
// too, so nothing should be reported.
func TestCatchAllIsNotReported(t *testing.T) {
	srv := vulnServer(t, "/srv/www/files", func(r *http.Request, _ string) string {
		if r.URL.RawQuery != "" {
			return "../../../etc/passwd"
		}
		return ""
	})
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/"}, OOBConfig{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n := totalFindings(res); n != 0 {
		t.Errorf("catch-all page produced %d findings, want 0", n)
	}
}

// TestBaselineSignatureIsIgnored checks that a file signature already on the
// unmodified page is not reported, even when a probe returns it.
func TestBaselineSignatureIsIgnored(t *testing.T) {
	if _, _, ok := matchFile(passwdText, passwdText, false); ok {
		t.Error("signature present in the baseline was reported")
	}
}

// TestBase64DecodeOnlyWhenEnabled checks that base64 content is decoded only
// for the wrapper module, so ordinary base64 on a page is not read as a file.
func TestBase64DecodeOnlyWhenEnabled(t *testing.T) {
	body := "<pre>" + base64.StdEncoding.EncodeToString([]byte(passwdText)) + "</pre>"
	if _, _, ok := matchFile(body, "", false); ok {
		t.Error("base64 content matched with decoding disabled")
	}
	if _, _, ok := matchFile(body, "", true); !ok {
		t.Error("base64-encoded passwd did not match with decoding enabled")
	}
}

// TestEncodedPayloadReachesWireIntact checks that a payload's percent sequences
// survive into the query string as typed. Double-encoding bypasses depend on
// this, and an encoder that re-escapes "%" would silently turn them into
// something else.
func TestEncodedPayloadReachesWireIntact(t *testing.T) {
	base, _ := url.Parse("https://target.example/download?file=a")
	p := queryPoint(requestSpec{Method: http.MethodGet}, base, "file")
	spec := p.build("%252e%252e%252fetc/passwd")
	u, err := url.Parse(spec.URL)
	if err != nil {
		t.Fatalf("built URL does not parse: %v", err)
	}
	// The app should receive the exact payload text after one decode.
	if got := u.Query().Get("file"); got != "%252e%252e%252fetc/passwd" {
		t.Errorf("app-level value = %q, want the payload unchanged", got)
	}
}

// TestPathSegmentKeepsRawPayload checks that a path payload goes on the wire
// as written, without the escaping that url.URL would add.
func TestPathSegmentKeepsRawPayload(t *testing.T) {
	seed, _ := url.Parse("https://target.example/static/app.js")
	segments := strings.Split(seed.EscapedPath(), "/")
	p := pathSegmentPoint(seed, requestSpec{Method: http.MethodGet}, segments, 2)
	spec := p.build("../../etc/passwd")
	if want := "https://target.example/static/../../etc/passwd"; spec.URL != want {
		t.Errorf("URL = %q, want %q", spec.URL, want)
	}
}

// TestCrawlSkipsSeedQueryPoints checks that the crawler does not add the
// seed's own query parameters as GET points. Those are built in seedPoints
// with the seed's real method and body, so a POST seed would otherwise be
// tested as a GET.
func TestCrawlSkipsSeedQueryPoints(t *testing.T) {
	seed, _ := url.Parse("https://target.example/search?q=1")
	page := `<form action="/go" method="post"><input name="file" value="a"></form>`
	client := &http.Client{}
	res := crawl(context.Background(), client, seed, page, map[string]string{}, 0, 1)
	for _, p := range res.points {
		if strings.HasPrefix(p.id, "query|GET|https://target.example/search|") {
			t.Errorf("crawl added a seed query point %q", p.id)
		}
	}
}

// TestPayloadWireStrings pins the exact strings a sample of payloads produce,
// so a change to a shared helper cannot silently alter what is sent.
func TestPayloadWireStrings(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"classic x4", classicModule.payloads[1].build("etc/passwd", point{}), "../../../../etc/passwd"},
		{"windows x4", windowsModule.payloads[0].build("win.ini", point{}), `..\..\..\..\windows\win.ini`},
		{"windows 8.3", windowsModule.payloads[6].build("win.ini", point{}), `..\..\..\..\WINDOW~1\win.ini`},
		{"encoded %2f", encodedModule.payloads[0].build("etc/passwd", point{}), "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f" + "etc%2fpasswd"},
		{"double-encoded", encodedModule.payloads[3].build("etc/passwd", point{}), "%252e%252e%252f" + "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f" + "etc%252fpasswd"},
		{"null byte", encodedModule.payloads[12].build("etc/passwd", point{}), "../../../../../../../../etc/passwd%00.png"},
		{"absolute file://", absoluteModule.payloads[2].build("etc/passwd", point{}), "file:///etc/passwd"},
		{"php base64", phpWrapperModule.payloads[0].build("etc/passwd", point{}), "php://filter/convert.base64-encode/resource=" + strings.Repeat("../", 8) + "etc/passwd"},
		{"nginx alias", aliasModule.payloads[0].build("etc/passwd", point{segment: "static"}), "static../etc/passwd"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, c.got, c.want)
		}
	}
}

// fetchTarget stands in for an app that takes a file name and fetches it when it
// is a URL, the way remote file inclusion behaves. Any other value gets an
// ordinary page, so the file-read modules find nothing to report.
func fetchTarget() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if file := r.URL.Query().Get("file"); strings.HasPrefix(file, "http://") {
			if resp, err := http.Get(file); err == nil {
				resp.Body.Close()
			}
		}
		_, _ = io.WriteString(w, "ok")
	}
}

// callbackRecorder stands in for Aperture's collaborator listener. It records
// each hit under the token in the path, with the identifier after it if there is
// one, the way handleCollaborator does.
func callbackRecorder(reg *collaborator.Registry) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 2 || parts[0] != "collab" {
			return
		}
		ident := ""
		if len(parts) >= 3 {
			ident = parts[2]
		}
		reg.Record(parts[1], collaborator.Interaction{
			ID: fmt.Sprint(len(reg.Poll(parts[1]))), Protocol: "http", RemoteAddr: "203.0.113.9",
			Identifier: ident,
		})
	}))
}

// TestRunOOBCallbackConfirmsURLFetch checks that a path the app fetches as a URL
// is reported as a fetch, not as a file read.
func TestRunOOBCallbackConfirmsURLFetch(t *testing.T) {
	reg := collaborator.NewRegistry()
	cb := callbackRecorder(reg)
	defer cb.Close()
	srv := httptest.NewServer(fetchTarget())
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/fetch?file=report.pdf"},
		OOBConfig{Registry: reg, CallbackBaseURL: cb.URL})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.OOBEnabled {
		t.Fatal("OOBEnabled = false with a listener configured")
	}
	m := moduleResultByID(t, res, oobCallbackModule.id)
	if len(m.Findings) == 0 {
		t.Fatal("oob-callback reported no findings for a path the app fetched")
	}
	f := m.Findings[0]
	if f.Confidence != ConfidenceConfirmed {
		t.Errorf("confidence = %q, want confirmed", f.Confidence)
	}
	if !strings.HasPrefix(f.Label, "Arbitrary URL fetched via ") {
		t.Errorf("label = %q, want a URL-fetch label", f.Label)
	}
	if !strings.Contains(f.Detail, "not a file read") {
		t.Errorf("detail does not separate a fetch from a read: %s", f.Detail)
	}
	if f.Request == nil {
		t.Error("callback finding does not carry the request that fired it")
	}
	// The file-read modules see only an ordinary page, so none of them reports.
	for _, mod := range res.Modules {
		if mod.ID != oobCallbackModule.id && len(mod.Findings) != 0 {
			t.Errorf("module %s reported %d findings from a fetch", mod.ID, len(mod.Findings))
		}
	}
}

// TestRunOOBSharedTokenAttributesHits covers the Callback picker path, where
// every point shares one token and hits are credited back through identifiers.
func TestRunOOBSharedTokenAttributesHits(t *testing.T) {
	reg := collaborator.NewRegistry()
	cb := callbackRecorder(reg)
	defer cb.Close()
	srv := httptest.NewServer(fetchTarget())
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/fetch?file=report.pdf"},
		OOBConfig{Registry: reg, CallbackBaseURL: cb.URL, SharedToken: "sharedtok01", SharedProvider: "aperture"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	m := moduleResultByID(t, res, oobCallbackModule.id)
	if len(m.Findings) == 0 {
		t.Fatal("shared-token run reported no findings for a path the app fetched")
	}
	// Each finding is credited to its point through its identifier, so no two
	// findings may name the same point.
	seen := map[string]bool{}
	for _, f := range m.Findings {
		if seen[f.Label] {
			t.Errorf("two findings credited to the same point: %q", f.Label)
		}
		seen[f.Label] = true
	}
}

// TestRunWithoutListenerSkipsCallbackModule checks that no listener means the
// callback module does not appear in the result at all.
func TestRunWithoutListenerSkipsCallbackModule(t *testing.T) {
	srv := httptest.NewServer(fetchTarget())
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/fetch?file=report.pdf"}, OOBConfig{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.OOBEnabled {
		t.Error("OOBEnabled = true with no listener")
	}
	for _, mod := range res.Modules {
		if mod.ID == oobCallbackModule.id {
			t.Error("callback module ran with no listener")
		}
	}
}

// moduleResultByID returns the named module's result, failing the test when it
// is absent.
func moduleResultByID(t *testing.T, res *Result, id string) ModuleResult {
	t.Helper()
	for _, m := range res.Modules {
		if m.ID == id {
			return m
		}
	}
	t.Fatalf("no module %q in result", id)
	return ModuleResult{}
}
