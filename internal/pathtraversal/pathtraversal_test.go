package pathtraversal

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/Indigo6415/Aperture/internal/collaborator"
)

// passwdText is a plausible /etc/passwd, enough to match the root signature.
const passwdText = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"

// fakeFiles is the filesystem the vulnerable test servers read from, keyed by
// absolute path. Only /etc/passwd exists, so any other name is a 404.
var fakeFiles = map[string]string{
	"/etc/passwd":              passwdText,
	"/srv/etc/passwd":          passwdText,
	"/srv/www/files/index.php": phpSourceText,
}

// phpSourceText is a small PHP file, the kind the php://filter source read returns.
const phpSourceText = "<?php echo 'hello';\n"

// issueText is a default Debian/Ubuntu /etc/issue, carrying the "\n \l"
// agetty escape its signature keys on. The doubled backslashes are Go escaping,
// so the file content is the literal text "Ubuntu 22.04.3 LTS \n \l".
const issueText = "Ubuntu 22.04.3 LTS \\n \\l\n"

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

// TestQueryValueIsWrittenRaw checks that a payload's percent sequences reach the
// query string as typed, and that the other parameters are kept as they were.
// An encoder that re-escapes "%" adds a decoding layer, so a double-encoded
// payload would arrive as triple-encoded and every encoding bypass would miss.
func TestQueryValueIsWrittenRaw(t *testing.T) {
	base, _ := url.Parse("https://target.example/download?file=a&keep=1")
	p := queryPoint(requestSpec{Method: http.MethodGet}, base, "file")
	spec := p.build("%252e%252e%252fetc/passwd")
	if want := "https://target.example/download?keep=1&file=%252e%252e%252fetc/passwd"; spec.URL != want {
		t.Errorf("URL = %q, want %q", spec.URL, want)
	}
	u, err := url.Parse(spec.URL)
	if err != nil {
		t.Fatalf("built URL does not parse: %v", err)
	}
	// One decode by the app turns the payload into its first-level form.
	if got := u.Query().Get("file"); got != "%2e%2e%2fetc/passwd" {
		t.Errorf("app-level value after one decode = %q, want %q", got, "%2e%2e%2fetc/passwd")
	}
}

// TestRawValueFor checks which bytes rawValueFor escapes. Payload percent
// sequences, IIS %u escapes, and the path characters are kept. Characters that
// would split or change a query are escaped, and a "%" that starts no escape
// becomes %25.
func TestRawValueFor(t *testing.T) {
	cases := map[string]string{
		"../etc/passwd":         "../etc/passwd",
		"%2e%2e%2f":             "%2e%2e%2f",
		"%u2215":                "%u2215",
		"a&b#c+d e":             "a%26b%23c%2Bd%20e",
		"100%":                  "100%25",
		"%zz":                   "%25zz",
		`..\..\win.ini`:         "..%5C..%5Cwin.ini",
		"php://filter/read=x/y": "php://filter/read=x/y",
		"%00.png":               "%00.png",
		"é":                     "%C3%A9",
	}
	for in, want := range cases {
		if got := rawValueFor(in); got != want {
			t.Errorf("rawValueFor(%q) = %q, want %q", in, got, want)
		}
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
	// Each case looks its payload up by name, so adding a payload to a module
	// never shifts the expectations for the others.
	cases := []struct {
		label string
		p     payload
		pt    point
		file  string
		want  string
	}{
		{"classic x4", payloadNamed(t, classicModule, "../ x4"), point{}, "etc/passwd", "../../../../etc/passwd"},
		{"windows x4", payloadNamed(t, windowsModule, `..\ x4`), point{}, "win.ini", `..\..\..\..\windows\win.ini`},
		{"windows 8.3", payloadNamed(t, windowsModule, `WINDOW~1 short name`), point{}, "win.ini", `..\..\..\..\WINDOW~1\win.ini`},
		{"windows root-relative", payloadNamed(t, windowsModule, `/windows/ root-relative`), point{}, "win.ini", "/windows/win.ini"},
		{"windows env var", payloadNamed(t, windowsModule, `%SYSTEMROOT%\ variable`), point{}, "win.ini", `%SYSTEMROOT%\win.ini`},
		{"encoded %2f", payloadNamed(t, encodedModule, "%2e%2e%2f x4"), point{}, "etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f" + "etc%2fpasswd"},
		{"double-encoded", payloadNamed(t, encodedModule, "%252e%252e%252f double-encoded x8"), point{}, "etc/passwd", strings.Repeat("%252e%252e%252f", 8) + "etc%252fpasswd"},
		{"IIS unicode", payloadNamed(t, encodedModule, "..%u2215 IIS unicode slash x4"), point{}, "etc/passwd", "..%u2215..%u2215..%u2215..%u2215etc%u2215passwd"},
		{"null byte .png", payloadNamed(t, encodedModule, "%00.png null-byte suffix"), point{}, "etc/passwd", "../../../../../../../../etc/passwd%00.png"},
		{"null byte bare", payloadNamed(t, encodedModule, "%00 bare null byte x8"), point{}, "etc/passwd", "../../../../../../../../etc/passwd%00"},
		{"absolute file://", payloadNamed(t, absoluteModule, "file:///etc/passwd"), point{}, "etc/passwd", "file:///etc/passwd"},
		{"absolute file:/", payloadNamed(t, absoluteModule, "file:/etc/passwd"), point{}, "etc/passwd", "file:/etc/passwd"},
		{"php base64", payloadNamed(t, phpWrapperModule, "php://filter base64 ../ x8"), point{}, "etc/passwd", "php://filter/convert.base64-encode/resource=" + strings.Repeat("../", 8) + "etc/passwd"},
		{"php source", payloadNamed(t, phpWrapperModule, "php://filter base64 index.php source"), point{}, "index.php", "php://filter/convert.base64-encode/resource=index.php"},
		{"nginx alias", payloadNamed(t, aliasModule, "segment.. (nginx alias)"), point{segment: "static"}, "etc/passwd", "static../etc/passwd"},
		{"classic /etc/issue", payloadNamed(t, classicModule, "../ x8 /etc/issue"), point{}, "etc/issue", strings.Repeat("../", 8) + "etc/issue"},
		{"windows trailing dot", payloadNamed(t, windowsModule, `..\ x4 win.ini trailing dot`), point{}, "win.ini", `..\..\..\..\windows\win.ini.`},
		{"separator double-slash", payloadNamed(t, separatorModule, "..// double-slash x4"), point{}, "etc/passwd", "..//..//..//..//etc/passwd"},
		{"separator mixed", payloadNamed(t, separatorModule, `..\/ mixed separators x4`), point{}, "etc/passwd", `..\/..\/..\/..\/etc/passwd`},
		{"overlong 4-byte", payloadNamed(t, encodedModule, "%f0%80%80%ae 4-byte overlong x4"), point{}, "etc/passwd", strings.Repeat("%f0%80%80%ae%f0%80%80%ae%f0%80%80%af", 4) + "etc%f0%80%80%afpasswd"},
	}
	for _, c := range cases {
		if got := c.p.build(c.file, c.pt); got != c.want {
			t.Errorf("%s: got %q, want %q", c.label, got, c.want)
		}
	}
}

// payloadNamed returns the payload of m with the given name, failing the test
// when there is none.
func payloadNamed(t *testing.T, m module, name string) payload {
	t.Helper()
	for _, p := range m.payloads {
		if p.name == name {
			return p
		}
	}
	t.Fatalf("module %s has no payload %q", m.id, name)
	return payload{}
}

// TestPayloadNamesUnique checks that no two payloads in a module share a name.
// The name is the label a finding reports, and payloadNamed relies on it.
func TestPayloadNamesUnique(t *testing.T) {
	total := 0
	for _, m := range modules {
		seen := map[string]bool{}
		for _, p := range m.payloads {
			if seen[p.name] {
				t.Errorf("module %s has two payloads named %q", m.id, p.name)
			}
			seen[p.name] = true
			total++
		}
	}
	t.Logf("%d payloads across %d modules", total, len(modules))
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

// TestDoubleDecodeBypassFound checks an encoding bypass end to end. The app
// decodes the query value once, filters out "../", then decodes again before
// the file lookup. Only a payload written raw reaches that second decode. The
// classic payload must not get through the filter.
func TestDoubleDecodeBypassFound(t *testing.T) {
	srv := vulnServer(t, "/srv/www/files", func(r *http.Request, _ string) string {
		once := r.URL.Query().Get("file")
		// The filter sees the once-decoded value.
		if strings.Contains(once, "../") {
			return ""
		}
		twice, err := url.PathUnescape(once)
		if err != nil {
			return ""
		}
		return twice
	})
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/download?file=report.pdf"}, OOBConfig{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, ok := findHit(res, "encoded-traversal", `query parameter "file"`); !ok {
		t.Fatalf("double-decode bypass not found; findings: %d", totalFindings(res))
	}
	if _, ok := findHit(res, "classic-traversal", `query parameter "file"`); ok {
		t.Error("classic ../ got through a filter that blocks ../")
	}
}

// TestPHPSourceReadIsLikely checks the PHP source read. The app refuses
// traversal, so the only php://filter payload that gets through is the one that
// reads the app's own index.php. That read is confirmed by the weak PHP-source
// signature, so it is reported as "likely", not "confirmed".
func TestPHPSourceReadIsLikely(t *testing.T) {
	srv := vulnServer(t, "/srv/www/files", func(r *http.Request, _ string) string {
		name := r.URL.Query().Get("file")
		if strings.Contains(name, "..") {
			return ""
		}
		return name
	})
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/download?file=report.pdf"}, OOBConfig{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	m := moduleResultByID(t, res, "php-filter-wrapper")
	var got *Finding
	for i := range m.Findings {
		if strings.Contains(m.Findings[i].Payload, "index.php") {
			got = &m.Findings[i]
		}
	}
	if got == nil {
		t.Fatalf("no php-filter finding for index.php; findings: %d", len(m.Findings))
	}
	if got.Confidence != ConfidenceLikely {
		t.Errorf("confidence = %q, want %q (weak PHP signature)", got.Confidence, ConfidenceLikely)
	}
	if !strings.HasPrefix(got.Evidence, "base64-decoded:") {
		t.Errorf("evidence = %q, want a base64-decoded snippet", got.Evidence)
	}
}

// TestXMLBodyRead checks that a traversal in an XML text node is found, and
// that the label names the element.
func TestXMLBodyRead(t *testing.T) {
	srv := vulnServer(t, "/srv/www/files", func(r *http.Request, body string) string {
		if r.Method != http.MethodPost {
			return ""
		}
		var doc struct {
			File string `xml:"file"`
		}
		if err := xml.Unmarshal([]byte(body), &doc); err != nil {
			return ""
		}
		return doc.File
	})
	defer srv.Close()

	res, err := Run(context.Background(), Request{
		URL:         srv.URL + "/api/render",
		Body:        `<req><file>report.pdf</file><note>hello</note></req>`,
		ContentType: "application/xml",
	}, OOBConfig{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, ok := findHit(res, "classic-traversal", `XML text of <file>`); !ok {
		t.Fatalf("no XML finding on the file element; findings: %d", totalFindings(res))
	}
	// The unrelated <note> text is not a file name, so it must not produce a finding.
	if _, ok := findHit(res, "classic-traversal", `XML text of <note>`); ok {
		t.Error("finding reported on the note element")
	}
}

// TestXMLBodyDetectedWithoutContentType checks that a body that starts with "<"
// is treated as XML when no Content-Type is given, so its text nodes are tested.
func TestXMLBodyDetectedWithoutContentType(t *testing.T) {
	pts := bodyPoints(requestSpec{Method: http.MethodPost, URL: "https://t.example/x", Headers: map[string]string{}}, `<a><b>c</b></a>`, "")
	if len(pts) != 1 {
		t.Fatalf("points = %d, want 1 (the text of <b>)", len(pts))
	}
	if !strings.Contains(pts[0].label, "<b>") {
		t.Errorf("label = %q, want it to name <b>", pts[0].label)
	}
}

// TestXMLPayloadIsEscaped checks that a payload with XML-special characters
// stays well formed, and that the parser hands the app the same characters back.
func TestXMLPayloadIsEscaped(t *testing.T) {
	pts := xmlPoints(requestSpec{Method: http.MethodPost, URL: "https://t.example/x"}, `<req><file>report.pdf</file></req>`)
	if len(pts) != 1 {
		t.Fatalf("points = %d, want 1", len(pts))
	}
	value := `../a&b<"c'`
	spec := pts[0].build(value)
	var doc struct {
		File string `xml:"file"`
	}
	if err := xml.Unmarshal([]byte(spec.Body), &doc); err != nil {
		t.Fatalf("body is not well-formed XML: %v\n%s", err, spec.Body)
	}
	if doc.File != value {
		t.Errorf("parsed value = %q, want %q", doc.File, value)
	}
}

// rawLineServer accepts connections and records each request line as sent.
// Unlike httptest, it does not parse the request target, so a payload with an
// IIS-style "%u" escape reaches it as written.
func rawLineServer(t *testing.T) (string, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	lines := make(chan string, 16)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				line, err := bufio.NewReader(c).ReadString('\n')
				if err != nil {
					return
				}
				lines <- strings.TrimRight(line, "\r\n")
				io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			}(conn)
		}
	}()
	return ln.Addr().String(), lines
}

// TestRequestTargetSentAsWritten checks that the request line carries the
// payload's bytes unchanged. A raw backslash, a %u escape, and a "//" target
// each have to survive, since the bypasses depend on them.
func TestRequestTargetSentAsWritten(t *testing.T) {
	addr, lines := rawLineServer(t)
	targets := []string{
		`/static/..\..\windows\win.ini`,
		`/a/..%u2215..%u2215etc%u2215passwd`,
		`/download?file=%252e%252e%252fetc/passwd&x=%u2215`,
		`///etc/passwd`,
	}
	client := &http.Client{Timeout: 5 * time.Second}
	for _, target := range targets {
		// The response is not checked: the test reads the request line only.
		send(context.Background(), client, nil, requestSpec{Method: http.MethodGet, URL: "http://" + addr + target})
		select {
		case got := <-lines:
			if want := "GET " + target + " HTTP/1.1"; got != want {
				t.Errorf("request line = %q, want %q", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no request line recorded for %q", target)
		}
	}
}

// verifyCase is one scenario for verifyRead. The server answers the control
// request with controlBody (or drops the connection when controlHijack is set),
// and answers the replay with replayBody, or probeBody when replayBody is empty.
type verifyCase struct {
	name          string
	probeBody     string
	replayBody    string
	controlBody   string
	controlHijack bool
	status        int
	want          readVerdict
	confidence    string
	detailHas     string
}

// TestVerifyRead checks each way a candidate read can come out: reproduced,
// shown by the control (a catch-all), not reproduced on replay, control
// unavailable, weak signature, and server-error status. Each case states the
// confidence and the detail sentence the operator should see.
func TestVerifyRead(t *testing.T) {
	cases := []verifyCase{
		{name: "reproduced and clean", probeBody: passwdText, controlBody: "ok",
			want: verdictReported, confidence: ConfidenceConfirmed, detailHas: "returned it again"},
		{name: "control shows the same signature", probeBody: passwdText, controlBody: passwdText,
			want: verdictCatchAll},
		{name: "replay does not show it", probeBody: passwdText, replayBody: "ok", controlBody: "ok",
			want: verdictNotReproduced},
		{name: "control cannot be fetched", probeBody: passwdText, controlHijack: true,
			want: verdictReported, confidence: ConfidenceLikely, detailHas: "could not be fetched"},
		{name: "weak signature", probeBody: "<?php echo 1;", controlBody: "ok",
			want: verdictReported, confidence: ConfidenceLikely, detailHas: "weak one"},
		{name: "server error status", probeBody: passwdText, controlBody: "ok", status: http.StatusInternalServerError,
			want: verdictReported, confidence: ConfidenceLikely, detailHas: "status was 500"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, verdict := runVerify(t, c)
			if verdict != c.want {
				t.Fatalf("verdict = %v, want %v", verdict, c.want)
			}
			if c.want != verdictReported {
				return
			}
			if f.Confidence != c.confidence {
				t.Errorf("confidence = %q, want %q", f.Confidence, c.confidence)
			}
			if !strings.Contains(f.Detail, c.detailHas) {
				t.Errorf("detail = %q, want it to contain %q", f.Detail, c.detailHas)
			}
		})
	}
}

// runVerify sets up one verifyCase against a test server and returns what
// verifyRead decided.
func runVerify(t *testing.T, c verifyCase) (Finding, readVerdict) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("file")
		if strings.Contains(name, negativeControlName) {
			if c.controlHijack {
				// Dropping the connection makes the control a transport error.
				if hj, ok := w.(http.Hijacker); ok {
					if conn, _, err := hj.Hijack(); err == nil {
						conn.Close()
					}
				}
				return
			}
			io.WriteString(w, c.controlBody)
			return
		}
		// Every other request is a replay, since verifyRead is given the probe result.
		body := c.replayBody
		if body == "" {
			body = c.probeBody
		}
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)

	target, err := url.Parse(srv.URL + "/download?file=report.pdf")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pt := queryPoint(requestSpec{Method: http.MethodGet}, target, "file")
	p := payloadNamed(t, classicModule, "../ x1")
	value := p.build(p.target, pt)
	probe := pt.build(value)

	status := c.status
	if status == 0 {
		status = http.StatusOK
	}
	res := &sendResult{StatusCode: status, Body: c.probeBody, Request: CapturedRequest{Method: http.MethodGet, URL: probe.URL}}
	sig, evidence, ok := matchFile(res.Body, "", false)
	if !ok {
		t.Fatalf("probe body %q does not match any signature", c.probeBody)
	}
	deps := runDeps{client: &http.Client{Timeout: 5 * time.Second}}
	f, verdict := verifyRead(context.Background(), deps, classicModule, pt, p, value, probe, res, sig, evidence)
	return f, verdict
}

// TestVerifyReadDropsCancelledRun checks that a run cancelled mid-verification
// drops the candidate instead of reporting it at a lower confidence. Both the
// control and the replay fail on a cancelled context, and that failure must
// not count as evidence.
func TestVerifyReadDropsCancelledRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, passwdText)
	}))
	defer srv.Close()

	target, _ := url.Parse(srv.URL + "/download?file=report.pdf")
	pt := queryPoint(requestSpec{Method: http.MethodGet}, target, "file")
	p := payloadNamed(t, classicModule, "../ x1")
	value := p.build(p.target, pt)
	probe := pt.build(value)
	res := &sendResult{StatusCode: http.StatusOK, Body: passwdText, Request: CapturedRequest{Method: http.MethodGet, URL: probe.URL}}
	sig, evidence, ok := matchFile(passwdText, "", false)
	if !ok {
		t.Fatal("passwd text does not match")
	}

	// Cancel before verification starts, so every request fails.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	deps := runDeps{client: &http.Client{Timeout: 5 * time.Second}}
	if _, verdict := verifyRead(ctx, deps, classicModule, pt, p, value, probe, res, sig, evidence); verdict != verdictNotReproduced {
		t.Errorf("verdict = %v on a cancelled run, want verdictNotReproduced", verdict)
	}
}

// TestSignatures checks the strengthened signatures on both sides. The
// /etc/passwd match needs a listing, not one quoted root line. The /proc/version
// match needs the kernel build line, not the bare words "Linux version".
func TestSignatures(t *testing.T) {
	quotedRoot := "root:x:0:0:root:/root:/bin/bash\n<p>the first line of passwd</p>"
	if _, _, ok := matchFile(quotedRoot, "", false); ok {
		t.Error("a single quoted root line was reported as /etc/passwd")
	}
	if _, _, ok := matchFile(passwdText, "", false); !ok {
		t.Error("a passwd listing was not reported")
	}

	banner := "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-068) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023"
	if sig, _, ok := matchFile(banner, "", false); !ok || sig.name != "/proc/version" {
		t.Errorf("kernel banner not matched as /proc/version (ok=%v, sig=%q)", ok, sig.name)
	}
	if _, _, ok := matchFile("Linux version 5.4 is supported by this app.", "", false); ok {
		t.Error("prose mentioning a Linux version was reported as /proc/version")
	}
}

// TestMatchFilePrefersStrong checks that a strong signature beats a weak one in
// the same text, whatever the table order, and that a weak match alone is still
// returned, with its own weak strength.
func TestMatchFilePrefersStrong(t *testing.T) {
	sig, _, ok := matchFile("<?php echo 1; ?>\n"+passwdText, "", false)
	if !ok || sig.name != "/etc/passwd" || !sig.strong {
		t.Errorf("sig = %q (strong=%v, ok=%v), want strong /etc/passwd", sig.name, sig.strong, ok)
	}
	sig, _, ok = matchFile("<?php echo 1; ?>", "", false)
	if !ok || sig.name != "PHP source" || sig.strong {
		t.Errorf("sig = %q (strong=%v, ok=%v), want weak PHP source", sig.name, sig.strong, ok)
	}
}

// TestEtcIssueSignature checks the second Unix oracle: an /etc/issue read is
// matched by its agetty-escape signature, in both the Debian and RHEL forms,
// while ordinary prose is not.
func TestEtcIssueSignature(t *testing.T) {
	if sig, _, ok := matchFile(issueText, "", false); !ok || sig.name != "/etc/issue" {
		t.Errorf("Debian issue not matched (ok=%v, sig=%q)", ok, sig.name)
	}
	// RHEL/CentOS default: "\S\nKernel \r on an \m".
	rhel := "\\S\nKernel \\r on an \\m\n"
	if sig, _, ok := matchFile(rhel, "", false); !ok || sig.name != "/etc/issue" {
		t.Errorf("RHEL issue not matched (ok=%v, sig=%q)", ok, sig.name)
	}
	if _, _, ok := matchFile("Welcome, please sign in to your account.", "", false); ok {
		t.Error("ordinary prose matched as /etc/issue")
	}
}

// TestWebConfigSignature checks the IIS web.config oracle, which is weak: a
// match is reported, but only at "likely" strength.
func TestWebConfigSignature(t *testing.T) {
	cfg := `<?xml version="1.0"?><configuration><system.webServer><handlers/></system.webServer></configuration>`
	sig, _, ok := matchFile(cfg, "", false)
	if !ok || sig.name != "web.config" {
		t.Fatalf("web.config not matched (ok=%v, sig=%q)", ok, sig.name)
	}
	if sig.strong {
		t.Error("web.config signature should be weak")
	}
}

// TestEtcIssueOracleFound checks a host that exposes /etc/issue but not
// /etc/passwd: the classic module's issue payload still confirms the read.
func TestEtcIssueOracleFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("file")
		if name == "" {
			io.WriteString(w, "home")
			return
		}
		// Only /etc/issue is readable; every other resolved path is a 404.
		if path.Join("/srv/www/files", name) == "/etc/issue" {
			io.WriteString(w, issueText)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/download?file=report.pdf"}, OOBConfig{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	f, ok := findHit(res, "classic-traversal", `query parameter "file"`)
	if !ok {
		t.Fatalf("issue oracle not found; findings: %d", totalFindings(res))
	}
	if !strings.Contains(f.Payload, "etc/issue") {
		t.Errorf("finding payload %q is not the /etc/issue oracle", f.Payload)
	}
}

// TestOverlongUTF8BypassFound checks one of the encodings transferred from
// dotdotpwn end to end. The app blocks "../" and the simple percent-dot and
// percent-slash forms, but a lenient decoder folds 4-byte overlong UTF-8 to
// "." and "/" before the file lookup, so only that payload gets through.
func TestOverlongUTF8BypassFound(t *testing.T) {
	srv := vulnServer(t, "/srv/www/files", func(r *http.Request, _ string) string {
		// Read the value as written on the wire, so the percent sequences are
		// still text rather than already-decoded bytes.
		raw := r.URL.RawQuery
		_, val, ok := strings.Cut(raw, "file=")
		if !ok {
			return ""
		}
		if j := strings.IndexByte(val, '&'); j >= 0 {
			val = val[:j]
		}
		low := strings.ToLower(val)
		// Reject plain traversal and the common single-escape dot/slash forms.
		if strings.Contains(val, "../") || strings.Contains(low, "%2e") || strings.Contains(low, "%2f") || strings.Contains(low, "%c0") {
			return ""
		}
		// Fold only the 4-byte overlong forms, the way a lenient stack would.
		return strings.NewReplacer("%f0%80%80%ae", ".", "%f0%80%80%af", "/").Replace(low)
	})
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/download?file=report.pdf"}, OOBConfig{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	f, ok := findHit(res, "encoded-traversal", `query parameter "file"`)
	if !ok {
		t.Fatalf("overlong UTF-8 bypass not found; findings: %d", totalFindings(res))
	}
	if !strings.Contains(f.Payload, "%f0%80%80%ae") {
		t.Errorf("finding payload %q is not the 4-byte overlong form", f.Payload)
	}
	// The plain ../ payloads are blocked, so the classic module finds nothing.
	if _, ok := findHit(res, "classic-traversal", `query parameter "file"`); ok {
		t.Error("classic ../ got through a filter that blocks it")
	}
}

// TestBisectionReportsDepth checks the depth finder transferred from
// dotdotpwn's bisection algorithm. The app sits four directories below the
// filesystem root, so the smallest traversal that reaches /etc/passwd is four
// steps, and the finding's detail must state that.
func TestBisectionReportsDepth(t *testing.T) {
	srv := vulnServer(t, "/a/b/c/d", func(r *http.Request, _ string) string {
		return r.URL.Query().Get("file")
	})
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/download?file=report.pdf"}, OOBConfig{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	f, ok := findHit(res, "classic-traversal", `query parameter "file"`)
	if !ok {
		t.Fatalf("no classic finding; findings: %d", totalFindings(res))
	}
	if !strings.Contains(f.Detail, `minimal traversal depth that still reads the file is 4`) {
		t.Errorf("detail does not report the bisected depth of 4: %s", f.Detail)
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
