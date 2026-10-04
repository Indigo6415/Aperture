package ssrf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestProtocolURLEncodesRawBytes checks that a gopher probe's bytes survive
// the URL: CRLF is percent-encoded, plain letters are not, and the FastCGI
// record's NUL and control bytes all come out escaped.
func TestProtocolURLEncodesRawBytes(t *testing.T) {
	var redis, fcgi serviceProbe
	for _, p := range protocolProbes {
		switch p.service {
		case "Redis":
			redis = p
		case "FastCGI":
			fcgi = p
		}
	}

	if got, want := redis.protocolURL(), "gopher://127.0.0.1:6379/_INFO%0D%0A"; got != want {
		t.Fatalf("Redis gopher URL = %q, want %q", got, want)
	}
	if got, want := fcgi.protocolURL(), "gopher://127.0.0.1:9000/_%01%09%00%00%00%00%00%00"; got != want {
		t.Fatalf("FastCGI gopher URL = %q, want %q", got, want)
	}
}

// TestProtocolURLDictForm checks the dict:// form, which carries the command
// as plain text rather than percent-encoded bytes.
func TestProtocolURLDictForm(t *testing.T) {
	for _, p := range protocolProbes {
		if p.scheme != "dict" {
			continue
		}
		if got, want := p.protocolURL(), "dict://127.0.0.1:6379/info"; got != want {
			t.Fatalf("dict URL = %q, want %q", got, want)
		}
	}
}

// TestProtocolProbesAreDetectionOnly guards the read-only constraint: no probe
// may issue a write verb. The list is a deny-list of the commands that change
// service state, and a probe that matches one fails the test.
func TestProtocolProbesAreDetectionOnly(t *testing.T) {
	writeVerbs := []string{"SET", "CONFIG", "SAVE", "BGSAVE", "FLUSH", "DEL", "EVAL", "MODULE", "SLAVEOF", "REPLICAOF", "ADD", "ADDUSER", "RCPT", "MAIL"}
	for _, p := range protocolProbes {
		upper := strings.ToUpper(p.raw)
		for _, v := range writeVerbs {
			// A "CONFIG REWRITE" signature lives in the matcher, not the probe,
			// so only the sent bytes are checked here.
			if strings.Contains(upper, v) {
				t.Errorf("%s probe sends %q, which contains write verb %s", p.service, p.raw, v)
			}
		}
	}
}

// fakeSSRFServer stands in for a vulnerable endpoint: it takes the "url"
// parameter and fetches it. The fetch is simulated, not performed, so the
// test controls exactly what each payload returns. body is handed back for a
// payload whose value starts with the given prefix.
func fakeSSRFServer(t *testing.T, prefix, body string) (*httptest.Server, *url.URL) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("url")
		if strings.HasPrefix(v, prefix) {
			w.Write([]byte(body))
			return
		}
		w.Write([]byte("<html>ordinary page</html>"))
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL + "/fetch")
	if err != nil {
		t.Fatal(err)
	}
	return srv, u
}

// runProtocolOnly runs Run against u with only the protocol module's points in
// play: the parameter list is pinned to url, and the product endpoints are off.
func runProtocolOnly(t *testing.T, u *url.URL) *Result {
	t.Helper()
	res, err := Run(context.Background(), Request{
		URL:              u.String(),
		Params:           []string{"url"},
		NoKnownEndpoints: true,
	}, OOBConfig{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return res
}

// protocolFindings collects the findings from the internal-service module.
func protocolFindings(res *Result) []Finding {
	for _, m := range res.Modules {
		if m.ID == protocolModule.id {
			return m.Findings
		}
	}
	return nil
}

// TestProtocolModuleReportsRedisThroughGopher checks that a server which
// fetches a gopher://127.0.0.1:6379 URL and returns Redis INFO output is
// reported, and that the finding names Redis.
func TestProtocolModuleReportsRedisThroughGopher(t *testing.T) {
	_, u := fakeSSRFServer(t, "gopher://127.0.0.1:6379/", "# Server\r\nredis_version:7.2.4\r\n")
	findings := protocolFindings(runProtocolOnly(t, u))
	if len(findings) == 0 {
		t.Fatal("no finding for a Redis INFO response through gopher")
	}
	var found bool
	for _, f := range findings {
		if strings.Contains(f.Label, "Redis") && strings.Contains(f.Label, "gopher://") {
			found = true
			if f.Confidence != ConfidenceConfirmed {
				t.Errorf("Redis confidence = %q, want %q", f.Confidence, ConfidenceConfirmed)
			}
		}
	}
	if !found {
		t.Fatalf("no Redis gopher finding among %+v", findings)
	}
}

// TestProtocolModuleIgnoresPageEchoingPayload checks the echo guard: a page
// that reflects the gopher URL back, with no service behind it, must not be
// reported as the service answering.
func TestProtocolModuleIgnoresPageEchoingPayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("You asked for: " + r.URL.Query().Get("url")))
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL + "/fetch")
	findings := protocolFindings(runProtocolOnly(t, u))
	for _, f := range findings {
		if strings.Contains(f.Label, "Redis") || strings.Contains(f.Label, "memcached") {
			t.Fatalf("echoed payload reported as a service: %q", f.Label)
		}
	}
}

// TestProtocolModuleIgnoresServiceSignatureOnEveryRequest checks the control
// gate: a server whose every response carries the Redis banner, whatever the
// payload, is a page that always says it, not a fetch.
func TestProtocolModuleIgnoresServiceSignatureOnEveryRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("redis_version:7.2.4 static banner"))
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL + "/fetch")
	if findings := protocolFindings(runProtocolOnly(t, u)); len(findings) != 0 {
		t.Fatalf("a banner present on every response was reported: %+v", findings)
	}
}

// TestEndpointTargetsKeepsRealProducts checks the existence gate: an endpoint
// that answers in its own right is kept, and one that 404s is dropped.
func TestEndpointTargetsKeepsRealProducts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/proxy" {
			w.Write([]byte("proxy handler"))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	origin, _ := url.Parse(srv.URL)

	targets := endpointTargets(context.Background(), srv.Client(), origin, nil)
	var names []string
	for _, ft := range targets {
		names = append(names, ft.url.Path)
	}
	if !contains(names, "/proxy") {
		t.Fatalf("/proxy not kept; kept %v", names)
	}
	if contains(names, "/cors") {
		t.Fatalf("/cors kept although it 404s; kept %v", names)
	}
}

// TestEndpointTargetsDropsCatchAll checks the catch-all gate: a single-page
// app that serves the same page for every path must yield no endpoints, since
// it cannot tell a product from its own front end.
func TestEndpointTargetsDropsCatchAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body><div id=app>single page app shell</div></body></html>"))
	}))
	t.Cleanup(srv.Close)
	origin, _ := url.Parse(srv.URL)

	if targets := endpointTargets(context.Background(), srv.Client(), origin, nil); len(targets) != 0 {
		var paths []string
		for _, ft := range targets {
			paths = append(paths, ft.url.Path)
		}
		t.Fatalf("catch-all server produced endpoints: %v", paths)
	}
}

// contains reports whether s holds v.
func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
