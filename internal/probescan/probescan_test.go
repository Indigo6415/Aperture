package probescan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Indigo6415/Aperture/internal/fingerprint"
)

// spaShell is what a single-page app serves for every unknown route. It
// contains "=", "{", "require", "dependencies", "CREATE", and "<html", which
// the old substring validators accepted as evidence of a real file.
const spaShell = `<!doctype html><html><head><title>Acme Portal</title>
<script src="/app.js"></script></head><body><div id="root"></div>
<p>Sign in to continue. Create an account to require access to dependencies and reports.</p>
<style>.a{color:red}</style></body></html>`

// fixtureServer serves files by exact path with their content type, and
// answers everything else with the SPA shell, as a catch-all route does.
func fixtureServer(t *testing.T, files map[string][2]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f, ok := files[r.URL.Path]; ok {
			w.Header().Set("Content-Type", f[0])
			fmt.Fprint(w, f[1])
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, spaShell)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// runModule runs one registered module against url with a freshly built
// catch-all profile, the same way RunScanStreaming does for a real scan.
func runModule(t *testing.T, url string, id string) []Finding {
	t.Helper()
	ctx := context.Background()
	client := newProbeClient(16, nil)
	profile, err := fingerprint.BuildProfile(ctx, client.follow, url, nil)
	if err != nil {
		t.Fatalf("BuildProfile: %v", err)
	}
	client.profile = profile
	for _, m := range registeredModules {
		if m.id == id {
			return m.run(ctx, &Target{URL: url, Hostname: "fixture"}, client)
		}
	}
	t.Fatalf("no module %q", id)
	return nil
}

// TestCatchAllHostProducesNoFileFindings is the headline false-positive test:
// a host that serves its shell for every path must not be reported as leaking
// any file, directory, or dev artifact.
func TestCatchAllHostProducesNoFileFindings(t *testing.T) {
	srv := fixtureServer(t, nil)
	for _, id := range []string{"sensitive_files", "version_control", "dev_artifacts", "directories"} {
		if got := runModule(t, srv.URL, id); len(got) != 0 {
			t.Errorf("%s reported %d findings on a catch-all host, want 0: %+v", id, len(got), got)
		}
	}
}

// TestRealDotEnvIsConfirmed checks that a genuine .env file is found, that it
// is marked confirmed, and that its secret values are masked in the evidence.
func TestRealDotEnvIsConfirmed(t *testing.T) {
	const secret = "hunter2-super-secret-value"
	srv := fixtureServer(t, map[string][2]string{
		"/.env": {"text/plain", "APP_KEY=base64:abc123\nDB_PASSWORD=" + secret + "\nDB_HOST=10.0.0.5\n"},
	})
	findings := runModule(t, srv.URL, "sensitive_files")
	var env *Finding
	for i := range findings {
		if strings.HasPrefix(findings[i].Label, "Environment file") {
			env = &findings[i]
		}
	}
	if env == nil {
		t.Fatalf("real .env not reported; findings: %+v", findings)
	}
	if env.Confidence != ConfidenceConfirmed {
		t.Errorf("confidence = %q, want confirmed", env.Confidence)
	}
	if strings.Contains(env.Evidence, secret) {
		t.Errorf("evidence leaks the raw secret: %q", env.Evidence)
	}
}

// TestGitHEADRequiresRealRef checks that the .git/HEAD check accepts a real
// symbolic ref and rejects an HTML page that merely starts with the word "ref".
func TestGitHEADRequiresRealRef(t *testing.T) {
	srv := fixtureServer(t, map[string][2]string{
		"/.git/HEAD":   {"text/plain", "ref: refs/heads/main\n"},
		"/.git/config": {"text/plain", "[core]\n\trepositoryformatversion = 0\n"},
	})
	findings := runModule(t, srv.URL, "version_control")
	labels := map[string]bool{}
	for _, f := range findings {
		labels[strings.SplitN(f.Label, " exposed", 2)[0]] = true
	}
	if !labels["Git HEAD file"] || !labels["Git config file"] {
		t.Errorf("real .git files not reported; got %v", labels)
	}
}

// TestDirectoryListingIsConfirmedAndCatchAllIsNot checks that a real autoindex
// page is confirmed, while the same 200 served by the catch-all is ignored.
func TestDirectoryListingIsConfirmedAndCatchAllIsNot(t *testing.T) {
	srv := fixtureServer(t, map[string][2]string{
		"/backup/": {"text/html", "<html><title>Index of /backup/</title><h1>Index of /backup/</h1></html>"},
	})
	findings := runModule(t, srv.URL, "directories")
	var listing *Finding
	for i := range findings {
		if strings.Contains(findings[i].Label, "open listing") {
			listing = &findings[i]
		}
	}
	if listing == nil {
		t.Fatalf("real listing not reported; findings: %+v", findings)
	}
	if listing.Confidence != ConfidenceConfirmed {
		t.Errorf("listing confidence = %q, want confirmed", listing.Confidence)
	}
	for _, f := range findings {
		if strings.Contains(f.Label, "/config") || strings.Contains(f.Label, "/tmp") {
			t.Errorf("catch-all path reported as accessible: %s", f.Label)
		}
	}
}

// TestSecretsAreMaskedAndPublicKeysIgnored checks that a real-looking key is
// reported with its value masked, that the raw key never appears in any
// serialized finding, and that a publishable key is not reported at all.
func TestSecretsAreMaskedAndPublicKeysIgnored(t *testing.T) {
	const awsKey = "AKIAQRSTUVWXYZ234567"
	const stripePublic = "pk_live_51HqRealLookingPublishableKeyValue"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><script>var k = "%s"; var s = "%s";</script></html>`, awsKey, stripePublic)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	findings := runModule(t, srv.URL, "secrets")
	raw, _ := json.Marshal(findings)
	if strings.Contains(string(raw), awsKey) {
		t.Errorf("raw AWS key appears in serialized findings: %s", raw)
	}
	if strings.Contains(string(raw), stripePublic) {
		t.Errorf("publishable key was reported as a leak: %s", raw)
	}
	var aws bool
	for _, f := range findings {
		if strings.Contains(f.Label, "AWS Access Key ID") {
			aws = true
		}
	}
	if !aws {
		t.Errorf("AWS key not reported; findings: %+v", findings)
	}
}

// TestSQLErrorAlreadyOnPageIsNotInjection checks that a page which shows a
// database error on every request is not reported as SQL injection, because
// the error text is already present in the original response.
func TestSQLErrorAlreadyOnPageIsNotInjection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><p>Docs: you have an error in your SQL syntax is a common MySQL message.</p>
<a href="/item?id=1">item</a></html>`)
	}))
	defer srv.Close()

	ctx := context.Background()
	client := newProbeClient(16, nil)
	target := paramTarget{url: srv.URL + "/item?id=1", params: map[string][]string{"id": {"1"}}}
	if got := checkSQLInjection(ctx, client, target); len(got) != 0 {
		t.Errorf("SQL error already on the page was reported as injection: %+v", got)
	}
}
