package ssrf

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Indigo6415/Aperture/internal/scanprogress"
)

// testDeps starts handler on a test server and returns runDeps aimed at it,
// with the given points and primary baseline body. Every request in the test
// goes to this server, so no test ever reaches a real metadata or internal host.
func testDeps(t *testing.T, handler http.HandlerFunc, points []probePoint, baseline string) runDeps {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	target, err := parseTarget(srv.URL + "/fetch")
	if err != nil {
		t.Fatal(err)
	}
	return newRunDeps(target, http.MethodGet, Request{}, points, make(chan struct{}, maxConcurrentRequests), scanprogress.Or(nil), baseline, newClient())
}

// TestEchoedPayloadIsNotAnInternalAnomaly checks the reflection false positive:
// a page that prints whatever URL it was given differs from every control only
// by that echoed URL. With echoes scrubbed, nothing should be reported.
func TestEchoedPayloadIsNotAnInternalAnomaly(t *testing.T) {
	deps := testDeps(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body><p>You asked for %s and it is noted for review.</p></body></html>", r.URL.Query().Get("url"))
	}, paramPoints([]string{"url"}), "")

	if findings := runInternalNetworkModule(context.Background(), deps); len(findings) != 0 {
		t.Errorf("echoed payload URL was reported as an internal address: %d finding(s), first: %q", len(findings), findings[0].Label)
	}
}

// TestInternalAddressDifferenceIsReported checks the positive case: loopback
// spellings get a dashboard, every other address gets the same failure page as
// the controls. The loopback payloads should be reported as likely.
func TestInternalAddressDifferenceIsReported(t *testing.T) {
	deps := testDeps(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("url")
		if strings.Contains(q, "127.0.0.1") || strings.Contains(q, "localhost") {
			fmt.Fprint(w, "<html><title>Internal billing dashboard</title><p>Metrics for the internal billing service, updated hourly across every region and tenant.</p></html>")
			return
		}
		fmt.Fprint(w, "<html><title>Connection failed</title><p>Could not reach that host.</p></html>")
	}, paramPoints([]string{"url"}), "")

	findings := runInternalNetworkModule(context.Background(), deps)
	if len(findings) == 0 {
		t.Fatal("loopback spellings answered differently from the controls but nothing was reported")
	}
	for _, f := range findings {
		if f.Confidence != ConfidenceLikely {
			t.Errorf("parameter finding confidence = %q, want %q", f.Confidence, ConfidenceLikely)
		}
	}
}

// TestHeaderPointRoutesToInternalHost checks the header injection location: a
// virtual-host router that serves a dashboard for a loopback Host header. The
// finding should be reported as heuristic and name the header.
func TestHeaderPointRoutesToInternalHost(t *testing.T) {
	deps := testDeps(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Host, "127.0.0.1") || strings.Contains(r.Host, "localhost") {
			fmt.Fprint(w, "<html><title>Admin console</title><p>Internal admin console with user management and audit logs for operators only.</p></html>")
			return
		}
		fmt.Fprint(w, "<html><title>Bad host</title><p>Unknown virtual host requested.</p></html>")
	}, headerPoints(), "")

	findings := runInternalNetworkModule(context.Background(), deps)
	if len(findings) == 0 {
		t.Fatal("a Host header routed to loopback was not reported")
	}
	for _, f := range findings {
		if f.Confidence != ConfidenceHeuristic {
			t.Errorf("header finding confidence = %q, want %q", f.Confidence, ConfidenceHeuristic)
		}
		if !strings.Contains(f.Label, "Header") {
			t.Errorf("header finding label does not name a header: %q", f.Label)
		}
	}
}

// TestCloudMetadataReportedWhenOnlyPayloadReturnsIt checks the cloud module's
// positive case: an endpoint that serves metadata content only for an address
// in the 169.254.169.254 range.
func TestCloudMetadataReportedWhenOnlyPayloadReturnsIt(t *testing.T) {
	deps := testDeps(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("url"), "169.254.169.254") {
			fmt.Fprint(w, "ami-id\ninstance-id\nlocal-hostname\n")
			return
		}
		fmt.Fprint(w, "<html><p>Welcome to the image importer.</p></html>")
	}, paramPoints([]string{"url"}), "")

	findings := runCloudMetadataModule(context.Background(), deps)
	if len(findings) == 0 {
		t.Fatal("metadata content returned only for the metadata address was not reported")
	}
	for _, f := range findings {
		if f.Confidence != ConfidenceConfirmed {
			t.Errorf("cloud finding confidence = %q, want %q", f.Confidence, ConfidenceConfirmed)
		}
	}
}

// TestCloudMetadataSuppressedWhenPageAlwaysShowsIt checks the baseline gating:
// a documentation page that always mentions metadata keys is not a metadata
// hit, whatever the parameter contains.
func TestCloudMetadataSuppressedWhenPageAlwaysShowsIt(t *testing.T) {
	deps := testDeps(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><p>Docs: the metadata keys are ami-id, instance-id and metadata-flavor.</p></html>")
	}, paramPoints([]string{"url"}), "")

	if findings := runCloudMetadataModule(context.Background(), deps); len(findings) != 0 {
		t.Errorf("page that always shows metadata keys was reported: %q", findings[0].Label)
	}
}

// TestCloudMetadataEchoedSignatureIsNotAHit checks the echo false positive: a
// page that prints the submitted URL back contains the signature
// "iam/security-credentials" only because the payload itself does. Scrubbing
// the echo must remove that match.
func TestCloudMetadataEchoedSignatureIsNotAHit(t *testing.T) {
	deps := testDeps(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<p>Invalid URL: %s</p>", r.URL.Query().Get("url"))
	}, paramPoints([]string{"url"}), "")

	if findings := runCloudMetadataModule(context.Background(), deps); len(findings) != 0 {
		t.Errorf("echoed payload was reported as metadata: %q", findings[0].Label)
	}
}

// TestCloudMetadataRedirectBounceIsLabelled checks the redirect-based SSRF: an
// endpoint that follows a same-origin redirect to metadata returns metadata
// content only for the bounce path. The finding should name the redirect.
func TestCloudMetadataRedirectBounceIsLabelled(t *testing.T) {
	deps := testDeps(t, func(w http.ResponseWriter, r *http.Request) {
		// A bounce payload's value is itself a same-origin URL containing "/redirect?url=".
		// An endpoint that follows it reaches the metadata address.
		if strings.Contains(r.URL.Query().Get("url"), "/redirect?url=") {
			fmt.Fprint(w, "ami-id\ninstance-id\n")
			return
		}
		fmt.Fprint(w, "<html><p>Welcome.</p></html>")
	}, paramPoints([]string{"url"}), "")

	findings := runCloudMetadataModule(context.Background(), deps)
	var bounce bool
	for _, f := range findings {
		if strings.Contains(f.Label, "same-origin redirect") {
			bounce = true
		}
	}
	if !bounce {
		t.Errorf("redirect-bounce metadata hit not labelled as a same-origin redirect: %+v", findings)
	}
}

// TestFileSchemeReadReported checks the file:// module's positive case: an
// endpoint that opens file:///etc/passwd and returns its contents.
func TestFileSchemeReadReported(t *testing.T) {
	deps := testDeps(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Query().Get("url"), "file:///etc/passwd") {
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
			return
		}
		fmt.Fprint(w, "<html><p>Import a document by URL.</p></html>")
	}, paramPoints([]string{"url"}), "")

	findings := runFileSchemeModule(context.Background(), deps)
	if len(findings) != 1 {
		t.Fatalf("file read findings = %d, want 1: %+v", len(findings), findings)
	}
	if findings[0].Confidence != ConfidenceConfirmed {
		t.Errorf("file read confidence = %q, want confirmed", findings[0].Confidence)
	}
}

// TestFileSchemeSuppressedWhenPageShowsPasswd checks the negative case: a page
// that documents the passwd format shows the same text for every input, so no
// file read is reported.
func TestFileSchemeSuppressedWhenPageShowsPasswd(t *testing.T) {
	deps := testDeps(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><pre>Example line: root:x:0:0:root:/root:/bin/bash</pre></html>")
	}, paramPoints([]string{"url"}), "")

	if findings := runFileSchemeModule(context.Background(), deps); len(findings) != 0 {
		t.Errorf("page that always shows a passwd line was reported: %q", findings[0].Label)
	}
}

// TestControlsFetchedOncePerPoint checks the shared control cache: the cloud,
// internal-network, and file modules all compare against the same controls, so
// each control must be sent exactly once per point, not once per module.
func TestControlsFetchedOncePerPoint(t *testing.T) {
	var blackholeHits atomic.Int32
	deps := testDeps(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("url") == blackholeURL {
			blackholeHits.Add(1)
		}
		fmt.Fprint(w, "<html><p>plain page</p></html>")
	}, paramPoints([]string{"url"}), "")

	runModulesForTarget(context.Background(), deps, OOBConfig{})
	if n := blackholeHits.Load(); n != 1 {
		t.Errorf("blackhole control sent %d times for one point across three modules, want 1", n)
	}
}

// TestRunReportsHeaderPointsTested checks that a full Run tests the header
// injection locations and says so in ParamsTested.
func TestRunReportsHeaderPointsTested(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><p>ok</p></html>")
	}))
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/"}, OOBConfig{})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, p := range res.ParamsTested {
		seen[p] = true
	}
	for _, h := range headerProbeNames {
		if !seen["header:"+h] {
			t.Errorf("ParamsTested does not include header:%s", h)
		}
	}
}

// TestScrubEchoesRemovesEveryReflectionForm checks that the echo scrub strips
// a payload in raw, query-escaped, and HTML-escaped form, so reflections in any
// of those encodings are removed.
func TestScrubEchoesRemovesEveryReflectionForm(t *testing.T) {
	target, _ := url.Parse("http://example.test/fetch")
	echoes := echoesFor(target)
	const payload = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
	body := "a " + payload + " b " + url.QueryEscape(payload) + " c " + htmlEscape(payload) + " d"
	scrubbed := scrubEchoes(body, echoes)
	for _, form := range []string{"169.254.169.254", "security-credentials"} {
		if strings.Contains(scrubbed, form) {
			t.Errorf("scrubbed body still contains %q: %q", form, scrubbed)
		}
	}
}

// TestPayloadTablesAreWellFormed checks the payload tables: no payload is sent
// twice, every entry has a description or provider, and every address parses.
func TestPayloadTablesAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range internalIPPayloads {
		if p.description == "" {
			t.Errorf("internal payload %q has no description", p.url)
		}
		if seen[p.url] {
			t.Errorf("internal payload %q is listed twice", p.url)
		}
		seen[p.url] = true
		if _, err := url.Parse(p.url); err != nil {
			t.Errorf("internal payload %q does not parse: %v", p.url, err)
		}
	}
	for _, p := range cloudMetadataPayloads {
		if p.provider == "" {
			t.Errorf("cloud payload %q has no provider", p.url)
		}
	}
	if len(internalIPPayloads) < 25 {
		t.Errorf("internal payload table has %d entries, expected at least 25", len(internalIPPayloads))
	}
}

// TestHeaderPointsOnlyInHeaderModule checks that header points are only tested by
// the module that sets headers. The cloud and file modules must never see them.
func TestHeaderPointsOnlyInHeaderModule(t *testing.T) {
	deps := runDeps{points: append(paramPoints([]string{"url"}), headerPoints()...)}
	if got := len(deps.pointsFor(cloudMetadataModule)); got != 1 {
		t.Errorf("cloud module sees %d points, want 1 (parameter only)", got)
	}
	if got := len(deps.pointsFor(internalNetworkModule)); got != 1+len(headerProbeNames) {
		t.Errorf("internal module sees %d points, want %d", got, 1+len(headerProbeNames))
	}
}

// TestControlCacheFetchesOnce checks the cache directly: concurrent callers for
// one point trigger a single fetch.
func TestControlCacheFetchesOnce(t *testing.T) {
	c := newControlCache()
	var calls atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.get(probePoint{name: "url"}, func() []*ssrfResult {
				calls.Add(1)
				return nil
			})
		}()
	}
	wg.Wait()
	if n := calls.Load(); n != 1 {
		t.Errorf("fetch ran %d times, want 1", n)
	}
}
