package xss

// blind.go is the blind-XSS module, ported from dalfox's xss_blind payloads and its
// out-of-band callback flow. A blind payload is stored by the application and runs
// later, somewhere the scanner never looks: an admin panel, a log viewer. So the
// payloads carry a callback URL on the shared collaborator, and the scanner waits
// for the callback to come back, rather than looking for a reflection.
//
// Each injection point gets one token (or the operator's shared token), and each
// blind template gets its own identifier under it. A callback names the point and
// template that produced it, so a hit maps back to exactly one request.

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Indigo6415/Aperture/internal/collaborator"
)

// OOBConfig is how Run reaches the shared callback listener for the blind-XSS
// module. The zero value disables the module, and it is left out of the result.
type OOBConfig struct {
	Registry *collaborator.Registry
	// CallbackBaseURL is this Aperture instance's own externally reachable
	// scheme://host[:port], used to build each token's HTTP callback address.
	CallbackBaseURL string
	// SharedToken and SharedProvider name a callback server the operator picked
	// instead of minting one token per point. SharedProvider is "aperture"
	// (polled through Registry) or "webhooksite" (polled through
	// collaborator.PollWebhookSite, SharedToken then being its UUID).
	SharedToken    string
	SharedProvider string
}

// blindUsable reports whether oob names a callback listener the module can both
// send to and read back from. A webhook.site token needs no registry or base URL;
// every other mode needs both.
func blindUsable(oob OOBConfig) bool {
	if oob.SharedToken != "" && oob.SharedProvider == "webhooksite" {
		return true
	}
	return oob.Registry != nil && oob.CallbackBaseURL != ""
}

// blindIdentifier labels one (point, template) pair. The label is short and
// URL-path safe, and parseBlindIdentifier reverses it.
func blindIdentifier(pointIdx, tmplIdx int) string {
	return "p" + strconv.Itoa(pointIdx) + "t" + strconv.Itoa(tmplIdx)
}

// blindIdentifierPattern matches a label that blindIdentifier produced.
var blindIdentifierPattern = regexp.MustCompile(`^p(\d+)t(\d+)$`)

// parseBlindIdentifier returns the point and template a callback label names.
// ok is false for a label this module did not write.
func parseBlindIdentifier(id string) (pointIdx, tmplIdx int, ok bool) {
	m := blindIdentifierPattern.FindStringSubmatch(id)
	if m == nil {
		return 0, 0, false
	}
	p, err1 := strconv.Atoi(m[1])
	t, err2 := strconv.Atoi(m[2])
	if err1 != nil || err2 != nil || t >= len(dalfoxBlindTemplates) {
		return 0, 0, false
	}
	return p, t, true
}

// blindRunsScript reports whether a template's callback proves script ran. A
// template whose handler fetches the callback (onerror) can only do so after
// JavaScript executed. The script-src shapes fire on markup parsing alone, so a
// hit from them proves the markup was parsed, not that the script ran.
func blindRunsScript(tmplIdx int) bool {
	return strings.Contains(dalfoxBlindTemplates[tmplIdx], "onerror")
}

// blindCallbackURL builds the callback address for one identifier under token.
// A webhook.site token is the UUID in its own URL; otherwise the callback goes
// through this instance's collaborator route.
func blindCallbackURL(oob OOBConfig, token, identifier string) string {
	if oob.SharedToken != "" && oob.SharedProvider == "webhooksite" {
		return collaborator.WebhookSiteCallbackURL(token) + "/" + identifier + "/"
	}
	return strings.TrimRight(oob.CallbackBaseURL, "/") + "/collab/" + token + "/" + identifier + "/"
}

// runBlindXSSModule stores every blind template at every injection point, waits
// for the callbacks, and reports each point whose callback came back. A point
// reports once, with its strongest hit: a callback that proves script ran beats a
// markup-only one.
func runBlindXSSModule(ctx context.Context, deps runDeps, oob OOBConfig) []Finding {
	findings := []Finding{}
	if !blindUsable(oob) {
		return findings
	}
	deps.rep.Phase("Sending blind XSS callbacks")

	// tokenFor is the token each point's payloads call back to.
	tokenFor := make([]string, len(deps.points))
	for i := range deps.points {
		if oob.SharedToken != "" {
			tokenFor[i] = oob.SharedToken
		} else {
			tokenFor[i] = oob.Registry.NewToken()
		}
	}

	// sent keeps the request each (point, template) pair sent, so a hit can cite it.
	sent := map[string]CapturedRequest{}
	client := newClient()
	for i, pt := range deps.points {
		for t, tmpl := range dalfoxBlindTemplates {
			identifier := blindIdentifier(i, t)
			callback := blindCallbackURL(oob, tokenFor[i], identifier)
			payload := strings.ReplaceAll(tmpl, "{}", callback)
			res := fetchInjectionPointThrottled(ctx, deps.sem, client, pt, payload, deps.req.Headers)
			if res.Err == nil {
				sent[identifier] = res.Request
			}
		}
	}

	hits := collectBlindHits(ctx, deps, oob, tokenFor)

	// The strongest hit per point is the one reported.
	best := map[int]collaborator.Interaction{}
	bestTmpl := map[int]int{}
	for _, h := range hits {
		p, t, ok := parseBlindIdentifier(h.Identifier)
		if !ok || p >= len(deps.points) {
			continue
		}
		if cur, seen := bestTmpl[p]; seen && (blindRunsScript(cur) || !blindRunsScript(t)) {
			continue
		}
		best[p] = h
		bestTmpl[p] = t
	}

	for i := range deps.points {
		h, ok := best[i]
		if !ok {
			continue
		}
		t := bestTmpl[i]
		pt := deps.points[i]
		identifier := blindIdentifier(i, t)
		req := sent[identifier]
		confidence := ConfidenceLikely
		strength := "a markup-only callback: the browser parsed the stored payload's tag and fetched the URL, which does not prove script ran"
		if blindRunsScript(t) {
			confidence = ConfidenceConfirmed
			strength = "a script-run callback: the stored payload's onerror handler ran in a browser and fetched the URL"
		}
		findings = append(findings, Finding{
			Label: fmt.Sprintf("%s stores input that calls back out of band (blind XSS)", capitalize(pointDescriptor(pt))),
			Detail: fmt.Sprintf(
				"Set %s to a payload that calls back to the collaborator, and a %s %s arrived later from %s, showing the stored value is rendered in a browser somewhere the scanner cannot see. This is %s.",
				pointDescriptor(pt), h.Protocol, h.Method, h.RemoteAddr, strength,
			),
			Evidence:   fmt.Sprintf("callback %s %s from %s", h.Method, h.Path, h.RemoteAddr),
			Method:     pt.Method,
			Request:    &req,
			Confidence: confidence,
		})
	}
	return findings
}

// collectBlindHits waits for callbacks on every point's token and returns what
// arrived. A webhook.site shared token is polled through its own API, and any
// other token through the registry.
func collectBlindHits(ctx context.Context, deps runDeps, oob OOBConfig, tokenFor []string) []collaborator.Interaction {
	if oob.SharedToken != "" && oob.SharedProvider == "webhooksite" {
		hits, _ := collaborator.WaitForCallbacks(ctx, func(c context.Context) ([]collaborator.Interaction, error) {
			return collaborator.PollWebhookSite(c, oob.SharedToken)
		}, collaborator.DefaultPollInterval, collaborator.DefaultQuietPeriod, collaborator.DefaultMaxWait)
		return hits
	}
	tokens := tokenFor
	if oob.SharedToken != "" {
		tokens = []string{oob.SharedToken}
	}
	collaborator.WaitForRegistry(ctx, oob.Registry, tokens, collaborator.DefaultPollInterval, collaborator.DefaultQuietPeriod, collaborator.DefaultMaxWait)
	var out []collaborator.Interaction
	if oob.Registry == nil {
		return out
	}
	seenToken := map[string]bool{}
	for _, t := range tokens {
		if seenToken[t] {
			continue
		}
		seenToken[t] = true
		out = append(out, oob.Registry.Poll(t)...)
	}
	return out
}
