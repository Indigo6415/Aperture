package pathtraversal

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Indigo6415/Aperture/internal/collaborator"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
)

// oobCallbackModule is the one check here that does not read a file. It puts a
// callback address where the point's value goes. If the application fetches a
// path it was handed as a URL (remote file inclusion, or a download that accepts
// a URL), the collaborator listener records a hit. That is a fetch, not a read,
// so its finding says so.
var oobCallbackModule = moduleMeta{id: "oob-callback", name: "Path input fetched as a URL (out-of-band callback)", severity: "high"}

// OOBConfig is how Run reaches the collaborator listener for oobCallbackModule.
// The zero value (nil Registry) leaves that module out of the run, and the
// file-read modules run either way.
type OOBConfig struct {
	Registry *collaborator.Registry
	// CallbackBaseURL is this Aperture instance's own externally reachable
	// scheme://host[:port], used to build each callback address.
	CallbackBaseURL string
	// DNSDomain, when set, adds a DNS-hostname address per point, which catches
	// a fetch whose outbound HTTP is blocked but whose DNS lookup is not.
	DNSDomain string
	// SharedToken/SharedProvider, when set, name a callback server the operator
	// picked from their Callback picker (see collaborator.Ref). Every point's
	// address then shares that token, and each point is told apart by its own
	// identifier. SharedProvider is "aperture" or "webhooksite". SharedToken==""
	// mints a fresh token per point instead.
	SharedToken    string
	SharedProvider string
}

// oobConfigured reports whether oob names a usable callback listener. A
// webhook.site server needs no Aperture listener, since it is hosted elsewhere.
func oobConfigured(oob OOBConfig) bool {
	if oob.SharedToken != "" && oob.SharedProvider == "webhooksite" {
		return true
	}
	return oob.Registry != nil && oob.CallbackBaseURL != ""
}

// oobProbe is one point's callback address. token is the collaborator token its
// URLs carry. ident is the identifier that tells its hits apart on a shared
// token, and is empty when the point has a token of its own.
type oobProbe struct {
	pt    point
	token string
	ident string
}

// oobProbes gives every point its callback address: a fresh token each, or a
// shared token with an identifier per point.
func oobProbes(oob OOBConfig, points []point) []oobProbe {
	probes := make([]oobProbe, len(points))
	for i, pt := range points {
		if oob.SharedToken == "" {
			probes[i] = oobProbe{pt: pt, token: oob.Registry.NewToken()}
			continue
		}
		probes[i] = oobProbe{pt: pt, token: oob.SharedToken, ident: fmt.Sprintf("pt-%d", i)}
	}
	return probes
}

// urls returns the callback addresses one point sends: an HTTP address on the
// listener, plus a DNS-hostname address when DNSDomain is set. A webhook.site
// server gets only its own HTTP address, since it has no DNS side here.
func (p oobProbe) urls(oob OOBConfig) []string {
	if oob.SharedProvider == "webhooksite" {
		return []string{collaborator.WebhookSiteCallbackURL(p.token) + "/" + p.ident + "/"}
	}
	path := strings.TrimRight(oob.CallbackBaseURL, "/") + "/collab/" + p.token + "/"
	if p.ident != "" {
		path += p.ident + "/"
	}
	out := []string{path}
	if oob.DNSDomain != "" {
		host := p.token
		if p.ident != "" {
			host = p.ident + "." + p.token
		}
		out = append(out, "http://"+host+"."+oob.DNSDomain+"/")
	}
	return out
}

// runOOBCallbackModule sends each point's callback address in place of its
// value, waits for the listener to settle, and reports every point that drew a
// hit. Requests share deps.sem with the other modules, so the throttle still
// bounds the whole run.
func runOOBCallbackModule(ctx context.Context, deps runDeps, oob OOBConfig) []Finding {
	probes := oobProbes(oob, deps.points)

	checks := make([]scanprogress.Check, len(probes))
	for i, p := range probes {
		checks[i] = scanprogress.Check{ID: oobCheckID(p), Label: p.pt.label, Group: oobCallbackModule.name}
	}
	deps.rep.Plan(checks...)
	for _, p := range probes {
		deps.rep.Start(oobCheckID(p))
	}

	// sent records the request behind each point's HTTP address, so a hit can
	// show the value that caused it. Each goroutine writes only its own index.
	sent := make([]CapturedRequest, len(probes))
	var wg sync.WaitGroup
	for i, p := range probes {
		for j, u := range p.urls(oob) {
			wg.Add(1)
			go func(i, j int, p oobProbe, u string) {
				defer wg.Done()
				res := send(ctx, deps.client, deps.sem, p.pt.build(u))
				// urls lists the HTTP address first, so index 0 is that one.
				if j == 0 {
					sent[i] = res.Request
				}
			}(i, j, p, u)
		}
	}
	wg.Wait()

	deps.rep.Phase("Waiting for out-of-band callbacks")
	hits := waitOOBHits(ctx, oob, probes)

	out := []Finding{}
	for i, p := range probes {
		id := oobCheckID(p)
		if len(hits[i]) == 0 {
			deps.rep.Done(id, 0, nil)
			continue
		}
		h := hits[i][0]
		captured := sent[i]
		out = append(out, Finding{
			Label: "Arbitrary URL fetched via " + p.pt.label,
			Detail: fmt.Sprintf(
				"Put a callback address where the path was expected at %s, and the server called back: %d inbound %s interaction(s), the first from %s. The application fetched a value the client supplied as a URL. This is a fetch, not a file read, but it shows the input is trusted as a location, which can lead to remote file inclusion or SSRF.",
				p.pt.label, len(hits[i]), h.Protocol, h.RemoteAddr,
			),
			Evidence:   fmt.Sprintf("%s callback from %s at %s", h.Protocol, h.RemoteAddr, h.Timestamp.Format(time.RFC3339)),
			Payload:    captured.URL,
			Method:     captured.Method,
			Confidence: ConfidenceConfirmed,
			Request:    &captured,
		})
		deps.rep.Done(id, 1, nil)
	}
	return out
}

// oobCheckID is the progress key for one point's callback check. It is stable
// for a run, so Plan, Start and Done all refer to the same square.
func oobCheckID(p oobProbe) string {
	return oobCallbackModule.id + "|" + p.pt.id
}

// waitOOBHits waits for the listener to settle, then returns each probe's hits,
// indexed like probes. A failed webhook.site poll discards what it returned, so
// every point then reads as no callback rather than as a partial result.
func waitOOBHits(ctx context.Context, oob OOBConfig, probes []oobProbe) [][]collaborator.Interaction {
	out := make([][]collaborator.Interaction, len(probes))

	// Per-point tokens: each point's hits sit under its own token.
	if oob.SharedToken == "" {
		tokens := make([]string, len(probes))
		for i, p := range probes {
			tokens[i] = p.token
		}
		collaborator.WaitForRegistry(ctx, oob.Registry, tokens, collaborator.DefaultPollInterval, collaborator.DefaultQuietPeriod, collaborator.DefaultMaxWait)
		for i, p := range probes {
			out[i] = oob.Registry.Poll(p.token)
		}
		return out
	}

	// Shared token: every point's hits sit under one token, grouped by the
	// identifier each probe carried.
	var hits []collaborator.Interaction
	if oob.SharedProvider == "webhooksite" {
		h, err := collaborator.WaitForCallbacks(ctx, func(c context.Context) ([]collaborator.Interaction, error) {
			return collaborator.PollWebhookSite(c, oob.SharedToken)
		}, collaborator.DefaultPollInterval, collaborator.DefaultQuietPeriod, collaborator.DefaultMaxWait)
		if err == nil {
			hits = h
		}
	} else {
		collaborator.WaitForRegistry(ctx, oob.Registry, []string{oob.SharedToken}, collaborator.DefaultPollInterval, collaborator.DefaultQuietPeriod, collaborator.DefaultMaxWait)
		hits = oob.Registry.Poll(oob.SharedToken)
	}

	byIdent := map[string][]collaborator.Interaction{}
	for _, h := range hits {
		byIdent[h.Identifier] = append(byIdent[h.Identifier], h)
	}
	for i, p := range probes {
		out[i] = byIdent[p.ident]
	}
	return out
}
