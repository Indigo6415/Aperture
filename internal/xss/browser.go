package xss

import (
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/adapters"
)

// verifyTimeout bounds one headless render of a candidate URL.
const verifyTimeout = 20 * time.Second

// verifyMarkerAttr is the attribute a verification payload writes onto <html>.
const verifyMarkerAttr = "data-apx"

// alertCall matches the alert(...) call every payload module uses to show
// that code ran. verifyPayload swaps it for a DOM write.
var alertCall = regexp.MustCompile(`alert\([^)]*\)`)

// verifyPayload rewrites a module payload so that, when executed, it sets an
// attribute carrying canary on the document element instead of calling alert.
// The breakout is unchanged, so this tests the same reflection, but the effect
// can be read back from the rendered DOM.
func verifyPayload(payload, canary string) string {
	setter := fmt.Sprintf("document.documentElement.setAttribute('%s','%s')", verifyMarkerAttr, canary)
	return alertCall.ReplaceAllLiteralString(payload, setter)
}

// neutralize escapes a payload's markup characters. The result shows the same
// text but cannot break out of anything, so it is the negative control: if
// the marker still appears with neutralized input, the page writes the marker
// on its own and the browser result says nothing about the reflection.
func neutralize(payload string) string {
	return strings.NewReplacer("<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;").Replace(payload)
}

// withParamValue returns rawURL with one query parameter replaced. It is used
// to rebuild the exact request an injection point makes, with a different value.
func withParamValue(rawURL, param, value string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// renderMarker loads rawURL in a headless browser and reports whether the
// rendered DOM carries the marker attribute with the expected value. It
// returns an error (not a false result) when no browser is installed, so the
// caller can tell "not executed" from "could not check".
func renderMarker(ctx context.Context, rawURL, canary string) (bool, error) {
	chrome, err := adapters.FindChromeBinary()
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()
	args := []string{
		"--headless=new",
		"--disable-gpu",
		"--no-sandbox",
		"--disable-extensions",
		"--virtual-time-budget=2000",
		"--dump-dom",
		rawURL,
	}
	out, err := exec.CommandContext(ctx, chrome, args...).Output()
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, fmt.Errorf("xss: headless render failed: %w", err)
	}
	return strings.Contains(string(out), verifyMarkerAttr+`="`+canary+`"`), nil
}

// verifyPointFinding runs the browser check for one candidate, with the
// negative control, and returns the finding with its confidence set:
//   - "confirmed": the payload set the marker, and the neutralized control did not;
//   - "likely": the browser could not run, the control also set the marker (so
//     the check is inconclusive), or the request was not browser-replayable.
//
// Only GET query and form-field injections can be replayed here. Header and
// POST injections keep the confidence the static check gave them.
func verifyPointFinding(ctx context.Context, pf pointFinding, canary string) pointFinding {
	if !pf.browserable {
		return pf
	}
	target, err := withParamValue(pf.finding.Request.URL, pf.param, verifyPayload(pf.payload, canary))
	if err != nil {
		return pf
	}
	control, err := withParamValue(pf.finding.Request.URL, pf.param, verifyPayload(neutralize(pf.payload), canary))
	if err != nil {
		return pf
	}

	executed, err := renderMarker(ctx, target, canary)
	if err != nil {
		pf.finding.Detail += " Not executed in a browser: " + err.Error() + "."
		return pf
	}
	if !executed {
		pf.finding.Detail += " A headless browser loaded the candidate URL and the injected code did not run, so this stays unconfirmed."
		return pf
	}
	controlRan, err := renderMarker(ctx, control, canary)
	if err != nil || controlRan {
		pf.finding.Detail += " The browser executed the payload, but the neutralized control also produced the marker, so the check is inconclusive."
		return pf
	}
	pf.finding.Confidence = ConfidenceConfirmed
	pf.finding.Detail += " Confirmed in a headless browser: the injected code wrote its marker to the rendered page, and the neutralized control did not."
	return pf
}
