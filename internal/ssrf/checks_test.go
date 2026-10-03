package ssrf

import (
	"strings"
	"testing"
)

// ctl builds a control result with a body.
func ctl(status int, body string) *ssrfResult {
	return &ssrfResult{StatusCode: status, ContentLength: len(body), Body: body}
}

// TestDynamicBodyLengthIsNotAnAnomaly checks the false-positive fix: a page whose
// length changes on every request (a timestamp, a token) must not look like a
// connection to an internal address, when its content is the same.
func TestDynamicBodyLengthIsNotAnAnomaly(t *testing.T) {
	page := strings.Repeat("<p>Welcome to the dashboard. Your recent activity appears below.</p>\n", 6)
	controls := []*ssrfResult{
		ctl(200, page+"<!-- generated 2026-10-03T12:00:01Z -->"),
		ctl(200, page+"<!-- generated 2026-10-03T12:00:02Z request 8f3a2c91 -->"),
		ctl(200, page+"<!-- generated 2026-10-03T12:00:03Z request 1b7d0e44 -->"),
	}
	payload := ctl(200, page+"<!-- generated 2026-10-03T12:00:09Z request 9c2e7a10 -->")
	if _, anomalous := differsFromControls(payload, controls); anomalous {
		t.Error("a page that only changed in dynamic tokens was reported as an internal-address response")
	}
}

// TestDifferentContentFromEveryControlIsAnomaly checks the true positive: a body
// that differs in content from all three controls, with the same status, is an
// anomaly.
func TestDifferentContentFromEveryControlIsAnomaly(t *testing.T) {
	controls := []*ssrfResult{
		ctl(200, "<html><title>Connection failed</title><p>Could not reach that host.</p></html>"),
		ctl(200, "<html><title>Connection failed</title><p>Could not reach that host.</p></html>"),
		ctl(200, "<html><title>Connection failed</title><p>Could not reach that host.</p></html>"),
	}
	payload := ctl(200, "<html><title>Internal dashboard</title><p>Metrics for the internal billing service, updated hourly.</p></html>")
	if _, anomalous := differsFromControls(payload, controls); !anomalous {
		t.Error("content unlike every control was not reported as anomalous")
	}
}

// TestOneMatchingControlClearsTheFinding checks that a payload matching any
// control is not reported. Requiring a difference from all controls is what
// keeps a single odd control from producing findings for every payload.
func TestOneMatchingControlClearsTheFinding(t *testing.T) {
	same := "<html><title>Connection failed</title><p>Could not reach that host.</p></html>"
	controls := []*ssrfResult{
		ctl(200, same),
		ctl(200, "<html><title>Odd control</title><p>Unrelated text.</p></html>"),
		ctl(200, same),
	}
	payload := ctl(200, same)
	if _, anomalous := differsFromControls(payload, controls); anomalous {
		t.Error("payload matching one control was reported")
	}
}
