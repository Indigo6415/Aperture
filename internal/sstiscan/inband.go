package sstiscan

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// inBandRCEModule confirms command execution from the response body itself,
// rather than from an out-of-band callback. It is the in-band counterpart of
// oobRCEModule and borrows the same per-engine payloads (rceTemplatePayloads),
// but the command only echoes a fresh random word, so nothing on the target
// changes. Ported from tplmap's execute() stage, which proves execution the
// same way: a random marker printed back by the engine.
var inBandRCEModule = moduleMeta{id: "rce-output", name: "Template injection -> shell command output (in-band)", severity: "critical"}

// runInBandRCEModule runs probeInBandPoint on every point.
func runInBandRCEModule(ctx context.Context, deps runDeps) []Finding {
	client := newClient()
	return runPointModule(deps, inBandRCEModule, func(pt injectionPoint) (Finding, bool) {
		return probeInBandPoint(ctx, deps, client, pt)
	})
}

// probeInBandPoint sends each engine's command-execution payload with
// "echo <marker>" as the command, and reports the point only when the marker
// comes back as a whole word in the response. A reflected payload also
// contains the marker, so the echoed "echo <marker>" text is excluded.
func probeInBandPoint(ctx context.Context, deps runDeps, client *http.Client, pt injectionPoint) (Finding, bool) {
	// Each engine's payload is tried in turn with its own fresh marker.
	for _, rp := range rceTemplatePayloads {
		_, _, marker := freshMarker()
		payload := rp.build("echo " + marker)
		res := fetchInjectionPointThrottled(ctx, deps.sem, client, pt, payload, deps.req.Headers)
		if res.Err != nil {
			continue
		}
		// The marker must be new (absent from the baseline), show up as a whole
		// word, and not appear only as the echoed command text.
		if containsStandalone(deps.baseline, marker) || !containsStandalone(res.Body, marker) || strings.Contains(res.Body, "echo "+marker) {
			continue
		}
		return Finding{
			Label: fmt.Sprintf("%s ran an attacker-supplied shell command via template injection (output echoed)", pointDescriptor(pt)),
			Detail: fmt.Sprintf(
				"Set %s to the %s template payload `%s`, which runs `echo %s` on the server. The response contained the random word %s as a standalone token, and the original page did not, so the engine executed the command and rendered its output. The command only echoes that word and changes nothing on the target.",
				pointDescriptor(pt), rp.engine, payload, marker, marker,
			),
			Evidence:   marker,
			Method:     pt.Method,
			StatusCode: res.StatusCode,
			Request:    &res.Request,
			Confidence: ConfidenceConfirmed,
		}, true
	}
	return Finding{}, false
}
