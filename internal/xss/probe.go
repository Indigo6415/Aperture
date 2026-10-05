package xss

// probe.go is the character-survival probe, ported from the reflection check in
// dalfox's scanning/check_reflection and its adaptive payload generator. One
// request per injection point carries the characters a payload is built from,
// between two markers. The characters that come back verbatim decide which
// payloads can run at that point. A payload that needs a character the filter
// strips or encodes cannot work, so it is never sent.

import (
	"context"
	"html"
	"net/http"
	"strings"
)

// probeSpecials are the characters payloads are built from: markup delimiters,
// quotes, call parentheses, the assignment and separator characters, backtick,
// and the space that separates attributes.
const probeSpecials = "<>\"'()=`;:/ "

// probeTokens are the words and fragments that filters commonly strip: the
// names of the execution primitives, the URL scheme, and the handler and tag
// names. A second probe sends them together; a token that does not come back
// is stripped, and every payload that contains it is dropped.
var probeTokens = []string{
	"alert", "prompt", "confirm", "eval", "Function",
	"javascript:", "<script", "<svg", "<img", "<iframe",
	"onerror=", "onload=", "onfocus=", "ontoggle=", "autofocus",
}

// wafBlockedStatuses are response codes a WAF or rate limiter returns for a
// suspicious request. A probe that gets one of these says nothing about which
// characters survive, so the point falls back to the unfiltered candidates.
var wafBlockedStatuses = map[int]bool{
	http.StatusForbidden:          true,
	http.StatusNotAcceptable:      true,
	http.StatusTooManyRequests:    true,
	http.StatusNotImplemented:     true,
	http.StatusServiceUnavailable: true,
}

// probeResult is what the probe learned about one injection point.
type probeResult struct {
	// reflected is true when the probe came back in the response between its markers.
	reflected bool
	// blocked is true when the server refused the probe itself.
	blocked bool
	// marker is the opening marker the probe carried. It is the evidence for the
	// "reflected but not executable" note when no payload runs.
	marker string
	// res is the probe's response, kept so the note can cite the request.
	res xssResult
	// stripped lists the probeTokens the filter removed from the response. A
	// payload containing one of them cannot be delivered intact.
	stripped []string
	// survives is indexed by byte. It is true for each probeSpecials character
	// that came back unchanged. When the probe was blocked, every entry is true,
	// since the probe says nothing about what the server would have passed.
	survives [256]bool
}

// probeMarkers returns the opening and closing markers for the probe. They come
// from the run's canary, but are short (six characters each), so the whole probe
// still fits under a length limit such as a truncate:30 filter.
func probeMarkers(canary string) (open, closer string) {
	return "pb" + canary[5:9], "pe" + canary[9:13]
}

// probePoint sends the probes to pt and reads back what the server lets through.
// The first probe finds which probeSpecials characters come back verbatim; the
// second, sent only if the first reflected, finds which probeTokens come back.
// The markers come from the run's canary, so a page cannot contain them unless
// it echoed this probe.
//
// A response that echoes the markers only after HTML references are decoded is
// still a reflection, but none of the probe's characters survived as-is, so every
// survival flag stays false and only the escaped note can come from it.
func probePoint(ctx context.Context, sem chan struct{}, client *http.Client, pt injectionPoint, canary string, headers map[string]string) probeResult {
	open, closer := probeMarkers(canary)
	res := fetchInjectionPointThrottled(ctx, sem, client, pt, open+probeSpecials+closer, headers)
	if res.Err != nil {
		return probeResult{}
	}
	if wafBlockedStatuses[res.StatusCode] {
		return probeResult{blocked: true, survives: allTrue(), marker: open, res: *res}
	}
	out := probeResult{marker: open, res: *res}
	if segment, ok := probeSegment(res.Body, open, closer); ok {
		out.reflected = true
		for i := 0; i < len(probeSpecials); i++ {
			c := probeSpecials[i]
			out.survives[c] = strings.IndexByte(segment, c) >= 0
		}
		out.stripped = strippedTokens(ctx, sem, client, pt, canary, headers)
		return out
	}
	decoded := html.UnescapeString(res.Body)
	if strings.Contains(decoded, open) && strings.Contains(decoded, closer) {
		out.reflected = true
	}
	return out
}

// probeSegment returns the text between the probe's markers. ok is false when
// either marker is missing, or when the closer does not follow the opener.
func probeSegment(body, open, closer string) (string, bool) {
	_, rest, found := strings.Cut(body, open)
	if !found {
		return "", false
	}
	segment, _, found := strings.Cut(rest, closer)
	return segment, found
}

// strippedTokens sends the token probe and returns each probeTokens entry that
// did not come back. A probe that fails to reflect (for example, one a length
// limit cut off) reports nothing stripped, so no payload is dropped on a guess.
func strippedTokens(ctx context.Context, sem chan struct{}, client *http.Client, pt injectionPoint, canary string, headers map[string]string) []string {
	open, closer := probeMarkers(canary)
	res := fetchInjectionPointThrottled(ctx, sem, client, pt, open+" "+strings.Join(probeTokens, " ")+closer, headers)
	if res.Err != nil {
		return nil
	}
	segment, ok := probeSegment(res.Body, open, closer)
	if !ok {
		return nil
	}
	var out []string
	for _, tok := range probeTokens {
		if !strings.Contains(segment, tok) {
			out = append(out, tok)
		}
	}
	return out
}

// allTrue returns a survival table in which every probe character passes.
func allTrue() [256]bool {
	var out [256]bool
	for i := 0; i < len(probeSpecials); i++ {
		out[probeSpecials[i]] = true
	}
	return out
}

// viable reports whether a payload can be delivered intact at this point: every
// probe character it uses came back unchanged, and it uses none of the tokens the
// filter strips. A payload that fails either test cannot run, so sending it would
// only add a request.
func (p *probeResult) viable(payload string) bool {
	for i := 0; i < len(payload); i++ {
		c := payload[i]
		// Only the probe's characters are checked. Everything else in a payload,
		// such as letters, digits and the canary, is not subject to the probe.
		if strings.IndexByte(probeSpecials, c) >= 0 && !p.survives[c] {
			return false
		}
	}
	for _, tok := range p.stripped {
		if strings.Contains(payload, tok) {
			return false
		}
	}
	return true
}
