package openredirect

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

// crlfTemplate is one CR/LF header-injection shape. template is the value put
// in a parameter, with {id} standing for the probe's identifier and {poison}
// for the callback address carrying it. header is the response header the
// shape tries to inject: a Set-Cookie named after the identifier, or a
// Location pointing at the callback.
type crlfTemplate struct {
	name     string
	template string
	header   string
}

// crlfTemplates is the CR/LF families from Oralyzer's CRLF scanner (its
// Set-Cookie canary and Location payloads), with the canary and callback in
// place of its fixed cookie and google.com. Shapes that are percent-encoded
// in the template reach the app still encoded, so they only inject on an app
// that decodes a second time. The rest inject on a single decode.
var crlfTemplates = []crlfTemplate{
	{"CRLF Set-Cookie", "\r\nSet-Cookie:{id}=1;", "Set-Cookie"},
	// Obsolete line folding: a tab or a space after the CRLF continues the
	// previous header, and some parsers read the injected line anyway.
	{"tab-folded CRLF Set-Cookie", "\r\n\tSet-Cookie:{id}=1;", "Set-Cookie"},
	{"space-folded CRLF Set-Cookie", "\r\n Set-Cookie:{id}=1;", "Set-Cookie"},
	{"percent-encoded CRLF Set-Cookie", "%0d%0aSet-Cookie:{id}=1;", "Set-Cookie"},
	// Two UTF-8 bytes that a legacy decoder swallows, leaving the CRLF behind.
	{"UTF-8 bogus-char CRLF Set-Cookie", "%E5%98%8A%E5%98%8D%0D%0ASet-Cookie:{id}=1;", "Set-Cookie"},
	// A Location injected into the response, which redirects to the callback
	// when the app writes no Location of its own.
	{"CRLF Location", "\r\nLocation:https://{poison}/", "Location"},
	{"percent-encoded CRLF Location", "%0d%0aLocation:https://{poison}/", "Location"},
}

// crlfProbe is one request built from a crlfTemplate, with the identifier its
// injected header must carry to count as a hit.
type crlfProbe struct {
	tpl        crlfTemplate
	identifier string
	spec       probeSpec
}

// crlfProbes builds one probe per (candidate parameter, template). Each probe
// has its own identifier, so the header it injects can be pinned to it alone.
func crlfProbes(d runDeps) []crlfProbe {
	out := make([]crlfProbe, 0, len(d.params)*len(crlfTemplates))
	// Every template is tried against every candidate parameter.
	for _, p := range d.params {
		for _, t := range crlfTemplates {
			identifier := openRedirectIdentifierFor("crlf-injection", p+" "+t.name, d.nonce)
			value := strings.NewReplacer("{id}", identifier, "{poison}", d.poison(identifier)).Replace(t.template)
			out = append(out, crlfProbe{
				tpl:        t,
				identifier: identifier,
				spec: probeSpec{
					label:      fmt.Sprintf("Parameter %q", p),
					sent:       fmt.Sprintf("%s=%s", p, value),
					identifier: identifier,
					rawURL:     withParam(d.target, p, value),
				},
			})
		}
	}
	return out
}

// crlfInjected reports whether the response carries a header of the probe's
// kind whose value holds its identifier. The identifier is random per run, so
// the match can't come from anything the app would send anyway.
func crlfInjected(h http.Header, header, identifier string) bool {
	// Check each value of that header kind for the identifier.
	for _, v := range h.Values(header) {
		if strings.Contains(v, identifier) {
			return true
		}
	}
	return false
}

// runCRLF sends every CR/LF probe and reports each one whose injected header
// shows up in the response. The header is itself the proof, so no callback is
// needed, and these findings are confirmed as soon as the response arrives.
func runCRLF(ctx context.Context, d runDeps, sent *atomic.Int64) []Finding {
	probes := crlfProbes(d)
	sent.Add(int64(len(probes)))

	var (
		mu  sync.Mutex
		out = []Finding{}
		wg  sync.WaitGroup
	)
	// Each probe runs on its own goroutine, bounded by the shared concurrency limit.
	for _, cp := range probes {
		wg.Add(1)
		go func(cp crlfProbe) {
			defer wg.Done()
			res, hop, err := d.timedSend(ctx, "probe", cp.spec.rawURL, d.req.Headers)
			if err != nil || !crlfInjected(res.Header, cp.tpl.header, cp.identifier) {
				return
			}
			chain := []ChainHop{hop}
			finalizeChain(chain)
			f := crlfFinding(cp, res, chain)
			mu.Lock()
			out = append(out, f)
			mu.Unlock()
		}(cp)
	}
	wg.Wait()
	return out
}

// crlfFinding turns a probe whose injected header was seen in the response
// into a Finding. Its detail names the header the probe injected and the
// request that did it.
func crlfFinding(cp crlfProbe, res *orResult, chain []ChainHop) Finding {
	return Finding{
		Label: fmt.Sprintf("%s injects a response header via %s", cp.tpl.name, cp.spec.label),
		Detail: fmt.Sprintf(
			"Sent %s and the response carried a %s header holding this probe's identifier (%s). The app wrote the value's raw CR/LF into its response headers, so an attacker can set headers the app never intended: a session cookie, a Location that redirects the visitor, or a forged response body on servers that split responses.",
			cp.spec.sent, cp.tpl.header, cp.identifier,
		),
		Evidence:   fmt.Sprintf("injected %s header in the response to %s", cp.tpl.header, cp.spec.label),
		Method:     http.MethodGet,
		StatusCode: res.StatusCode,
		Request:    &res.Request,
		Chain:      chain,
		Confidence: ConfidenceConfirmed,
	}
}

// crlfModule is the CR/LF header-injection check. It runs with no callback
// configured, because it judges the response headers directly (see direct).
var crlfModule = moduleDef{
	id: "crlf-injection", name: "CRLF header injection", severity: "medium",
	direct: runCRLF,
}
