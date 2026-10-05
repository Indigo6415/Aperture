package sstiscan

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// maxContextLevel is the deepest template context the math-eval module tries.
// Level 1 covers the contexts tplmap runs at its default level: the value
// landing inside an existing {{ }}, ${ }, #{ }, {% %}, or ( ) / [ ] / quote
// pair. Deeper contexts (block tags, comments, attribute lists) multiply the
// request count, so they stay off until there is a reason to pay for them.
const maxContextLevel = 1

// closureSlot marks where a context's escape characters go inside its prefix.
const closureSlot = "{C}"

// level1Closures ports tplmap's level-1 closure matrix (utils/closures.py,
// ctx_closures in each language plugin). The first list is the string or
// integer the value may be sitting in; the second is an optional function or
// call that has to be closed first. One choice is taken from each list, so
// the candidates are 1', 1", 1, 1'), 1"), 1), and each of those combined
// with nothing at all.
var level1Closures = [][]string{
	{"1'", `1"`, "1"},
	{")", ""},
}

// tplContext is one place in an engine's own syntax that the injected value
// can land in. prefix is written before the engine tag and must first close
// the surrounding expression: closureSlot is replaced by each escape the
// closures matrix produces. suffix is written after the tag to balance
// whatever the template still expects. Ported from tplmap's set_contexts()
// tables in plugins/engines/*.py.
type tplContext struct {
	level    int
	prefix   string
	suffix   string
	closures [][]string
}

// Per-engine context tables. Each entry is one place the probe can be sent
// from inside an existing template tag, not just as bare text.
var (
	// Jinja2, Twig, Nunjucks, Tornado: {{ %s }} and {% %s %}.
	jinjaContexts = []tplContext{
		{level: 1, prefix: "{C}}}", closures: level1Closures},
		{level: 1, prefix: "{C}%}", closures: level1Closures},
	}
	// Smarty: {$var} tags, with the bare tag reopened afterwards.
	smartyContexts = []tplContext{
		{level: 1, prefix: "{C}}", suffix: "{", closures: level1Closures},
	}
	// FreeMarker, Mako, JSP EL, Spring EL, Groovy: ${ %s }.
	dollarContexts = []tplContext{
		{level: 1, prefix: "{C}}", closures: level1Closures},
	}
	// Velocity: #set($x=%s) and similar directive arguments.
	velocityContexts = []tplContext{
		{level: 1, prefix: "{C})", closures: level1Closures},
	}
	// Pug / Jade: attribute and interpolation contexts, with // commenting out
	// the rest of the line.
	pugContexts = []tplContext{
		{level: 1, prefix: "{C})", suffix: "//", closures: level1Closures},
	}
	// doT: {{= %s }} inside a JavaScript-style statement.
	dotContexts = []tplContext{
		{level: 1, prefix: "{C};}}", suffix: "{{1;", closures: level1Closures},
	}
	// EJS: <%= %s %> closed with %> and reopened with a comment.
	ejsContexts = []tplContext{
		{level: 1, prefix: "{C}%>", suffix: "<%#", closures: level1Closures},
	}
)

// expandClosures returns every escape a closures matrix can produce: one
// choice from each list, concatenated in order. Duplicates are dropped and the
// shortest escapes come first, so the least intrusive one is tried before the
// longer ones. An empty matrix yields a single empty escape.
func expandClosures(matrix [][]string) []string {
	combos := []string{""}
	// Each list multiplies the candidates by its own length, so every
	// combination of one choice per list is built up in turn.
	for _, choices := range matrix {
		next := make([]string, 0, len(combos)*len(choices))
		for _, base := range combos {
			for _, c := range choices {
				next = append(next, base+c)
			}
		}
		combos = next
	}

	seen := map[string]bool{}
	out := []string{}
	// Drop repeats so one escape is not sent twice.
	for _, c := range combos {
		if seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i]) < len(out[j]) })
	return out
}

// contextVariant is one prefix/suffix pair a probe is sent inside. The zero
// value is the plain text context, which is how every probe was sent before
// context escapes were added.
type contextVariant struct {
	prefix, suffix string
	// closure is the escape that produced prefix, empty for the text context.
	closure string
}

// tplProbe is one engine-specific probe. wrap is the engine's own tag with a
// single %s for the expression, and expr returns a fresh expression plus the
// text its evaluation renders. contexts lists the places inside an existing
// tag the same probe is also sent from.
type tplProbe struct {
	engine      string
	jinjaFamily bool
	wrap        string
	expr        func() (expression, expected string)
	contexts    []tplContext
}

// fire builds one payload for this probe inside v's prefix and suffix, drawing
// fresh expression values each time so a page cannot repeat a fixed answer.
func (p tplProbe) fire(v contextVariant) (payload, expected string) {
	expression, expected := p.expr()
	return v.prefix + fmt.Sprintf(p.wrap, expression) + v.suffix, expected
}

// neutral builds the negative control for v: the same surrounding context, but
// the expression is replaced with a value that cannot evaluate to anything the
// probe expects.
func (p tplProbe) neutral(v contextVariant) string {
	return v.prefix + fmt.Sprintf(p.wrap, neutralMathValue) + v.suffix
}

// variants returns the text context first, then each escape of each context
// whose level is within maxContextLevel, shallowest level first.
func (p tplProbe) variants() []contextVariant {
	out := []contextVariant{{}}
	ctxs := append([]tplContext{}, p.contexts...)
	sort.SliceStable(ctxs, func(i, j int) bool { return ctxs[i].level < ctxs[j].level })
	// Every context is expanded into one variant per escape it allows.
	for _, ctx := range ctxs {
		if ctx.level > maxContextLevel {
			continue
		}
		for _, c := range expandClosures(ctx.closures) {
			out = append(out, contextVariant{
				prefix:  strings.ReplaceAll(ctx.prefix, closureSlot, c),
				suffix:  ctx.suffix,
				closure: c,
			})
		}
	}
	return out
}

// mathExpr is the arithmetic expression every engine family shares. Its
// product is seven or eight digits, so a page is unlikely to show it by chance.
func mathExpr() (string, string) {
	a, b, product := freshOperands()
	return fmt.Sprintf("%d*%d", a, b), product
}

// markerExpr returns a digit-free string-join expression, for engines where a
// number would be too easy to misread.
func markerExpr(quote, op string) func() (string, string) {
	return func() (string, string) {
		left, right, joined := freshMarker()
		return quote + left + quote + op + quote + right + quote, joined
	}
}

// tplProbes lists the engine probes in the order they are tried on a point.
// Each engine has an arithmetic probe that is also tried from inside its
// template contexts; the digit-free concatenation probes are tried bare only.
//
// Engine syntax and contexts follow tplmap's plugins/engines tables. Labels
// match sstiProbes so existing tests and findings keep their names.
func tplProbes() []tplProbe {
	return []tplProbe{
		{engine: "Jinja2 / Twig / Nunjucks / Pebble / Tornado", jinjaFamily: true, wrap: "{{%s}}", expr: mathExpr, contexts: jinjaContexts},
		{engine: "Jinja2 / Twig (string-concatenation marker)", wrap: "{{%s}}", expr: markerExpr("'", "~")},
		// Python repeats a string on multiplication, while Twig and Nunjucks
		// compute 11*7. This is the probe that tells Python's Jinja2 apart.
		{engine: "Jinja2 (Python string-multiply)", wrap: "{{%s}}", expr: func() (string, string) {
			return "11*'7'", jinjaStringMultiplyExpected
		}},
		{engine: "FreeMarker / Mako / JSP EL / Spring EL / Groovy", wrap: "${%s}", expr: mathExpr, contexts: dollarContexts},
		{engine: "FreeMarker / Mako / JSP EL / Groovy (string-concatenation marker)", wrap: "${%s}", expr: markerExpr("'", "+")},
		{engine: "ERB / EJS", wrap: "<%%= %s %%>", expr: mathExpr, contexts: ejsContexts},
		{engine: "ERB / EJS (string-concatenation marker)", wrap: "<%%= %s %%>", expr: markerExpr("'", "+")},
		{engine: "Razor (ASP.NET)", wrap: "@(%s)", expr: mathExpr},
		{engine: "Razor (ASP.NET) (string-concatenation marker)", wrap: "@(%s)", expr: markerExpr(`"`, "+")},
		{engine: "Smarty ({math} plugin)", wrap: `{math equation="%s"}`, expr: mathExpr, contexts: smartyContexts},
		{engine: "Smarty (bare expression)", wrap: "{%s}", expr: mathExpr},
		{engine: "Velocity", wrap: "#set($aperture=%s)$aperture", expr: mathExpr, contexts: velocityContexts},
		{engine: "Thymeleaf (inline expression)", wrap: "[[${%s}]]", expr: mathExpr},
		{engine: "Pug / Jade / JSF EL", wrap: "#{%s}", expr: mathExpr, contexts: pugContexts},
		{engine: "doT (Node)", wrap: "{{=%s}}", expr: mathExpr, contexts: dotContexts},
	}
}

// jinjaMultipliesInContext reports whether v's context evaluates Python string
// multiplication. A sibling engine returns a different value, so only Python's
// Jinja2 yields the expected string here.
func jinjaMultipliesInContext(ctx context.Context, deps runDeps, client *http.Client, pt injectionPoint, v contextVariant) bool {
	payload := v.prefix + jinjaStringMultiplyPayload + v.suffix
	res := fetchInjectionPointThrottled(ctx, deps.sem, client, pt, payload, deps.req.Headers)
	return res.Err == nil && containsStandalone(res.Body, jinjaStringMultiplyExpected)
}

// probeEnginePoint tries every engine probe on one point, first in the text
// context and then from inside each template context, stopping at the first
// that evaluates. A hit must survive the neutral control and a second probe
// with fresh values, sent from the same context, before it is reported.
func probeEnginePoint(ctx context.Context, deps runDeps, client *http.Client, pt injectionPoint) (Finding, bool) {
	// Probes are tried one after another, and each probe tries all its
	// contexts before the next probe starts.
	for _, p := range tplProbes() {
		for _, v := range p.variants() {
			payload, expected := p.fire(v)
			res := fetchInjectionPointThrottled(ctx, deps.sem, client, pt, payload, deps.req.Headers)
			if res.Err != nil || !evaluated(res.Body, payload, expected, deps.baseline) {
				continue
			}

			// Negative control: the same context with a value that cannot
			// evaluate. If the expected result still shows, the page prints it on
			// its own.
			control := fetchInjectionPointThrottled(ctx, deps.sem, client, pt, p.neutral(v), deps.req.Headers)
			if control.Err == nil && containsStandalone(control.Body, expected) {
				continue
			}

			// Confirmation: the same context with fresh values must evaluate as
			// well. A coincidence or a one-off reflection will not repeat.
			payload2, expected2 := p.fire(v)
			confirm := fetchInjectionPointThrottled(ctx, deps.sem, client, pt, payload2, deps.req.Headers)
			if confirm.Err != nil || !evaluated(confirm.Body, payload2, expected2, deps.baseline) {
				continue
			}

			engine := p.engine
			// Only Python's Jinja2 repeats a string on multiplication. If the
			// string-multiply probe gives its expected result in this same context,
			// the engine is Jinja2 rather than a sibling sharing the {{ }} syntax.
			if p.jinjaFamily && jinjaMultipliesInContext(ctx, deps, client, pt, v) {
				engine = "Jinja2 (Python)"
			}

			where := ""
			// A context hit names the escape and context used, so the operator can
			// see it was a break-out and not a plain tag.
			if v.closure != "" {
				where = fmt.Sprintf(" from inside an existing template tag (escape `%s`, prefix `%s`, suffix `%s`)", v.closure, v.prefix, v.suffix)
			}
			return Finding{
				Label: fmt.Sprintf("Possible %s SSTI via %s", engine, pointDescriptor(pt)),
				Detail: fmt.Sprintf(
					"Set %s to the template expression `%s`%s; the response body then contained `%s` (the evaluated result) instead of the literal payload text. The result was not on the original page, a neutral value did not produce it, and a second probe with new values evaluated the same way, so the server evaluated this value as a %s template expression.",
					pointDescriptor(pt), payload, where, expected, engine,
				),
				Evidence:   expected,
				Method:     pt.Method,
				StatusCode: res.StatusCode,
				Request:    &res.Request,
				Confidence: ConfidenceConfirmed,
			}, true
		}
	}
	return Finding{}, false
}
