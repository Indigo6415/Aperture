package xss

import "testing"

// TestScriptPayloadRunsFollowsLexerState checks the script-body rule. A payload
// runs only when some of its characters are code: outside a string, outside a
// comment, and not a template-literal's text. The landing state decides which.
func TestScriptPayloadRunsFollowsLexerState(t *testing.T) {
	cases := []struct {
		name    string
		state   htmlState
		payload string
		want    bool
	}{
		{"plain code runs", htmlState{kind: ctxScript}, `alert(1)`, true},
		{"a payload that opens a string in code is inert", htmlState{kind: ctxScript}, `';alert(1);'`, false},
		{"a quote in a string closes it, then code runs", htmlState{kind: ctxScript, quote: '\''}, `';alert(1);'`, true},
		{"plain text inside a template literal is inert", htmlState{kind: ctxScript, quote: '`'}, `alert(1)`, false},
		{"a backtick breakout from a template literal runs", htmlState{kind: ctxScript, quote: '`'}, "`;alert(1);`", true},
		{"a template expression runs", htmlState{kind: ctxScript, quote: '`'}, "${alert(1)}", true},
		{"a line comment hides code until a newline", htmlState{kind: ctxScript, jsComment: '/'}, "alert(1)", false},
		{"code after a newline in a line comment runs", htmlState{kind: ctxScript, jsComment: '/'}, "\nalert(1)", true},
		{"a block comment hides code until its close", htmlState{kind: ctxScript, jsComment: '*'}, "x */alert(1)", true},
		{"markup in code is not valid JavaScript", htmlState{kind: ctxScript}, `<img src=x>(1)`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scriptPayloadRuns(tc.state, tc.payload); got != tc.want {
				t.Errorf("scriptPayloadRuns = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestHandlerFiringRules checks which event handlers run without the user acting,
// and on which elements. An injected handler that cannot fire on its element is
// inert, so the payload does not count as executing.
func TestHandlerFiringRules(t *testing.T) {
	cases := []struct {
		name     string
		injected string
		host     string
		inert    bool
	}{
		{"onerror on a div is inert", ` onerror=alert(1) x=`, "div", true},
		{"onerror on an img runs", ` onerror=alert(1) x=`, "img", false},
		{"onload on a div is inert", ` onload=alert(1) x=`, "div", true},
		{"onload on an iframe runs", ` onload=alert(1) x=`, "iframe", false},
		{"onfocus with autofocus on a link is inert", ` autofocus onfocus=alert(1) x=`, "a", true},
		{"onfocus with autofocus on an input runs", ` autofocus onfocus=alert(1) x=`, "input", false},
		{"onfocus with tabindex on a div runs", ` autofocus onfocus=alert(1) tabindex=0 x=`, "div", false},
		{"onfocus without autofocus needs the user", ` onfocus=alert(1) x=`, "input", true},
		{"mouseover needs the user", ` onmouseover=alert(1) x=`, "div", true},
		{"onclick needs the user", ` onclick=alert(1) x=`, "a", true},
		{"ontoggle on details runs", ` open ontoggle=alert(1) x=`, "details", false},
		{"markup starts its own element", `><img src=x onerror=alert(1)>`, "div", false},
		{"interaction handler on new markup is inert", `><div onmouseover=alert(1)>`, "span", true},
		{"script alongside an interaction handler runs", `><div onclick=x><script>alert(1)</script>`, "span", false},
		{"begin on SVG animate runs", `><svg><animate onbegin=alert(1) attributeName=x dur=1s>`, "div", false},
		{"no handler is not inert", `javascript:alert(1)`, "a", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := handlersInertOn(tc.injected, tc.host); got != tc.inert {
				t.Errorf("handlersInertOn(%q, %q) = %v, want %v", tc.injected, tc.host, got, tc.inert)
			}
		})
	}
}

// TestPayloadExecutesRespectsHandlerFiring checks the handler rules through the
// public check: a handler breakout executes only when its element fires it.
func TestPayloadExecutesRespectsHandlerFiring(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		payload string
		want    bool
	}{
		{"onerror breakout in a div is inert", `<div data-x="" onerror=alert(1) x="">`, `" onerror=alert(1) x="`, false},
		{"onerror breakout in an img runs", `<img src=x data-x="" onerror=alert(1) x="">`, `" onerror=alert(1) x="`, true},
		{"interaction breakout in text is inert", `<p><div onmouseover=alert(1)></p>`, `<div onmouseover=alert(1)>`, false},
		{"svg onload in text runs", `<p><svg onload=alert(1)></p>`, `<svg onload=alert(1)>`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := payloadExecutes(tc.body, tc.payload); got != tc.want {
				t.Errorf("payloadExecutes = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestPayloadRunsInScriptBody checks the JavaScript-response rule, which applies
// to a JSONP callback or any other script file a page loads.
func TestPayloadRunsInScriptBody(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		payload string
		want    bool
	}{
		{"JSONP callback name runs", `/**/ alert(1)({"status":"ok"});`, `alert(1)`, true},
		{"reflection inside a JS string is inert", `var x = "alert(1)";`, `alert(1)`, false},
		{"a breakout from a JS string runs", `var x = "";alert(1);"";`, `";alert(1);"`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := payloadRunsInScriptBody(tc.body, tc.payload); got != tc.want {
				t.Errorf("payloadRunsInScriptBody = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestIsJavaScriptResponse checks the content types a script file is served as.
func TestIsJavaScriptResponse(t *testing.T) {
	for ct, want := range map[string]bool{
		"application/javascript":         true,
		"text/javascript; charset=utf-8": true,
		"application/ecmascript":         true,
		"text/html":                      false,
		"application/json":               false,
	} {
		if got := isJavaScriptResponse(ct); got != want {
			t.Errorf("isJavaScriptResponse(%q) = %v, want %v", ct, got, want)
		}
	}
}
