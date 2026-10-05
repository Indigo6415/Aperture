package xss

import "testing"

// TestDOMFlowDetectsTaintedSinks checks the core taint model: a value that comes
// from a source and reaches a sink is a flow, and the same sink with a clean
// value is not. The cases cover the source and sink families dalfox tracks.
func TestDOMFlowDetectsTaintedSinks(t *testing.T) {
	cases := []struct {
		name   string
		script string
		sink   string // empty means no flow is expected
	}{
		{"location hash to innerHTML", `el.innerHTML = location.hash;`, "innerHTML"},
		{"window.location search via substring", `el.innerHTML = window.location.search.substring(1);`, "innerHTML"},
		{"document.URL to eval", `eval(document.URL);`, "eval"},
		{"referrer to location.href", `location.href = document.referrer;`, "location"},
		{"window.name to document.write", `document.write(window.name);`, "document.write"},
		{"localStorage getItem to innerHTML", `el.innerHTML = localStorage.getItem("k");`, "innerHTML"},
		{"sessionStorage object read to eval", `eval(sessionStorage.payload);`, "eval"},
		{"postMessage data to innerHTML", `window.addEventListener("message", function (e) { el.innerHTML = e.data; });`, "innerHTML"},
		{"script src from storage", `s.src = localStorage.getItem("u");`, "src"},
		{"dangerous setAttribute name", `el.setAttribute("href", location.hash);`, "setAttribute"},
		{"execCommand insertHTML", `document.execCommand("insertHTML", false, location.hash);`, "execCommand"},
		{"new Function from source", `new Function(location.hash)();`, "Function"},
		{"setTimeout with string from source", `setTimeout(location.hash, 0);`, "setTimeout"},

		{"textContent is not a sink", `el.textContent = location.hash;`, ""},
		{"DOMPurify sanitizes", `el.innerHTML = DOMPurify.sanitize(location.hash);`, ""},
		{"encodeURIComponent sanitizes", `location.assign(encodeURIComponent(location.hash));`, ""},
		{"user-defined encoder by name", `function encodeHTML(s){ return s.replace(/</g, "&lt;"); } el.innerHTML = encodeHTML(location.hash);`, ""},
		{"non-dangerous attribute", `el.setAttribute("class", location.hash);`, ""},
		{"data attribute is not dangerous", `el.setAttribute("data-x", location.hash);`, ""},
		{"execCommand with a non-HTML command", `document.execCommand("bold", false, location.hash);`, ""},
		{"clean literal reaches the sink", `el.innerHTML = "<b>static</b>";`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flows, err := analyzeDOMScript(tc.script)
			if err != nil {
				t.Fatalf("analyzeDOMScript: %v", err)
			}
			if tc.sink == "" {
				if len(flows) != 0 {
					t.Fatalf("expected no flow, got %+v", flows)
				}
				return
			}
			if !hasFlow(flows, tc.sink) {
				t.Fatalf("expected a flow into %q, got %+v", tc.sink, flows)
			}
		})
	}
}

// TestDOMFlowFollowsValuesAcrossCode checks the interprocedural and flow-sensitive
// parts: a taint that crosses a helper, a closure, a method, an alias, or a
// strong reassignment. A flow that is cut by a clean reassignment must not report.
func TestDOMFlowFollowsValuesAcrossCode(t *testing.T) {
	cases := []struct {
		name   string
		script string
		want   bool
	}{
		{"through a helper's parameter", `function show(x){ el.innerHTML = x; } show(location.hash);`, true},
		{"helper called before its declaration", `later(location.hash); function later(x){ document.write(x); }`, true},
		{"through a returned value", `function src(){ return location.hash; } el.innerHTML = src();`, true},
		{"through an object property", `var o = {}; o.h = location.hash; el.innerHTML = o.h;`, true},
		{"through an array index", `var a = [location.hash]; el.innerHTML = a[0];`, true},
		{"through apply's element mapping", `function f(a, b){ document.write(b); } f.apply(null, ["safe", location.hash]);`, true},
		{"apply with taint only on a non-sink parameter", `function f(a, b){ el.innerHTML = b; } f.apply(null, [location.hash, "safe"]);`, false},
		{"through call on a sink alias", `var w = document.write; w.call(document, location.hash);`, true},
		{"through bind with a tainted prefix", `var w = document.write.bind(document, location.hash); w();`, true},
		{"through a class method", `class C { m(x){ el.innerHTML = x; } } new C().m(location.hash);`, true},
		{"through a static class method", `class C { static s(x){ document.write(x); } } C.s(location.hash);`, true},
		{"through Reflect.apply", `Reflect.apply(document.write, document, [location.hash]);`, true},
		{"through Reflect.construct Function", `Reflect.construct(Function, [location.hash]);`, true},
		{"through a message handler function", `function h(e){ el.innerHTML = e.data; } window.addEventListener("message", h);`, true},
		{"reassigned to a literal before the sink", `var x = location.hash; x = "static"; el.innerHTML = x;`, false},
		{"reassigned to a sanitized value", `var x = location.hash; x = DOMPurify.sanitize(x); el.innerHTML = x;`, false},
		{"assigned inside a branch", `var x = "a"; if (cond) { x = location.hash; } el.innerHTML = x;`, true},
		{"assigned inside a loop", `var x = ""; for (var i = 0; i < 3; i++) { x = location.hash; } document.write(x);`, true},
		{"computed sink name by concatenation", `window["doc" + "ument"]["wri" + "te"](location.hash);`, true},
		{"computed property name for innerHTML", `el["inner" + "HTML"] = location.hash;`, true},
		{"template literal keeps taint", "el.innerHTML = `<b>${location.hash}</b>`;", true},
		{"tainted function-name lookup keeps taint", `var r = localStorage.getItem.bind(localStorage); el.innerHTML = r("k");`, true},
		{"self-recursive function terminates", `function r(x){ return r(x); } el.innerHTML = r(location.hash);`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flows, err := analyzeDOMScript(tc.script)
			if err != nil {
				t.Fatalf("analyzeDOMScript: %v", err)
			}
			if got := len(flows) > 0; got != tc.want {
				t.Fatalf("flow = %v, want %v (flows %+v)", got, tc.want, flows)
			}
		})
	}
}

// TestDOMFlowReportsSourceOrigin checks the origin a flow records, which the
// finding names as the source: the exact path read, not just the container.
func TestDOMFlowReportsSourceOrigin(t *testing.T) {
	flows, err := analyzeDOMScript(`el.innerHTML = location.hash;`)
	if err != nil {
		t.Fatalf("analyzeDOMScript: %v", err)
	}
	if len(flows) != 1 || flows[0].origin != "location.hash" {
		t.Fatalf("origin = %+v, want one flow from location.hash", flows)
	}
}

// TestDOMFlowRejectsUnparseableScripts checks that a script the parser cannot read
// returns an error, which sends the caller to the regex fallback.
func TestDOMFlowRejectsUnparseableScripts(t *testing.T) {
	if _, err := analyzeDOMScript(`function (`); err == nil {
		t.Fatal("expected a parse error for a broken script")
	}
}

// hasFlow reports whether any flow reaches the named sink.
func hasFlow(flows []domFlow, sink string) bool {
	for _, f := range flows {
		if f.sink == sink {
			return true
		}
	}
	return false
}
