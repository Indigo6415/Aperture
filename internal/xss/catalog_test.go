package xss

import (
	"strings"
	"testing"
)

// TestDalfoxTableSizes pins the size of each table ported from dalfox's
// src/payload/xss_*.rs. The counts are dalfox's own, so a regenerated table that
// silently lost entries fails here.
func TestDalfoxTableSizes(t *testing.T) {
	want := map[string]struct{ got, n int }{
		"JS primitives (short)":    {len(dalfoxJSPrimitivesSmall), 17},
		"JS primitives (script)":   {len(dalfoxJSPrimitives), 26},
		"HTML templates":           {len(dalfoxHTMLTemplates), 56},
		"mXSS templates":           {len(dalfoxMXSSTemplates), 12},
		"event-handler names":      {len(dalfoxEventHandlerNames), 98},
		"DOM-clobbering templates": {len(dalfoxDOMClobberingTemplates), 8},
		"blind templates":          {len(dalfoxBlindTemplates), 3},
	}
	for name, w := range want {
		if w.got != w.n {
			t.Errorf("%s: %d entries, want %d (dalfox's count)", name, w.got, w.n)
		}
	}
}

// TestCatalogFamiliesAreWellFormed checks every family has a unique ID, a name,
// a severity, and candidates, and that no candidate still carries an unfilled
// placeholder. A placeholder left in a payload would be sent literally.
func TestCatalogFamiliesAreWellFormed(t *testing.T) {
	const canary = "apxss0123456789ab"
	seen := map[string]bool{}
	for _, fam := range buildCatalogFamilies(canary) {
		if seen[fam.id] {
			t.Errorf("duplicate family id %q", fam.id)
		}
		seen[fam.id] = true
		if fam.name == "" || fam.severity == "" {
			t.Errorf("family %q is missing a name or severity", fam.id)
		}
		if fam.list == nil {
			t.Errorf("family %q has no candidate list", fam.id)
			continue
		}
		candidates := fam.list(canary)
		if len(candidates) == 0 {
			t.Errorf("family %q has no candidates", fam.id)
		}
		for _, p := range candidates {
			for _, ph := range []string{"{JS}", "{CLASS}", "{ID}"} {
				if strings.Contains(p, ph) {
					t.Errorf("family %q: candidate %q still has %s", fam.id, p, ph)
				}
			}
		}
	}
}

// TestCatalogMarkersCarryTheCanary checks that a marker-carrying template is filled
// with values built from the run's canary, so a reflection of it can be attributed.
func TestCatalogMarkersCarryTheCanary(t *testing.T) {
	const canary = "apxss0123456789ab"
	got := fillCatalogMarkers(`<img data-x={CLASS} id={ID}>`, canary)
	want := `<img data-x=` + canary + `c id=` + canary + `i>`
	if got != want {
		t.Errorf("fillCatalogMarkers = %q, want %q", got, want)
	}
}

// TestCompactTemplatesAreShortest checks the marker-free variants. They are the
// short forms a length-limited reflection can still carry, sorted shortest first.
// {JS} stays in them: the family builder fills it with a primitive.
func TestCompactTemplatesAreShortest(t *testing.T) {
	compact := compactTemplates()
	if len(compact) == 0 {
		t.Fatal("no compact templates")
	}
	for i, c := range compact {
		if strings.Contains(c, "{CLASS}") || strings.Contains(c, "{ID}") {
			t.Errorf("compact template %q kept a marker", c)
		}
		if i > 0 && len(compact[i-1]) > len(c) {
			t.Errorf("compact templates not sorted: %q before %q", compact[i-1], c)
		}
	}
}

// TestProtocolURIMatch checks the javascript: URI judge. A browser drops tabs and
// newlines from a URL before it resolves the scheme, so a split scheme counts in a
// URL attribute, and the same text in plain body text does not.
func TestProtocolURIMatch(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		payload string
		want    bool
	}{
		{"javascript: in href", `<a href="javascript:alert(1)">`, `javascript:alert(1)`, true},
		{"tab-split scheme in href", "<a href=\"java\tscript:alert(1)\">", "java\tscript:alert(1)", true},
		{"javascript: in body text", `<p>javascript:alert(1)</p>`, `javascript:alert(1)`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, got := protocolURIMatch(tc.body, tc.payload, "")
			if got != tc.want {
				t.Errorf("protocolURIMatch = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAutomaticHandlerNamesAreAutomatic checks the event family keeps only handlers
// that fire without the user acting, since an interaction handler is never counted.
func TestAutomaticHandlerNamesAreAutomatic(t *testing.T) {
	auto := automaticHandlerNames(orderedHandlerNames())
	if len(auto) == 0 {
		t.Fatal("no automatic handlers")
	}
	for _, n := range auto {
		if !handlerFiresOn(n, " autofocus "+n+"=x", "input") && n != "onload" && n != "onerror" && n != "ontoggle" {
			t.Errorf("handler %q is in the event family but is not automatic", n)
		}
	}
}

// TestCandidatesRespectTheProbeAndBudget checks candidate selection. Nothing sent
// uses a stripped character, every candidate is distinct, and the budget caps the
// total.
func TestCandidatesRespectTheProbeAndBudget(t *testing.T) {
	const canary = "apxss0123456789ab"
	var probe probeResult
	probe.reflected = true
	probe.survives = allTrue()
	probe.survives['<'] = false
	probe.survives['>'] = false

	deps := runDeps{
		families: append(append([]payloadDef{}, payloadModules...), buildCatalogFamilies(canary)...),
		canary:   canary,
		budget:   40,
	}
	cands := deps.candidates(&probe)
	if len(cands) == 0 || len(cands) > deps.budget {
		t.Fatalf("got %d candidates, want between 1 and the budget of %d", len(cands), deps.budget)
	}
	seen := map[string]bool{}
	for _, c := range cands {
		if strings.ContainsAny(c.payload, "<>") {
			t.Errorf("candidate %q uses a stripped angle bracket", c.payload)
		}
		if seen[c.payload] {
			t.Errorf("candidate %q was sent twice", c.payload)
		}
		seen[c.payload] = true
	}
}
