package report

import (
	"strings"
	"testing"

	"github.com/Indigo6415/Aperture/internal/store"
)

// TestRenderHTMLEscapesCaseFields checks that operator- and target-supplied text
// is escaped in the HTML report, so a case name carrying markup can't inject
// script into the page.
func TestRenderHTMLEscapesCaseFields(t *testing.T) {
	payload := `<img src=x onerror=alert(1)>`
	r := Report{Case: store.Case{Name: payload}}
	html, err := r.RenderHTML()
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	out := string(html)
	if strings.Contains(out, "<img src=x") {
		t.Fatal("raw markup from the case name reached the HTML output unescaped")
	}
	if !strings.Contains(out, "&lt;img") {
		t.Fatal("expected the case name to appear HTML-escaped")
	}
}

// TestRenderJSONRoundTripsCaseName checks the JSON export is valid and carries
// the case name through unchanged.
func TestRenderJSONRoundTripsCaseName(t *testing.T) {
	r := Report{Case: store.Case{ID: "c1", Name: "Acme"}}
	raw, err := r.RenderJSON()
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	if !strings.Contains(string(raw), `"name": "Acme"`) && !strings.Contains(string(raw), `"name":"Acme"`) {
		t.Fatalf("case name missing from JSON: %s", raw)
	}
}
