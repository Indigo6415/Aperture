package secretscan

import "testing"

// TestWithHeadersGivesEachMatchItsOwnCopy checks that every match gets the
// crawl's headers, and that editing one match's map leaves the others alone.
func TestWithHeadersGivesEachMatchItsOwnCopy(t *testing.T) {
	matches := []Match{{Location: "https://h/a.js"}, {Location: "https://h/b.js"}}
	out := withHeaders(matches, map[string]string{"Authorization": "Bearer abc"})

	out[0].Headers["Authorization"] = "changed"

	if out[1].Headers["Authorization"] != "Bearer abc" {
		t.Errorf("second match header = %q, want the crawl's original value", out[1].Headers["Authorization"])
	}
}

// TestWithHeadersNoHeadersLeavesMatchesNil checks that a crawl without
// headers doesn't attach an empty map to its matches.
func TestWithHeadersNoHeadersLeavesMatchesNil(t *testing.T) {
	out := withHeaders([]Match{{Location: "https://h/a.js"}}, nil)
	if out[0].Headers != nil {
		t.Errorf("headers = %v, want nil", out[0].Headers)
	}
}
