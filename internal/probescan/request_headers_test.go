package probescan

import "testing"

// TestWithRequestHeadersStampsScanHeadersOnURLFindings checks that a finding
// with a URL gets the scan's credential headers, that its own headers win on
// a clash, and that a finding without a URL is left alone.
func TestWithRequestHeadersStampsScanHeadersOnURLFindings(t *testing.T) {
	scan := map[string]string{"Authorization": "Bearer abc", "Cookie": "sid=1"}
	findings := []Finding{
		{Label: "GET hit", URL: "https://h/admin"},
		{Label: "POST hit", URL: "https://h/graphql", Headers: map[string]string{"Content-Type": "application/json", "Cookie": "own=2"}},
		{Label: "no request", Detail: "target-level note"},
	}

	out := withRequestHeaders(findings, scan)

	if got := out[0].Headers; got["Authorization"] != "Bearer abc" || got["Cookie"] != "sid=1" {
		t.Errorf("GET finding headers = %v, want the scan's Authorization and Cookie", got)
	}
	if got := out[1].Headers; got["Content-Type"] != "application/json" || got["Authorization"] != "Bearer abc" || got["Cookie"] != "own=2" {
		t.Errorf("POST finding headers = %v, want Content-Type kept and its own Cookie winning", got)
	}
	if out[2].Headers != nil {
		t.Errorf("finding without a URL got headers %v, want none", out[2].Headers)
	}
}

// TestWithRequestHeadersLeavesNilWhenNothingToSend checks that a scan with
// no credential leaves findings' Headers nil, so the JSON omits the field.
func TestWithRequestHeadersLeavesNilWhenNothingToSend(t *testing.T) {
	out := withRequestHeaders([]Finding{{Label: "GET hit", URL: "https://h/x"}}, nil)
	if out[0].Headers != nil {
		t.Errorf("headers = %v, want nil", out[0].Headers)
	}
}
