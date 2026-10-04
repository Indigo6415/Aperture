package recon

import "testing"

// danglingDNS builds a completed DNS check whose CNAME points at the first
// provider in the table and which resolves to no address records.
func danglingDNS(t *testing.T, withA bool) (Check, string) {
	t.Helper()
	p := takeoverProviders[0]
	// A real provider hostname is a label under the provider domain.
	cname := "bucket." + p.cnameSuffix
	data := map[string]any{"cname": cname, "a": []string{}, "aaaa": []string{}}
	if withA {
		data["a"] = []string{"203.0.113.9"}
	}
	return Check{Status: StatusDone, Data: data}, p.name
}

// TestTakeoverConfidenceGrading checks that each kind of evidence maps to its own
// grade, and that a host with an address record and no unclaimed page is not
// flagged at all.
func TestTakeoverConfidenceGrading(t *testing.T) {
	p := takeoverProviders[0]

	dns, _ := danglingDNS(t, false)
	pageBody := p.fingerprint
	if pageBody == "" {
		t.Skip("first provider has no unclaimed-page fingerprint to test against")
	}

	confirmed, ok := detectTakeover("h.example.test", dns, Check{Status: StatusDone, Data: map[string]any{"bodySnippet": pageBody}})
	if !ok || confirmed.Data["confidence"] != "confirmed" {
		t.Errorf("dangling DNS + unclaimed page = %v, %+v; want confirmed", ok, confirmed.Data)
	}

	likely, ok := detectTakeover("h.example.test", dns, Check{Status: StatusError})
	if !ok || likely.Data["confidence"] != "likely" {
		t.Errorf("dangling DNS + failed connect = %v, %+v; want likely", ok, likely.Data)
	}

	lead, ok := detectTakeover("h.example.test", dns, Check{Status: StatusDone, Data: map[string]any{"bodySnippet": "ordinary page"}})
	if !ok || lead.Data["confidence"] != "heuristic" {
		t.Errorf("dangling DNS alone = %v, %+v; want heuristic", ok, lead.Data)
	}

	live, _ := danglingDNS(t, true)
	if _, ok := detectTakeover("h.example.test", live, Check{Status: StatusDone, Data: map[string]any{"bodySnippet": "ordinary page"}}); ok {
		t.Error("host with an address record and no unclaimed page was flagged")
	}
}
