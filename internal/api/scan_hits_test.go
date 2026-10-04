package api

import "testing"

// TestScanResultHitsReadsCapturedRequests checks that only findings carrying a
// captured request produce hits, and that info-only notes without one don't.
func TestScanResultHitsReadsCapturedRequests(t *testing.T) {
	data := []byte(`{"modules":[
		{"id":"reflected","findings":[
			{"label":"xss","request":{"method":"GET","url":"http://h/?q=<x>"}}
		]},
		{"id":"info","findings":[
			{"label":"note"}
		]},
		{"id":"redirect","findings":[
			{"label":"open redirect","request":{"method":"","url":"http://h/out?next=//evil"}}
		]}
	]}`)
	hits := scanResultHits(data)
	if len(hits) != 2 {
		t.Fatalf("got %d hits, want 2: %+v", len(hits), hits)
	}
	if hits[0].URL != "http://h/?q=<x>" || hits[0].Method != "GET" {
		t.Errorf("first hit = %+v", hits[0])
	}
	if hits[1].URL != "http://h/out?next=//evil" {
		t.Errorf("second hit = %+v", hits[1])
	}
}

// TestScanResultHitsIgnoresOtherShapes checks that a result without modules, or
// one that isn't JSON, yields no hits rather than an error.
func TestScanResultHitsIgnoresOtherShapes(t *testing.T) {
	if got := scanResultHits([]byte(`{"subdomains":["a.h"]}`)); len(got) != 0 {
		t.Errorf("non-module result gave %d hits", len(got))
	}
	if got := scanResultHits([]byte(`not json`)); got != nil {
		t.Errorf("invalid JSON gave %+v", got)
	}
}
