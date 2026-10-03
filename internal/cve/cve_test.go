package cve

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestLookupUsesCPERangeForKnownProduct checks that a mapped technology is
// matched through virtualMatchString, which checks the version against the
// affected range, and that its results are labeled range-confirmed.
func TestLookupUsesCPERangeForKnownProduct(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		fmt.Fprint(w, `{"vulnerabilities":[{"cve":{"id":"CVE-2099-0001","descriptions":[{"lang":"en","value":"test"}]}}]}`)
	}))
	defer srv.Close()
	old := nvdEndpoint
	nvdEndpoint = srv.URL
	defer func() { nvdEndpoint = old }()

	cves, err := Lookup(context.Background(), "WordPress", "6.2", "")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !strings.Contains(gotQuery, "virtualMatchString=") || strings.Contains(gotQuery, "keywordSearch") {
		t.Errorf("query = %q, want virtualMatchString and no keywordSearch", gotQuery)
	}
	if !strings.Contains(gotQuery, "wordpress") || !strings.Contains(gotQuery, "6.2") {
		t.Errorf("query %q does not carry the CPE vendor, product, and version", gotQuery)
	}
	if len(cves) != 1 || cves[0].MatchType != MatchRange {
		t.Errorf("results = %+v, want one range-confirmed CVE", cves)
	}
}

// TestLookupFallsBackToKeywordForUnknownProduct checks that a technology with no
// CPE mapping is searched by keyword and labeled as such, so the UI can warn
// that it may describe a different product.
func TestLookupFallsBackToKeywordForUnknownProduct(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		fmt.Fprint(w, `{"vulnerabilities":[{"cve":{"id":"CVE-2099-0002","descriptions":[{"lang":"en","value":"test"}]}}]}`)
	}))
	defer srv.Close()
	old := nvdEndpoint
	nvdEndpoint = srv.URL
	defer func() { nvdEndpoint = old }()

	cves, err := Lookup(context.Background(), "Some Unmapped App", "1.0", "")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !strings.Contains(gotQuery, "keywordSearch=") {
		t.Errorf("query = %q, want keyword fallback", gotQuery)
	}
	if len(cves) != 1 || cves[0].MatchType != MatchKeyword {
		t.Errorf("results = %+v, want one keyword-only CVE", cves)
	}
}

// TestLookupWithoutVersionMakesNoRequest checks that a versionless lookup is
// refused before any network call.
func TestLookupWithoutVersionMakesNoRequest(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer srv.Close()
	old := nvdEndpoint
	nvdEndpoint = srv.URL
	defer func() { nvdEndpoint = old }()

	if cves, err := Lookup(context.Background(), "WordPress", "", ""); err != nil || cves != nil {
		t.Errorf("Lookup without version = %v, %v; want nil, nil", cves, err)
	}
	if hit {
		t.Error("a versionless lookup still reached NVD")
	}
}
