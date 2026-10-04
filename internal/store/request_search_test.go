package store

import (
	"path/filepath"
	"testing"
	"time"
)

// openSearchStore opens a fresh store with one run and a small log for node
// "scan": a hit, a non-hit with the same status, and a body-only match.
func openSearchStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "aperture.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.CreateRun("run-1", "flow-1"); err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	ts := time.Now().UTC().Truncate(time.Second)
	rows := []RequestRecord{
		{Method: "GET", URL: "http://h/hit", StatusCode: 200, RequestRaw: "GET /hit", ResponseRaw: "HTTP/1.1 200 OK\n\nplain"},
		{Method: "GET", URL: "http://h/miss", StatusCode: 200, RequestRaw: "GET /miss", ResponseRaw: "HTTP/1.1 200 OK\n\nplain"},
		{Method: "POST", URL: "http://h/login", StatusCode: 500, RequestRaw: "POST /login\n\nuser=admin", ResponseRaw: "HTTP/1.1 500\n\nSQL syntax error near 'x'"},
	}
	for i := range rows {
		rows[i].RunID, rows[i].NodeID, rows[i].Host, rows[i].Timestamp = "run-1", "scan", "h", ts
	}
	// Written synchronously so the rows exist before the test queries them.
	s.insertRequests(rows)
	return s
}

// TestSearchMatchesBodies checks that a query finds text that appears only in
// a request or response body, and that it doesn't match rows without it.
func TestSearchMatchesBodies(t *testing.T) {
	s := openSearchStore(t)
	got, err := s.SearchRequests("run-1", "scan", "sql syntax")
	if err != nil {
		t.Fatalf("SearchRequests: %v", err)
	}
	if len(got) != 1 || got[0].URL != "http://h/login" {
		t.Fatalf("body search = %+v, want only /login", got)
	}
	got, _ = s.SearchRequests("run-1", "scan", "USER=ADMIN")
	if len(got) != 1 {
		t.Fatalf("request-body search (case-insensitive) = %d rows, want 1", len(got))
	}
	got, _ = s.SearchRequests("run-1", "scan", "%")
	if len(got) != 0 {
		t.Fatalf("a literal %% must not act as a wildcard, got %d rows", len(got))
	}
}

// TestHitFlagComesFromRecordedHits checks that only the request named by a
// recorded hit is flagged, and that a method left empty is treated as GET.
func TestHitFlagComesFromRecordedHits(t *testing.T) {
	s := openSearchStore(t)
	if err := s.RecordHits("run-1", "scan", []RequestHit{{Method: "", URL: "http://h/hit"}, {Method: "post", URL: "http://h/login"}}); err != nil {
		t.Fatalf("RecordHits: %v", err)
	}
	list, err := s.ListRequests("run-1", "scan")
	if err != nil {
		t.Fatalf("ListRequests: %v", err)
	}
	want := map[string]bool{"http://h/hit": true, "http://h/miss": false, "http://h/login": true}
	for _, r := range list {
		if r.Hit != want[r.URL] {
			t.Errorf("%s Hit = %v, want %v", r.URL, r.Hit, want[r.URL])
		}
	}
}
