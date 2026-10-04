package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// TestRequestLogSurvivesReopen checks the full path: rows queued with
// RecordRequest are flushed by Close, survive a reopen, and come back from
// the list and detail queries with their raw bodies only on the detail.
func TestRequestLogSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aperture.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.CreateRun("run-1", "flow-1"); err != nil {
		t.Fatalf("CreateRun: %v", err)
	}

	ts := time.Now().UTC().Truncate(time.Second)
	for i, url := range []string{"http://h/a", "http://h/b", "http://h/c"} {
		s.RecordRequest(RequestRecord{
			RunID: "run-1", NodeID: "webfuzz-0", Method: "GET", URL: url, Host: "h",
			StatusCode: 200 + i, Size: int64(10 * i), TTFBMs: 5,
			RequestRaw: "GET " + url, ResponseRaw: "HTTP/1.1 200 OK\n\nbody",
			Timestamp: ts,
		})
	}
	// A row for a different node must not show up in webfuzz-0's log.
	s.RecordRequest(RequestRecord{RunID: "run-1", NodeID: "katana-0", Method: "GET", URL: "http://other/", Host: "other", Timestamp: ts})

	// Close must flush the queue before returning, since nothing else would.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s, err = Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()

	list, err := s.ListRequests("run-1", "webfuzz-0")
	if err != nil {
		t.Fatalf("ListRequests: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("listed %d requests, want 3", len(list))
	}
	if list[0].URL != "http://h/a" || list[2].StatusCode != 202 {
		t.Errorf("list not in request order: %+v", list)
	}
	if list[0].RequestRaw != "" || list[0].ResponseRaw != "" {
		t.Errorf("list view should omit raw bodies")
	}

	detail, err := s.GetRequest("run-1", "webfuzz-0", list[1].ID)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if detail.RequestRaw != "GET http://h/b" || detail.ResponseRaw != "HTTP/1.1 200 OK\n\nbody" {
		t.Errorf("detail raw bodies = %q / %q", detail.RequestRaw, detail.ResponseRaw)
	}
}

// TestGetRequestIsScopedToRunAndNode checks that a request ID from one node
// cannot be fetched through a different node's path.
func TestGetRequestIsScopedToRunAndNode(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "aperture.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if err := s.CreateRun("run-1", "flow-1"); err != nil {
		t.Fatalf("CreateRun: %v", err)
	}

	s.RecordRequest(RequestRecord{RunID: "run-1", NodeID: "webfuzz-0", Method: "GET", URL: "http://h/", Host: "h", Timestamp: time.Now()})
	// The writer is asynchronous, so wait for the row by polling the list.
	var list []RequestRecord
	for i := 0; i < 200 && len(list) == 0; i++ {
		list, _ = s.ListRequests("run-1", "webfuzz-0")
		time.Sleep(5 * time.Millisecond)
	}
	if len(list) != 1 {
		t.Fatalf("row never appeared, got %d", len(list))
	}

	if _, err := s.GetRequest("run-1", "katana-0", list[0].ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetRequest through the wrong node = %v, want ErrNotFound", err)
	}
}

// TestDeleteCaseClearsOnlyThatCasesRequestLogs checks that deleting a case
// removes the request logs of its direct scans and job runs, and leaves the
// logs of another case alone.
func TestDeleteCaseClearsOnlyThatCasesRequestLogs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aperture.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for _, id := range []string{"case-1", "case-2"} {
		if err := s.CreateCase(id, id, ""); err != nil {
			t.Fatalf("CreateCase %s: %v", id, err)
		}
	}
	if err := s.SaveCaseScan(CaseScan{ID: "scan-1", CaseID: "case-1", Target: "t", Tool: "openredirect", Severity: "info", Summary: "s", Data: "{}"}); err != nil {
		t.Fatalf("SaveCaseScan: %v", err)
	}
	if err := s.SaveCaseScan(CaseScan{ID: "scan-2", CaseID: "case-2", Target: "t", Tool: "openredirect", Severity: "info", Summary: "s", Data: "{}"}); err != nil {
		t.Fatalf("SaveCaseScan: %v", err)
	}
	if err := s.CreateJob(Job{ID: "job-1", CaseID: "case-1", Tool: "probe", RunID: "run-1", Targets: []string{"t"}, Status: "running"}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	ts := time.Now().UTC()
	for _, run := range []string{"scan-1", "run-1", "scan-2"} {
		s.RecordRequest(RequestRecord{RunID: run, NodeID: "scan", Method: "GET", URL: "http://h/", Host: "h", Timestamp: ts})
	}
	// Flush the writer so the rows exist before the delete is checked.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()

	if err := s.DeleteCase("case-1"); err != nil {
		t.Fatalf("DeleteCase: %v", err)
	}
	for _, run := range []string{"scan-1", "run-1"} {
		list, err := s.ListRequests(run, "scan")
		if err != nil {
			t.Fatalf("ListRequests %s: %v", run, err)
		}
		if len(list) != 0 {
			t.Errorf("run %s still has %d requests after its case was deleted", run, len(list))
		}
	}
	kept, err := s.ListRequests("scan-2", "scan")
	if err != nil {
		t.Fatalf("ListRequests scan-2: %v", err)
	}
	if len(kept) != 1 {
		t.Errorf("another case's scan lost its request log: %d rows left, want 1", len(kept))
	}
}
