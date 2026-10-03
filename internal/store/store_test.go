package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Indigo6415/Aperture/internal/model"
)

// TestFindingDetailFieldsRoundTrip checks that the template, severity, matcher,
// reproduce, and confidence fields survive a save and a read. The insert and
// select lists are written by hand, so a mismatch would only show at runtime.
func TestFindingDetailFieldsRoundTrip(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "aperture.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if err := s.CreateRun("run-1", "flow-1"); err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	want := model.Finding{
		ID:         "f-1",
		URL:        "https://h/x",
		StatusCode: 200,
		Method:     "POST",
		SourceTool: "nuclei",
		Timestamp:  time.Now().UTC().Truncate(time.Second),
		Template:   "exposed-panel",
		Severity:   "high",
		Matcher:    "status-200",
		Reproduce:  "curl -X POST https://h/x",
		Confidence: "likely",
	}
	if err := s.SaveFinding("run-1", "node-1", want); err != nil {
		t.Fatalf("SaveFinding: %v", err)
	}

	got, err := s.ListFindings("run-1", "")
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	f := got[0]
	if f.Template != want.Template || f.Severity != want.Severity || f.Matcher != want.Matcher ||
		f.Reproduce != want.Reproduce || f.Confidence != want.Confidence {
		t.Errorf("detail fields lost in round trip: got %+v", f)
	}
	if f.Method != "POST" {
		t.Errorf("method = %q, want POST", f.Method)
	}
}
