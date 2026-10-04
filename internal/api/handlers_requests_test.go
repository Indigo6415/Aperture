package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Indigo6415/Aperture/internal/engine"
	"github.com/Indigo6415/Aperture/internal/netgov"
	"github.com/Indigo6415/Aperture/internal/store"
)

// TestDirectScanRecordsEveryRequestUnderItsScanID checks that a request made on
// a direct scan's context is stored under that scan's ID, so the inspector can
// list it from the same ID the live progress stream used.
func TestDirectScanRecordsEveryRequestUnderItsScanID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "aperture.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	s := NewServer(st, engine.New(), nil, "")

	ctx := s.withScanRecorder(context.Background(), "scan-abc")
	client := &http.Client{Transport: netgov.New(http.DefaultTransport)}
	for _, p := range []string{"/one", "/two"} {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+p, nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Do %s: %v", p, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	// Closing the store flushes the async request writer, so the reopened
	// database holds every row the scan recorded.
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	st, err = store.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st.Close()

	list, err := st.ListRequests("scan-abc", directScanNodeID)
	if err != nil {
		t.Fatalf("ListRequests: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("listed %d requests for the scan, want 2", len(list))
	}
	if list[0].StatusCode != http.StatusOK || list[0].Size != int64(len("ok")) {
		t.Errorf("first request = status %d size %d, want 200 and 2", list[0].StatusCode, list[0].Size)
	}
}
