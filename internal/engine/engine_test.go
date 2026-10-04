package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Indigo6415/Aperture/internal/adapters"
	"github.com/Indigo6415/Aperture/internal/model"
	"github.com/Indigo6415/Aperture/internal/netgov"
)

// TestExecuteRoutesNodeExchangesToSink runs a real native fuzzer node against
// a local server and checks that each request it made reaches the sink tagged
// with the run and node that produced it.
func TestExecuteRoutesNodeExchangesToSink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	wordlist := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wordlist, []byte("admin\nfoo\nbar\n"), 0o600); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}
	cfg, _ := json.Marshal(adapters.WebFuzzConfig{URL: srv.URL + "/FUZZ", Wordlist: wordlist, Threads: 2, Timeout: 5})
	flow := Flow{Nodes: []Node{{ID: "webfuzz-0", Kind: KindWebFuzz, Config: cfg}}}

	var mu sync.Mutex
	type seen struct {
		runID, nodeID string
		ex            netgov.Exchange
	}
	var got []seen

	e := New()
	e.SetExchangeSink(func(runID, nodeID string, ex netgov.Exchange) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, seen{runID, nodeID, ex})
	})
	noResult := func(string, model.Finding) {}
	noStatus := func(string, NodeStatus, string) {}
	noProgress := func(string, int, int) {}
	if err := e.Execute(context.Background(), flow, "run-1", noResult, noStatus, noProgress); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) < 3 {
		t.Fatalf("sink received %d exchanges, want at least one per wordlist entry", len(got))
	}
	for _, s := range got {
		if s.runID != "run-1" || s.nodeID != "webfuzz-0" {
			t.Errorf("exchange tagged run %q node %q, want run-1 webfuzz-0", s.runID, s.nodeID)
		}
	}
}
