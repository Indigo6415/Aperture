package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Indigo6415/Aperture/internal/store"
)

// TestPingTargetsAliveAndDead checks the liveness verdict end to end against
// real sockets: a server that answers (even with a 404) must count as alive
// with its status code, and an address with nothing listening must count as
// dead with an error. Results must also keep the input order.
func TestPingTargetsAliveAndDead(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer up.Close()

	// Start and immediately close a server so its port is known to be unused.
	down := httptest.NewServer(http.NotFoundHandler())
	downURL := down.URL
	down.Close()

	targets := []store.Target{
		{ID: "a", Value: up.URL},
		{ID: "b", Value: downURL},
	}

	got := pingTargets(context.Background(), targets)
	if len(got) != 2 {
		t.Fatalf("got %d results, want 2", len(got))
	}

	if got[0].TargetID != "a" || !got[0].Alive || got[0].StatusCode != http.StatusNotFound {
		t.Errorf("live target: got %+v, want alive with status 404", got[0])
	}
	if got[1].TargetID != "b" || got[1].Alive || got[1].Error == "" {
		t.Errorf("dead target: got %+v, want not alive with an error", got[1])
	}
}

// TestStreamPingTargetsEmitsAsFinished checks that a fast target's verdict is
// emitted before a slow one that was listed first, so the UI can show results
// as they land. Each verdict still carries the index of its target.
func TestStreamPingTargetsEmitsAsFinished(t *testing.T) {
	// The first target's handler blocks until the test releases it, so it
	// cannot finish before the fast target has been emitted.
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		http.NotFound(w, r)
	}))
	defer slow.Close()
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer fast.Close()

	targets := []store.Target{
		{ID: "slow", Value: slow.URL},
		{ID: "fast", Value: fast.URL},
	}

	var order []string
	streamPingTargets(context.Background(), targets, func(i int, res pingResult) {
		order = append(order, res.TargetID)
		if res.TargetID == "fast" {
			// The fast verdict has arrived; now let the slow check finish.
			close(release)
		}
		if targets[i].ID != res.TargetID {
			t.Errorf("index %d paired with target %q, want %q", i, res.TargetID, targets[i].ID)
		}
	})

	if len(order) != 2 || order[0] != "fast" || order[1] != "slow" {
		t.Errorf("emit order = %v, want [fast slow]", order)
	}
}
