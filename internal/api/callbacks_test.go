package api

import (
	"testing"
	"time"

	"github.com/Indigo6415/Aperture/internal/collaborator"
	"github.com/Indigo6415/Aperture/internal/store"
)

// TestCallbacksForMatchesTokenAfterRedirect checks that a redirect's Location
// picks up the callbacks on its token that arrived after it was sent, and skips
// hits from before, hits with a different identifier, and other tokens.
func TestCallbacksForMatchesTokenAfterRedirect(t *testing.T) {
	reg := collaborator.NewRegistry()
	const token = "a4b5692f8c4ed3322ce9"
	sent := time.Now()
	loc := "http://collab.example:8338/collab/" + token + "/or-forwarded-host/"

	reg.Record(token, collaborator.Interaction{Timestamp: sent.Add(-time.Minute), Protocol: "http"})                                 // before the request
	reg.Record(token, collaborator.Interaction{Timestamp: sent.Add(time.Second), Protocol: "http", Identifier: "or-forwarded-host"}) // match
	reg.Record(token, collaborator.Interaction{Timestamp: sent.Add(time.Second), Protocol: "http", Identifier: "other-test"})        // wrong identifier
	reg.Record("ffffffffffffffffffff", collaborator.Interaction{Timestamp: sent.Add(time.Second), Protocol: "http"})                 // unrelated token

	s := &Server{collab: reg}
	got := s.callbacksFor(store.RequestRecord{Location: loc, Timestamp: sent})
	if len(got) != 1 || got[0].Identifier != "or-forwarded-host" {
		t.Fatalf("callbacksFor = %+v, want the one matching hit", got)
	}
	// A non-redirect has no Location, so nothing can be linked.
	if n := s.callbacksFor(store.RequestRecord{Timestamp: sent}); n != nil {
		t.Errorf("no Location should give no callbacks, got %d", len(n))
	}
	// Reading must not consume the hits: the Collaborator tab still needs them.
	if n := len(reg.Poll(token)); n != 3 {
		t.Errorf("hits after lookup = %d, want all 3 kept", n)
	}
}
