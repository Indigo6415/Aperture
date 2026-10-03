package graphqlenum

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// TestMutationOverGETNeedsTheMutationRoot checks the false-positive fix: a
// server that runs a GET selection against the query root answers "Query", and
// must not be reported as executing a mutation.
func TestMutationOverGETNeedsTheMutationRoot(t *testing.T) {
	cases := []struct {
		name     string
		typename string
		want     int
	}{
		{"query root answer is not a mutation", "Query", 0},
		{"mutation root answer is reported", "Mutation", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, `{"data":{"__typename":%q}}`, tc.typename)
			}))
			defer srv.Close()
			target, _ := url.Parse(srv.URL + "/graphql")
			client := &http.Client{Timeout: 5 * time.Second}
			got := runMutationOverGETModule(context.Background(), client, target, nil)
			if len(got) != tc.want {
				t.Errorf("findings = %d, want %d: %+v", len(got), tc.want, got)
			}
		})
	}
}
