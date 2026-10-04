package csrf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRunCountsFormsAndFlagsMissingToken serves a page with a state-changing
// POST form that carries no anti-CSRF token, and expects the form to be found
// and at least one finding raised against it.
func TestRunCountsFormsAndFlagsMissingToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body><form method="post" action="/transfer">
			<input name="amount"><input name="to"><button>Send</button></form></body></html>`))
	}))
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.FormsFound != 1 {
		t.Fatalf("FormsFound = %d, want 1", res.FormsFound)
	}
	total := 0
	for _, m := range res.Modules {
		total += len(m.Findings)
	}
	if total == 0 {
		t.Fatal("a POST form with no anti-CSRF token produced no findings")
	}
}
