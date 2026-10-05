package xss

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/Indigo6415/Aperture/internal/collaborator"
)

// callbackInPayload pulls the token and identifier out of a blind payload's
// callback URL, which the module builds as /collab/<token>/<identifier>/.
var callbackInPayload = regexp.MustCompile(`/collab/([^/]+)/(p\d+t\d+)/`)

// TestBlindIdentifierRoundTrip checks that a callback label names the point and
// template that produced it, and that anything else is rejected.
func TestBlindIdentifierRoundTrip(t *testing.T) {
	id := blindIdentifier(3, 1)
	p, tmpl, ok := parseBlindIdentifier(id)
	if !ok || p != 3 || tmpl != 1 {
		t.Fatalf("parseBlindIdentifier(%q) = (%d, %d, %v), want (3, 1, true)", id, p, tmpl, ok)
	}
	for _, bad := range []string{"", "x", "p3", "p3t99", "t1p2"} {
		if _, _, ok := parseBlindIdentifier(bad); ok {
			t.Errorf("parseBlindIdentifier(%q) accepted a label the module did not write", bad)
		}
	}
}

// TestBlindRunsScriptOnlyForHandlerTemplate checks which blind templates prove a
// script ran. Only the onerror template's callback can come from running script;
// the script-src templates fire on markup parsing alone.
func TestBlindRunsScriptOnlyForHandlerTemplate(t *testing.T) {
	for i, tmpl := range dalfoxBlindTemplates {
		want := strings.Contains(tmpl, "onerror")
		if got := blindRunsScript(i); got != want {
			t.Errorf("blindRunsScript(%d) = %v, want %v for %q", i, got, want, tmpl)
		}
	}
}

// TestBlindUsableRequiresAListener checks that the module runs only with a
// listener it can both send to and read back from.
func TestBlindUsableRequiresAListener(t *testing.T) {
	reg := collaborator.NewRegistry()
	cases := []struct {
		name string
		oob  OOBConfig
		want bool
	}{
		{"nothing configured", OOBConfig{}, false},
		{"registry without a base URL", OOBConfig{Registry: reg}, false},
		{"registry and base URL", OOBConfig{Registry: reg, CallbackBaseURL: "http://a.test"}, true},
		{"shared aperture token without a registry", OOBConfig{SharedToken: "t", SharedProvider: "aperture", CallbackBaseURL: "http://a.test"}, false},
		{"shared webhook.site token needs no registry", OOBConfig{SharedToken: "uuid", SharedProvider: "webhooksite"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := blindUsable(tc.oob); got != tc.want {
				t.Errorf("blindUsable = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRunBlindXSSFindsCallbacks runs the whole module against a page that stores
// its input and renders it later. The stored payloads are "viewed" by the test: the
// victim side reads each callback out of the payload and records the hit, the way
// a browser would. A script-run hit must be reported as confirmed.
func TestRunBlindXSSFindsCallbacks(t *testing.T) {
	reg := collaborator.NewRegistry()
	var mu sync.Mutex
	var stored []string
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("q")
		if strings.Contains(v, "/collab/") {
			mu.Lock()
			stored = append(stored, v)
			mu.Unlock()
			// The victim's browser renders the stored value. Only the onerror
			// template fires without a parse-only path, so its hit is the script-run one.
			for _, m := range callbackInPayload.FindAllStringSubmatch(v, -1) {
				reg.Record(m[1], collaborator.Interaction{Identifier: m[2], Protocol: "http", Method: "GET", Path: m[0]})
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// The app never echoes the input back, so the reflection scan finds nothing.
		_, _ = w.Write([]byte("<html><body>saved</body></html>"))
	}))
	defer app.Close()

	oob := OOBConfig{Registry: reg, CallbackBaseURL: "http://aperture.test"}
	res, err := Run(context.Background(), Request{URL: app.URL + "/save?q=seed", Params: []string{"q"}, SkipBrowser: true}, oob)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var blind *ModuleResult
	for i := range res.Modules {
		if res.Modules[i].ID == "blind-xss" {
			blind = &res.Modules[i]
		}
	}
	if blind == nil {
		t.Fatal("the blind-xss module should be present when a listener is configured")
	}
	if len(blind.Findings) != 1 {
		t.Fatalf("blind findings = %d, want one for the one point", len(blind.Findings))
	}
	f := blind.Findings[0]
	if f.Confidence != ConfidenceConfirmed {
		t.Errorf("confidence = %q, want %q for a script-run callback", f.Confidence, ConfidenceConfirmed)
	}
	if !strings.Contains(f.Label, "blind XSS") {
		t.Errorf("label %q should name blind XSS", f.Label)
	}
	if f.Request == nil || f.Request.URL == "" {
		t.Error("the finding should cite the request that stored the payload")
	}
}

// TestRunBlindXSSWithoutAListenerOmitsTheModule checks that a run without a
// listener does not invent a blind-XSS module.
func TestRunBlindXSSWithoutAListenerOmitsTheModule(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>saved</body></html>"))
	}))
	defer app.Close()
	res, err := Run(context.Background(), Request{URL: app.URL + "/save?q=seed", Params: []string{"q"}, SkipBrowser: true}, OOBConfig{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, m := range res.Modules {
		if m.ID == "blind-xss" {
			t.Fatal("no listener configured, so the blind-xss module should be omitted")
		}
	}
}
