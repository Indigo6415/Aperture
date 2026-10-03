package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// TestSPAHandlerFallbackAndMisses checks the routing contract between the
// embedded frontend and the API: client-side routes fall back to index.html,
// while missing API endpoints and missing bundle files return a real 404.
// A 200 index.html reply to those requests is what made failures look like a
// blank page before.
func TestSPAHandlerFallbackAndMisses(t *testing.T) {
	uiFS := fstest.MapFS{
		"index.html":    {Data: []byte("<html>app shell</html>")},
		"assets/app.js": {Data: []byte("console.log('bundle')")},
	}
	h := spaHandler(uiFS)

	cases := []struct {
		name     string
		path     string
		wantCode int
		wantBody string
	}{
		{"root serves the shell", "/", http.StatusOK, "app shell"},
		{"existing asset is served as-is", "/assets/app.js", http.StatusOK, "console.log('bundle')"},
		{"client-side route falls back to shell", "/cases/123", http.StatusOK, "app shell"},
		{"missing API route is a 404", "/api/does-not-exist", http.StatusNotFound, ""},
		{"API root with no route is a 404", "/api", http.StatusNotFound, ""},
		{"missing hashed bundle is a 404", "/assets/index-OLD123.js", http.StatusNotFound, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if rec.Code != tc.wantCode {
				t.Fatalf("GET %s: status = %d, want %d", tc.path, rec.Code, tc.wantCode)
			}
			if tc.wantBody != "" && !strings.Contains(rec.Body.String(), tc.wantBody) {
				t.Errorf("GET %s: body = %q, want it to contain %q", tc.path, rec.Body.String(), tc.wantBody)
			}
			// A 404 must not carry the shell, or the frontend would parse it as a
			// successful response.
			if tc.wantCode == http.StatusNotFound && strings.Contains(rec.Body.String(), "app shell") {
				t.Errorf("GET %s: a 404 must not carry the index.html fallback", tc.path)
			}
		})
	}
}
