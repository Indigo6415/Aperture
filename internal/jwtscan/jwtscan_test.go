package jwtscan

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// signHS256 builds a compact HS256 JWT with the given payload and key.
func signHS256(t *testing.T, payload map[string]any, key string) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signingInput := enc(map[string]any{"alg": "HS256", "typ": "JWT"}) + "." + enc(payload)
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// verifyingServer accepts a token only when its HS256 signature checks out
// against key. A valid token gets the account's page; anything else gets 401.
// It counts requests so the test can prove the offline crack sends none.
func verifyingServer(t *testing.T, key string, requests *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		parts := strings.Split(token, ".")
		if len(parts) == 3 {
			mac := hmac.New(sha256.New, []byte(key))
			mac.Write([]byte(parts[0] + "." + parts[1]))
			want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
			if parts[2] == want {
				fmt.Fprint(w, "<html>Welcome back, alice@example.com. Your account overview.</html>")
				return
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "unauthorized")
	}))
}

// TestWeakSecretRecoveredOfflineWithoutRequests checks that a weak HMAC secret
// is recovered by local verification, and that the candidate list costs no
// requests to the target.
func TestWeakSecretRecoveredOfflineWithoutRequests(t *testing.T) {
	payload := map[string]any{"sub": "alice", "email": "alice@example.com", "exp": 4102444800}
	token := signHS256(t, payload, "secret")

	var requests atomic.Int32
	srv := verifyingServer(t, "secret", &requests)
	defer srv.Close()

	resp, err := RunScan(context.Background(), ScanRequest{URL: srv.URL + "/account", Token: token}, OOBConfig{})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	if resp.CrackedSecret != "secret" {
		t.Errorf("CrackedSecret = %q, want %q", resp.CrackedSecret, "secret")
	}
	var weak *TestResult
	for i := range resp.Results {
		if resp.Results[i].ID == "weak_secret" {
			weak = &resp.Results[i]
		}
	}
	if weak == nil || weak.Status != StatusVulnerable {
		t.Fatalf("weak_secret result = %+v, want vulnerable", weak)
	}
	// Baselines are 3 valid + 3 invalid sends. Everything after that is the
	// other tests. The weak-secret check itself must add nothing, so the count
	// stays well below one request per candidate in the list.
	if got := int(requests.Load()); got >= len(weakSecrets) {
		t.Errorf("target received %d requests; offline cracking should not add one per candidate (list size %d)", got, len(weakSecrets))
	}
}

// TestAcceptAllServerIsNotReportedAsAccepting checks the central false-positive
// case: a host that answers 200 with varying content for every token, with no
// account identity in it, must not produce acceptance findings.
func TestAcceptAllServerIsNotReportedAsAccepting(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Length changes on every request; there is no identity to match.
		fmt.Fprint(w, strings.Repeat("public ", int(n.Add(1))))
	}))
	defer srv.Close()

	token := signHS256(t, map[string]any{"sub": "alice", "exp": 4102444800}, "secret")
	resp, err := RunScan(context.Background(), ScanRequest{URL: srv.URL + "/", Token: token}, OOBConfig{})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	for _, r := range resp.Results {
		if r.Status == StatusVulnerable && r.ID != "weak_secret" {
			t.Errorf("%s reported vulnerable against an accept-all page: %s", r.ID, r.Summary)
		}
	}
	found := false
	for _, a := range resp.Advisories {
		if strings.Contains(a, "No identity claim") {
			found = true
		}
	}
	if !found {
		t.Errorf("no advisory explaining why acceptance was not checked: %v", resp.Advisories)
	}
}

// TestOfflineAdvisories checks the properties reported without any request.
func TestOfflineAdvisories(t *testing.T) {
	got := offlineAdvisories(
		map[string]any{"alg": "none", "jku": "https://attacker.example/keys", "kid": "../../x"},
		map[string]any{"sub": "bob", "iat": 1000, "exp": 1000 + 2*365*24*3600},
	)
	joined := strings.Join(got, "\n")
	for _, want := range []string{`alg "none"`, `"jku"`, `"kid"`, "exceeds one year"} {
		if !strings.Contains(joined, want) {
			t.Errorf("advisories missing %q: %v", want, got)
		}
	}
	if none := offlineAdvisories(map[string]any{"alg": "HS256"}, map[string]any{"exp": 2000000000}); len(none) != 0 {
		t.Errorf("clean token produced advisories: %v", none)
	}
}

// TestForgedIdentityChangeIsDetected is the regression test for claim tampering
// when the forged token changes the identity itself. The server accepts unsigned
// tokens and answers with the token's own sub claim, so a sub→admin forgery gets
// back "hello admin". That only counts if the patched identity is treated as a
// marker, which the original-identity check alone would miss.
func TestForgedIdentityChangeIsDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		headerJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
		payloadJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var header, payload map[string]any
		_ = json.Unmarshal(headerJSON, &header)
		_ = json.Unmarshal(payloadJSON, &payload)
		// Tokens carrying any claim besides sub and exp are refused. That isolates
		// the identity change: only a forged sub can get through, so an accepted
		// forgery must show the changed identity.
		for k := range payload {
			if k != "sub" && k != "exp" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		// Unsigned tokens are accepted (the vulnerability), and so is a valid
		// HS256 signature under the real secret.
		accepted := strings.EqualFold(fmt.Sprint(header["alg"]), "none")
		if !accepted {
			mac := hmac.New(sha256.New, []byte("secret"))
			mac.Write([]byte(parts[0] + "." + parts[1]))
			accepted = parts[2] == base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		}
		if !accepted {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "unauthorized")
			return
		}
		fmt.Fprintf(w, "<html>hello %v, your account overview follows.</html>", payload["sub"])
	}))
	defer srv.Close()

	token := signHS256(t, map[string]any{"sub": "alice", "exp": 4102444800}, "secret")
	resp, err := RunScan(context.Background(), ScanRequest{URL: srv.URL + "/me", Token: token}, OOBConfig{})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	var claims *TestResult
	for i := range resp.Results {
		if resp.Results[i].ID == "claim_tampering" {
			claims = &resp.Results[i]
		}
	}
	if claims == nil || claims.Status != StatusVulnerable {
		t.Fatalf("claim_tampering = %+v, want vulnerable: the server accepted a forged sub→admin token", claims)
	}
	for _, a := range claims.Attempts {
		if strings.Contains(a.Label, `sub → "admin"`) && a.Hit {
			return
		}
	}
	t.Errorf("the sub → admin forgery was not the attempt that hit: %+v", claims.Attempts)
}
