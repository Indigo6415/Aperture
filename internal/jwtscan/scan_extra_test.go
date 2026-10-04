package jwtscan

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// validHS256 reports whether parts is a three-part HS256 token signed with key.
func validHS256(parts []string, key string) bool {
	if len(parts) != 3 {
		return false
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	return parts[2] == base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// serverAccepting returns a target that serves the account page for the valid
// HS256 token (key "secret") and for any token accept approves, and answers 401
// otherwise. header is the token's decoded header, nil if it doesn't decode.
func serverAccepting(accept func(parts []string, header map[string]any) bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		parts := strings.Split(token, ".")
		var header map[string]any
		if len(parts) >= 1 {
			if hb, err := base64.RawURLEncoding.DecodeString(parts[0]); err == nil {
				_ = json.Unmarshal(hb, &header)
			}
		}
		if validHS256(parts, "secret") || accept(parts, header) {
			fmt.Fprint(w, "<html>Welcome back, alice@example.com. Your account overview.</html>")
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "unauthorized")
	}))
}

// resultByID returns the scan's result for the given test ID, or nil.
func resultByID(resp *ScanResponse, id string) *TestResult {
	for i := range resp.Results {
		if resp.Results[i].ID == id {
			return &resp.Results[i]
		}
	}
	return nil
}

// attemptLabelled returns the attempt whose label contains sub, or nil.
func attemptLabelled(r *TestResult, sub string) *Attempt {
	for i := range r.Attempts {
		if strings.Contains(r.Attempts[i].Label, sub) {
			return &r.Attempts[i]
		}
	}
	return nil
}

// TestAlgNoneCasingCombinationsAreCovered checks that a verifier comparing
// alg exactly, and accepting only one odd casing ("NoNe") with no signature, is
// caught. The old four-casing list never tried "NoNe".
func TestAlgNoneCasingCombinationsAreCovered(t *testing.T) {
	srv := serverAccepting(func(parts []string, header map[string]any) bool {
		return len(parts) == 3 && parts[2] == "" && header["alg"] == "NoNe"
	})
	defer srv.Close()

	token := signHS256(t, map[string]any{"sub": "alice", "exp": 4102444800}, "secret")
	resp, err := RunScan(context.Background(), ScanRequest{URL: srv.URL + "/account", Token: token}, OOBConfig{})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	r := resultByID(resp, "alg_none")
	if r == nil || r.Status != StatusVulnerable {
		t.Fatalf("alg_none = %+v, want vulnerable", r)
	}
	if a := attemptLabelled(r, `"NoNe"`); a == nil || !a.Hit {
		t.Errorf("the accepted NoNe casing was not the hit: %+v", r.Attempts)
	}
}

// TestAlgNoneOmittedAlgIsCovered checks a verifier that accepts an unsigned token
// with no alg field at all, but rejects any alg value, including "".
func TestAlgNoneOmittedAlgIsCovered(t *testing.T) {
	srv := serverAccepting(func(parts []string, header map[string]any) bool {
		_, hasAlg := header["alg"]
		return len(parts) == 3 && parts[2] == "" && !hasAlg
	})
	defer srv.Close()

	token := signHS256(t, map[string]any{"sub": "alice", "exp": 4102444800}, "secret")
	resp, err := RunScan(context.Background(), ScanRequest{URL: srv.URL + "/account", Token: token}, OOBConfig{})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	r := resultByID(resp, "alg_none")
	if r == nil || r.Status != StatusVulnerable || !strings.Contains(r.Summary, "alg omitted") {
		t.Fatalf("alg_none = %+v, want vulnerable via an omitted alg", r)
	}
}

// TestAlgNoneRejectedIsSafe is the negative case for the wider casing list: a
// verifier that rejects every unsigned token must not produce a finding.
func TestAlgNoneRejectedIsSafe(t *testing.T) {
	srv := serverAccepting(func(parts []string, header map[string]any) bool { return false })
	defer srv.Close()

	token := signHS256(t, map[string]any{"sub": "alice", "exp": 4102444800}, "secret")
	resp, err := RunScan(context.Background(), ScanRequest{URL: srv.URL + "/account", Token: token}, OOBConfig{})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	if r := resultByID(resp, "alg_none"); r == nil || r.Status != StatusSafe {
		t.Errorf("alg_none = %+v, want safe", r)
	}
	if len(resultByID(resp, "alg_none").Attempts) != len(algNoneVariants()) {
		t.Errorf("attempts = %d, want one per variant (%d)", len(resultByID(resp, "alg_none").Attempts), len(algNoneVariants()))
	}
}

// TestTwoSegmentTokenIsCaught checks that a parser accepting a token with its
// signature segment removed entirely (two segments, no trailing dot) is reported
// under empty_sig.
func TestTwoSegmentTokenIsCaught(t *testing.T) {
	srv := serverAccepting(func(parts []string, header map[string]any) bool {
		return len(parts) == 2
	})
	defer srv.Close()

	token := signHS256(t, map[string]any{"sub": "alice", "exp": 4102444800}, "secret")
	resp, err := RunScan(context.Background(), ScanRequest{URL: srv.URL + "/account", Token: token}, OOBConfig{})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	r := resultByID(resp, "empty_sig")
	if r == nil || r.Status != StatusVulnerable || !strings.Contains(r.Summary, "two segments") {
		t.Fatalf("empty_sig = %+v, want vulnerable via the two-segment form", r)
	}
}

// TestRS256ToHS384ConfusionIsFound checks the wider confusion matrix. The target
// verifies RS256 correctly, but also accepts HS384 with the public key bytes as
// the HMAC secret. An HS256-only probe would miss it.
func TestRS256ToHS384ConfusionIsFound(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	srv := serverAccepting(func(parts []string, header map[string]any) bool {
		if len(parts) != 3 {
			return false
		}
		signingInput := parts[0] + "." + parts[1]
		switch header["alg"] {
		case "RS256":
			sig, err := base64.RawURLEncoding.DecodeString(parts[2])
			if err != nil {
				return false
			}
			digest := sha256.Sum256([]byte(signingInput))
			return rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, digest[:], sig) == nil
		case "HS384":
			// The bug under test: the verifier takes the public key bytes as an HMAC secret.
			mac := hmac.New(sha512.New384, []byte(pubPEM))
			mac.Write([]byte(signingInput))
			return parts[2] == base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		}
		return false
	})
	defer srv.Close()

	token, err := buildJWTRSA(map[string]any{"alg": "RS256", "typ": "JWT"}, map[string]any{"sub": "alice", "exp": 4102444800}, priv)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := RunScan(context.Background(), ScanRequest{URL: srv.URL + "/account", Token: token, PubKeyPEM: pubPEM}, OOBConfig{})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	r := resultByID(resp, "rs256_hs256_confusion")
	if r == nil || r.Status != StatusVulnerable {
		t.Fatalf("rs256_hs256_confusion = %+v, want vulnerable", r)
	}
	if !strings.Contains(r.Summary, "HS384") {
		t.Errorf("summary does not name the accepted HMAC width: %q", r.Summary)
	}
}

// TestRS256ConfusionRejectedIsSafe is the negative case: a verifier that only
// accepts the real RS256 signature must not report confusion under any width.
func TestRS256ConfusionRejectedIsSafe(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	srv := serverAccepting(func(parts []string, header map[string]any) bool {
		if len(parts) != 3 || header["alg"] != "RS256" {
			return false
		}
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			return false
		}
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		return rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, digest[:], sig) == nil
	})
	defer srv.Close()

	token, err := buildJWTRSA(map[string]any{"alg": "RS256", "typ": "JWT"}, map[string]any{"sub": "alice", "exp": 4102444800}, priv)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := RunScan(context.Background(), ScanRequest{URL: srv.URL + "/account", Token: token, PubKeyPEM: pubPEM}, OOBConfig{})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	if r := resultByID(resp, "rs256_hs256_confusion"); r == nil || r.Status != StatusSafe {
		t.Errorf("rs256_hs256_confusion = %+v, want safe", r)
	}
}

// TestExpiredSourceTokenAcceptedIsVulnerable checks the expiry test's first case:
// the caller's own token is well past exp, and the server still serves the
// account. No forging is involved.
func TestExpiredSourceTokenAcceptedIsVulnerable(t *testing.T) {
	// The server checks the signature and nothing else, so an expired token is served.
	srv := serverAccepting(func(parts []string, header map[string]any) bool { return false })
	defer srv.Close()

	past := time.Now().Add(-30 * 24 * time.Hour).Unix()
	token := signHS256(t, map[string]any{"sub": "alice", "exp": past}, "secret")
	resp, err := RunScan(context.Background(), ScanRequest{URL: srv.URL + "/account", Token: token}, OOBConfig{})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	r := resultByID(resp, "expired_token")
	if r == nil || r.Status != StatusVulnerable {
		t.Fatalf("expired_token = %+v, want vulnerable", r)
	}
	if !containsAdvisory(resp.Advisories, "already expired") {
		t.Errorf("no advisory about the already-expired token: %v", resp.Advisories)
	}
}

// TestExpiredTokenEnforcedIsSafe is the negative case: the server enforces exp,
// so a validly signed token re-signed with exp a day in the past (the secret is
// recovered here) must be refused.
func TestExpiredTokenEnforcedIsSafe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		parts := strings.Split(token, ".")
		var payload map[string]any
		if len(parts) == 3 {
			if pb, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
				_ = json.Unmarshal(pb, &payload)
			}
		}
		exp, _ := payload["exp"].(float64)
		// Refuse anything expired, which is the enforcement under test.
		if validHS256(parts, "secret") && int64(exp) > time.Now().Unix() {
			fmt.Fprint(w, "<html>Welcome back, alice@example.com. Your account overview.</html>")
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	token := signHS256(t, map[string]any{"sub": "alice", "exp": time.Now().Add(time.Hour).Unix()}, "secret")
	resp, err := RunScan(context.Background(), ScanRequest{URL: srv.URL + "/account", Token: token}, OOBConfig{})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	if resp.CrackedSecret != "secret" {
		t.Fatalf("expected the secret to be recovered for the re-sign path, got %q", resp.CrackedSecret)
	}
	if r := resultByID(resp, "expired_token"); r == nil || r.Status != StatusSafe {
		t.Errorf("expired_token = %+v, want safe", r)
	}
}

// TestExpiredTokenSkippedWithoutExpOrSecret checks that the expiry test skips
// rather than reporting when there is no exp claim, or nothing to forge with.
func TestExpiredTokenSkippedWithoutExpOrSecret(t *testing.T) {
	c := &scanCtx{payload: map[string]any{"sub": "alice"}, ok: &probeResult{StatusCode: 200}}
	if r := c.testExpiredToken(nil); r.Status != StatusSkipped {
		t.Errorf("no exp, no secret: status = %q, want skipped", r.Status)
	}
	c.payload["exp"] = float64(time.Now().Add(time.Hour).Unix())
	if r := c.testExpiredToken(nil); r.Status != StatusSkipped {
		t.Errorf("future exp, no secret: status = %q, want skipped", r.Status)
	}
}

// TestClaimTamperingNewPatchIsCaught checks a privilege claim added by this
// change: a verifier that trusts is_superuser=true on an unsigned token is caught,
// even though none of the older role/admin patches are accepted.
func TestClaimTamperingNewPatchIsCaught(t *testing.T) {
	srv := serverAccepting(func(parts []string, header map[string]any) bool {
		if len(parts) != 3 || parts[2] != "" {
			return false
		}
		pb, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return false
		}
		var payload map[string]any
		_ = json.Unmarshal(pb, &payload)
		return payload["is_superuser"] == true
	})
	defer srv.Close()

	token := signHS256(t, map[string]any{"sub": "alice", "exp": 4102444800}, "secret")
	resp, err := RunScan(context.Background(), ScanRequest{URL: srv.URL + "/account", Token: token}, OOBConfig{})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	r := resultByID(resp, "claim_tampering")
	if r == nil || r.Status != StatusVulnerable {
		t.Fatalf("claim_tampering = %+v, want vulnerable", r)
	}
	if a := attemptLabelled(r, "is_superuser"); a == nil || !a.Hit {
		t.Errorf("the is_superuser forgery was not the hit: %+v", r.Attempts)
	}
}

// TestExtendedWeakSecretIsRecovered checks that a secret from the expanded
// wordlist, here "s3cr3t", is recovered offline. The old list did not include it.
func TestExtendedWeakSecretIsRecovered(t *testing.T) {
	var requests atomic.Int32
	srv := verifyingServer(t, "s3cr3t", &requests)
	defer srv.Close()

	token := signHS256(t, map[string]any{"sub": "alice", "email": "alice@example.com", "exp": 4102444800}, "s3cr3t")
	resp, err := RunScan(context.Background(), ScanRequest{URL: srv.URL + "/account", Token: token}, OOBConfig{})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	if resp.CrackedSecret != "s3cr3t" {
		t.Errorf("CrackedSecret = %q, want s3cr3t", resp.CrackedSecret)
	}
}

// TestWordBoundaryMarkers checks that an identity marker only matches as a whole
// word. "ann" must not match inside "announcement", which is how a short name
// could previously make an unrelated page look like an accepted forgery.
func TestWordBoundaryMarkers(t *testing.T) {
	cases := []struct {
		haystack, needle string
		want             bool
	}{
		{"announcement for all users", "ann", false},
		{"hello ann.", "ann", true},
		{"welcome back, alice@example.com", "alice", true},
		{"xalice", "alice", false},
		{"alice", "alice", true},
		{"", "alice", false},
		{"anything", "", false},
	}
	for _, c := range cases {
		if got := containsWord(c.haystack, c.needle); got != c.want {
			t.Errorf("containsWord(%q, %q) = %v, want %v", c.haystack, c.needle, got, c.want)
		}
	}
}

// TestOfflineAdvisoryForExpiredToken checks the offline advisory for an exp that
// has already passed, and that a token with a future exp gets none.
func TestOfflineAdvisoryForExpiredToken(t *testing.T) {
	if !containsAdvisory(offlineAdvisories(map[string]any{"alg": "HS256"}, map[string]any{"exp": 1000}), "already expired") {
		t.Error("expired token did not get the already-expired advisory")
	}
	future := time.Now().Add(time.Hour).Unix()
	if containsAdvisory(offlineAdvisories(map[string]any{"alg": "HS256"}, map[string]any{"exp": future}), "already expired") {
		t.Error("token with a future exp was reported as expired")
	}
}

// TestProbeHonorsHostHeaderOverride checks the transport fix: a Host passed in
// the caller's headers must reach the target as the Host, which a plain
// Header.Set silently dropped.
func TestProbeHonorsHostHeaderOverride(t *testing.T) {
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if _, err := probe(newHTTPClient(), srv.URL+"/", "tok", "GET", "", map[string]string{"Host": "app.example.test"}); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if gotHost != "app.example.test" {
		t.Errorf("Host = %q, want app.example.test", gotHost)
	}
}

// containsAdvisory reports whether any advisory contains sub.
func containsAdvisory(advisories []string, sub string) bool {
	for _, a := range advisories {
		if strings.Contains(a, sub) {
			return true
		}
	}
	return false
}
