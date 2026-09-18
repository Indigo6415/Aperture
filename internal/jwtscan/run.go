package jwtscan

import (
	"fmt"
	"strings"
)

// ScanRequest is everything one JWT misconfiguration scan needs -- mirrors
// JWTear's CLI flags (-u/-t/-m/--cookie/--pubkey/--wordlist/-H) one for one.
type ScanRequest struct {
	URL          string
	Token        string
	Method       string // defaults to GET
	Cookie       string // empty sends the token as Authorization: Bearer instead
	ExtraHeaders map[string]string
	PubKeyPEM    string   // enables the RS256->HS256 confusion test
	ExtraSecrets []string // extends the built-in weak-secret wordlist
}

// Baseline records the two reference requests every test's hit/miss
// judgement is made against: the caller's real token, and a token that can
// never be valid.
type Baseline struct {
	ValidStatus   int `json:"validStatus"`
	ValidLength   int `json:"validLength"`
	InvalidStatus int `json:"invalidStatus"`
	InvalidLength int `json:"invalidLength"`
	// Identical is true when the valid and invalid baselines are
	// indistinguishable by status+length -- every test result then rests
	// entirely on the content-length heuristic and should be treated with
	// extra suspicion.
	Identical bool `json:"identical"`
}

// ScanResponse is the full result of one scan: the decoded source token
// plus every test's outcome, in a fixed, UI-friendly order.
type ScanResponse struct {
	Header        map[string]any `json:"header"`
	Payload       map[string]any `json:"payload"`
	Baseline      Baseline       `json:"baseline"`
	Results       []TestResult   `json:"results"`
	CrackedSecret string         `json:"crackedSecret,omitempty"`
	// SecretsTried is how many candidate secrets the weak-secret test
	// actually ran, after applying maxSecretAttempts -- shown in the UI so
	// a truncated custom wordlist isn't mistaken for a full run.
	SecretsTried int `json:"secretsTried"`
}

// RunScan parses req.Token, establishes baselines against req.URL, then
// runs every misconfiguration test against it. Returns an error only when
// the scan itself can't proceed at all (bad token, unreachable target, or a
// token that the target doesn't even accept) -- once running, every
// individual test failing to find anything is a normal ScanResponse result,
// not an error.
func RunScan(req ScanRequest) (*ScanResponse, error) {
	header, payload, _, err := ParseJWT(req.Token)
	if err != nil {
		return nil, fmt.Errorf("cannot parse JWT: %w", err)
	}

	method := req.Method
	if method == "" {
		method = "GET"
	}
	client := newHTTPClient()

	okResp, err := probe(client, req.URL, req.Token, method, req.Cookie, req.ExtraHeaders)
	if err != nil {
		return nil, fmt.Errorf("could not reach target with the provided token: %w", err)
	}
	if okResp.StatusCode >= 400 {
		return nil, fmt.Errorf(
			"the provided token was rejected (HTTP %d) -- make sure it grants access to this exact URL/method before scanning",
			okResp.StatusCode,
		)
	}

	failResp, err := probe(client, req.URL, invalidBaselineToken, method, req.Cookie, req.ExtraHeaders)
	if err != nil {
		return nil, fmt.Errorf("baseline invalid-token request failed: %w", err)
	}

	ctx := &scanCtx{
		client: client, url: req.URL, method: method, cookie: req.Cookie,
		headers: req.ExtraHeaders, header: header, payload: payload,
		ok: okResp, fail: failResp,
	}

	secrets := make([]string, 0, len(weakSecrets)+len(req.ExtraSecrets))
	seen := make(map[string]struct{}, len(weakSecrets)+len(req.ExtraSecrets))
	for _, s := range weakSecrets {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		secrets = append(secrets, s)
	}
	for _, s := range req.ExtraSecrets {
		if len(secrets) >= maxSecretAttempts {
			break
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		secrets = append(secrets, s)
	}

	weakResult, cracked := ctx.testWeakSecret(secrets)

	// Auto-discovery only makes sense for an RSA-signed source token (there's
	// no RS256 public key to find otherwise) and never overrides a key the
	// caller explicitly provided -- see testRS256HS256.
	var discoveredKey []pemCandidate
	if strings.TrimSpace(req.PubKeyPEM) == "" {
		if alg, _ := header["alg"].(string); strings.HasPrefix(strings.ToUpper(alg), "RS") {
			discoveredKey = discoverPublicKeyPEM(client, req.URL, header)
		}
	}

	resp := &ScanResponse{
		Header:  header,
		Payload: payload,
		Baseline: Baseline{
			ValidStatus:   okResp.StatusCode,
			ValidLength:   okResp.Length,
			InvalidStatus: failResp.StatusCode,
			InvalidLength: failResp.Length,
			Identical:     okResp.StatusCode == failResp.StatusCode && okResp.Length == failResp.Length,
		},
		SecretsTried: len(secrets),
		Results: []TestResult{
			ctx.testAlgNone(),
			ctx.testEmptySig(),
			weakResult,
			ctx.testJWKInjection(),
			ctx.testKidInjection(),
			ctx.testClaimTampering(cracked),
			ctx.testRS256HS256(req.PubKeyPEM, discoveredKey),
		},
	}
	if cracked != nil {
		resp.CrackedSecret = *cracked
	}
	return resp, nil
}
