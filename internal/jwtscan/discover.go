package jwtscan

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
)

// pemCandidate is one guess at the target's RS256 public key, in PEM form,
// worth trying as the RS256->HS256 confusion test's HMAC secret. source
// describes where it came from, shown in the UI so a hit (or a miss) is
// explainable rather than a mystery token.
type pemCandidate struct {
	PEM    string
	Source string
}

// jwkSet is the minimal JWKS shape (RFC 7517) discovery needs: enough to
// find an RSA signing key and skip anything else (EC keys, encryption-only
// keys, ...).
type jwkSet struct {
	Keys []struct {
		Kty string `json:"kty"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

// discoverPublicKeyPEM best-effort locates the RSA public key a target
// signs its RS256 tokens with, so the RS256->HS256 confusion test can run
// without the operator hunting the key down by hand. Tried in order: the
// token's own "jku"/"x5u" header (the standards-compliant way a server
// points at its own keys), OIDC discovery, then a handful of well-known
// paths real deployments commonly expose a key at. Returns nil -- not an
// error -- when nothing is found, since this is a nice-to-have a scan
// should degrade gracefully without, not fail over.
//
// A key reconstructed from JWKS/x5u components can't know which exact byte
// serialization the target's own code uses internally as "the secret," so
// pemCandidatesFor returns both common encodings (SubjectPublicKeyInfo and
// PKCS1) for the caller to try -- a raw PEM/cert fetched directly is used
// as-is, since those bytes are already exact.
func discoverPublicKeyPEM(client *http.Client, targetURL string, header map[string]any) []pemCandidate {
	origin, err := originOf(targetURL)
	if err != nil {
		return nil
	}

	if jku, ok := header["jku"].(string); ok && jku != "" {
		if c := candidatesFromJWKS(client, jku, fmt.Sprintf("jku header (%s)", jku)); len(c) > 0 {
			return c
		}
	}
	if x5u, ok := header["x5u"].(string); ok && x5u != "" {
		if c := candidatesFromX5U(client, x5u, fmt.Sprintf("x5u header (%s)", x5u)); len(c) > 0 {
			return c
		}
	}
	if jwksURI, err := discoverJWKSURIFrom(client, origin+"/.well-known/openid-configuration"); err == nil && jwksURI != "" {
		if c := candidatesFromJWKS(client, jwksURI, fmt.Sprintf("OIDC discovery (%s)", jwksURI)); len(c) > 0 {
			return c
		}
	}
	for _, path := range []string{"/.well-known/jwks.json", "/.well-known/jwks", "/jwks.json"} {
		u := origin + path
		if c := candidatesFromJWKS(client, u, u); len(c) > 0 {
			return c
		}
	}
	for _, path := range []string{"/public.pem", "/public_key.pem", "/publickey.pem", "/pubkey.pem", "/.well-known/public.pem"} {
		u := origin + path
		if body, err := fetchRawPEM(client, u); err == nil && body != "" {
			return []pemCandidate{{PEM: body, Source: u}}
		}
	}
	return nil
}

func originOf(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("cannot determine origin of %q", rawURL)
	}
	return u.Scheme + "://" + u.Host, nil
}

func httpGetBody(client *http.Client, targetURL string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", targetURL, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// discoverJWKSURIFrom reads an OIDC discovery document (e.g.
// /.well-known/openid-configuration) and returns its jwks_uri field.
func discoverJWKSURIFrom(client *http.Client, discoveryURL string) (string, error) {
	body, err := httpGetBody(client, discoveryURL)
	if err != nil {
		return "", err
	}
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", err
	}
	return doc.JWKSURI, nil
}

func candidatesFromJWKS(client *http.Client, jwksURL, source string) []pemCandidate {
	body, err := httpGetBody(client, jwksURL)
	if err != nil {
		return nil
	}
	var set jwkSet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil
	}
	for _, k := range set.Keys {
		if k.Kty != "RSA" || k.N == "" || k.E == "" {
			continue
		}
		pub, err := rsaPublicKeyFromJWK(k.N, k.E)
		if err != nil {
			continue
		}
		return pemCandidatesFor(pub, source)
	}
	return nil
}

// candidatesFromX5U fetches an x5u URL, which per RFC 7515 is either a
// single PEM certificate or a JSON array of base64-encoded DER certs (chain
// leaf first), and extracts its RSA public key.
func candidatesFromX5U(client *http.Client, x5uURL, source string) []pemCandidate {
	body, err := httpGetBody(client, x5uURL)
	if err != nil {
		return nil
	}

	var der []byte
	if strings.Contains(string(body), "-----BEGIN CERTIFICATE-----") {
		block, _ := pem.Decode(body)
		if block == nil {
			return nil
		}
		der = block.Bytes
	} else {
		var chain []string
		if err := json.Unmarshal(body, &chain); err != nil || len(chain) == 0 {
			return nil
		}
		decoded, err := base64.StdEncoding.DecodeString(chain[0])
		if err != nil {
			return nil
		}
		der = decoded
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil
	}
	return pemCandidatesFor(pub, source)
}

func rsaPublicKeyFromJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := b64dec(nB64)
	if err != nil {
		return nil, err
	}
	eBytes, err := b64dec(eB64)
	if err != nil {
		return nil, err
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(new(big.Int).SetBytes(eBytes).Int64())}, nil
}

// pemCandidatesFor renders pub as PEM in both encodings real
// implementations commonly use as "the key's bytes" -- SubjectPublicKeyInfo
// (the default for Python's cryptography, Node's jsonwebtoken, ...) and
// bare PKCS1 -- since which one matches what the target's own code hashes
// as the confusion attack's secret can't be known in advance.
func pemCandidatesFor(pub *rsa.PublicKey, source string) []pemCandidate {
	var out []pemCandidate
	if der, err := x509.MarshalPKIXPublicKey(pub); err == nil {
		out = append(out, pemCandidate{
			PEM:    string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
			Source: source + ", SubjectPublicKeyInfo encoding",
		})
	}
	out = append(out, pemCandidate{
		PEM:    string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(pub)})),
		Source: source + ", PKCS1 encoding",
	})
	return out
}

func fetchRawPEM(client *http.Client, targetURL string) (string, error) {
	body, err := httpGetBody(client, targetURL)
	if err != nil {
		return "", err
	}
	if !strings.Contains(string(body), "-----BEGIN") {
		return "", fmt.Errorf("response is not a PEM-encoded key")
	}
	return string(body), nil
}
