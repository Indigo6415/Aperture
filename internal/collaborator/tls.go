package collaborator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// selfSignedValidity is how long a generated certificate stays valid. The
// certificate is self-signed and only used for the callback listener, so a
// long lifetime avoids surprise expiry without weakening anything a client
// could check (it can't check a self-signed chain anyway).
const selfSignedValidity = 365 * 24 * time.Hour

// CertInfo describes a stored certificate for display in the UI. Fingerprint
// is the SHA-256 of the DER certificate, the value an operator would compare
// against when pinning or trusting it.
type CertInfo struct {
	Fingerprint string    `json:"fingerprint"`
	NotBefore   time.Time `json:"notBefore"`
	NotAfter    time.Time `json:"notAfter"`
	Subjects    []string  `json:"subjects"`
}

// NewSelfSignedCert generates a fresh ECDSA P-256 key and a self-signed
// certificate for the callback listener. ips and dnsNames become its Subject
// Alternative Names, so a client that tolerates the self-signed trust problem
// (curl -k, verify=False) still sees a matching name. Returns PEM-encoded
// certificate and key.
func NewSelfSignedCert(ips []net.IP, dnsNames []string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Aperture collaborator"},
		// Backdate slightly so a client whose clock is a little behind still sees it as valid.
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(selfSignedValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           ips,
		DNSNames:              dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// DescribeCertPEM parses a PEM certificate and returns its display details.
// Returns an error if the PEM doesn't hold a valid X.509 certificate.
func DescribeCertPEM(certPEM []byte) (CertInfo, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return CertInfo{}, fmt.Errorf("no CERTIFICATE PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return CertInfo{}, err
	}
	sum := sha256.Sum256(cert.Raw)
	info := CertInfo{
		Fingerprint: fmt.Sprintf("%X", sum[:]),
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
	}
	for _, ip := range cert.IPAddresses {
		info.Subjects = append(info.Subjects, ip.String())
	}
	info.Subjects = append(info.Subjects, cert.DNSNames...)
	return info, nil
}
