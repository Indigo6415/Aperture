package probescan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

const certExpiryWarningDays = 30

// fetchCertificate opens a raw TLS connection to the target and returns the
// leaf certificate the server presented, verifying nothing (this tool
// routinely targets self-signed lab boxes) -- ported from certificate.py's
// _get_certificate.
func fetchCertificate(ctx context.Context, t *Target) (*x509.Certificate, error) {
	addr := net.JoinHostPort(t.Hostname, fmt.Sprint(t.Port))
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: probeTimeout},
		Config:    &tls.Config{InsecureSkipVerify: true, ServerName: t.Hostname}, //nolint:gosec // deliberate: inspecting the cert, not trusting it
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("not a TLS connection")
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate presented")
	}
	return certs[0], nil
}

func certHostnameMatches(cert *x509.Certificate, hostname string) bool {
	if err := cert.VerifyHostname(hostname); err == nil {
		return true
	}
	// VerifyHostname already handles wildcard matching; nothing further to
	// try -- mirrors certificate.py's SAN/commonName wildcard check.
	return false
}

// certificateModule ports modules/certificate.py: expiry, not-yet-valid,
// hostname mismatch, self-signed, and weak-signature checks. Only runs for
// https:// targets, same as the original's early return.
var certificateModule = moduleDef{
	id:       "certificate",
	name:     "TLS Certificate",
	severity: "medium",
	run: func(ctx context.Context, t *Target, c *probeClient) []Finding {
		if !strings.HasPrefix(t.URL, "https://") {
			return nil
		}

		cert, err := fetchCertificate(ctx, t)
		if err != nil {
			return []Finding{{Label: "Could not retrieve TLS certificate: " + err.Error()}}
		}

		var findings []Finding
		now := time.Now().UTC()

		if cert.NotAfter.Before(now) {
			days := int(now.Sub(cert.NotAfter).Hours() / 24)
			findings = append(findings, Finding{
				Label: fmt.Sprintf("Certificate expired %d days ago (expired %s)", days, cert.NotAfter.Format("2006-01-02")),
			})
		} else if days := int(cert.NotAfter.Sub(now).Hours() / 24); days < certExpiryWarningDays {
			findings = append(findings, Finding{
				Label: fmt.Sprintf("Certificate expires in %d days (%s)", days, cert.NotAfter.Format("2006-01-02")),
			})
		}

		if now.Before(cert.NotBefore) {
			findings = append(findings, Finding{
				Label: "Certificate is not yet valid (valid from " + cert.NotBefore.Format("2006-01-02") + ")",
			})
		}

		if !certHostnameMatches(cert, t.Hostname) {
			names := cert.DNSNames
			if len(names) == 0 && cert.Subject.CommonName != "" {
				names = []string{cert.Subject.CommonName}
			}
			findings = append(findings, Finding{
				Label: fmt.Sprintf("Certificate hostname mismatch -- cert valid for %v, got %s", names, t.Hostname),
			})
		}

		if cert.Subject.String() == cert.Issuer.String() {
			findings = append(findings, Finding{
				Label: "Certificate is self-signed (issuer == subject: " + cert.Subject.CommonName + ")",
			})
		}

		if cert.SignatureAlgorithm == x509.MD5WithRSA || cert.SignatureAlgorithm == x509.SHA1WithRSA || cert.SignatureAlgorithm == x509.DSAWithSHA1 || cert.SignatureAlgorithm == x509.ECDSAWithSHA1 {
			findings = append(findings, Finding{
				Label: "Certificate uses weak " + cert.SignatureAlgorithm.String() + " signature algorithm",
			})
		}

		return findings
	},
}
