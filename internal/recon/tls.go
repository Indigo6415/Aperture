package recon

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// checkTLS dials domain:443 and inspects the leaf certificate presented.
// InsecureSkipVerify is intentional: Aperture is a recon tool and wants to
// report on whatever certificate a host presents (self-signed, expired,
// wrong hostname, ...) rather than refuse to connect to it.
//
// Data shape: {"subject": string, "issuer": string, "sans": []string,
// "notBefore": time.Time, "notAfter": time.Time, "daysRemaining": int}
func checkTLS(ctx context.Context, domain string) (map[string]any, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config:    &tls.Config{InsecureSkipVerify: true, ServerName: domain},
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(domain, "443"))
	if err != nil {
		return nil, fmt.Errorf("tls dial: %w", err)
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok || len(tlsConn.ConnectionState().PeerCertificates) == 0 {
		return nil, fmt.Errorf("tls: no certificate presented")
	}
	leaf := tlsConn.ConnectionState().PeerCertificates[0]

	return map[string]any{
		"subject":       leaf.Subject.CommonName,
		"issuer":        leaf.Issuer.CommonName,
		"sans":          leaf.DNSNames,
		"notBefore":     leaf.NotBefore,
		"notAfter":      leaf.NotAfter,
		"daysRemaining": int(time.Until(leaf.NotAfter).Hours() / 24),
	}, nil
}
