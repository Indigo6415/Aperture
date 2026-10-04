package collaborator

import (
	"net"
	"testing"
)

// TestRegistryTokensAreUniqueAndRecordedInteractionsArePollable checks token
// minting and that an interaction recorded for a token comes back from Poll.
func TestRegistryTokensAreUniqueAndRecordedInteractionsArePollable(t *testing.T) {
	r := NewRegistry()
	a, b := r.NewToken(), r.NewToken()
	if a == "" || a == b {
		t.Fatalf("tokens must be non-empty and distinct, got %q and %q", a, b)
	}
	r.Record(a, Interaction{Protocol: "http"})
	if got := r.Poll(a); len(got) == 0 {
		t.Fatal("Poll returned nothing for a token that received an interaction")
	}
	if got := r.Poll(b); len(got) != 0 {
		t.Fatalf("Poll leaked %d interactions to an unrelated token", len(got))
	}
}

// TestSelfSignedCertDescribesItself checks the generated certificate parses
// back and reports a fingerprint, which the UI shows to the operator.
func TestSelfSignedCertDescribesItself(t *testing.T) {
	certPEM, keyPEM, err := NewSelfSignedCert([]net.IP{net.ParseIP("127.0.0.1")}, []string{"collab.test"})
	if err != nil {
		t.Fatalf("NewSelfSignedCert: %v", err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("expected both a certificate and a key")
	}
	info, err := DescribeCertPEM(certPEM)
	if err != nil {
		t.Fatalf("DescribeCertPEM: %v", err)
	}
	if info.Fingerprint == "" {
		t.Fatal("certificate fingerprint is empty")
	}
	if !info.NotAfter.After(info.NotBefore) {
		t.Fatal("certificate validity window is empty or inverted")
	}
}
