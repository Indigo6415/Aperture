package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/Indigo6415/Aperture/internal/collaborator"
)

// Settings keys for the callback listener's HTTPS side. The certificate and key
// live in the same settings store as the rest of the collaborator config, so
// they survive restarts without a separate file.
const (
	settingCollabTLSEnabled = "collaborator_tls_enabled"
	settingCollabTLSCert    = "collaborator_tls_cert"
	settingCollabTLSKey     = "collaborator_tls_key"
)

// collabTLSStatus is what the Collaborator tab shows about the HTTPS side.
type collabTLSStatus struct {
	Enabled bool                   `json:"enabled"`
	HasCert bool                   `json:"hasCert"`
	Cert    *collaborator.CertInfo `json:"cert,omitempty"`
}

// collabTLSEnabled reports whether the callback listener should accept TLS
// handshakes. Stored as "1" or "0"; anything else (including an unset value)
// means off.
func (s *Server) collabTLSEnabled() bool {
	v, _, _ := s.store.GetSetting(settingCollabTLSEnabled)
	return v == "1"
}

// collabGetCertificate is the TLS config's GetCertificate hook. It loads the
// stored certificate on every handshake, so regenerating or disabling it from
// the UI takes effect immediately without restarting the listener.
func (s *Server) collabGetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	certPEM, _, _ := s.store.GetSetting(settingCollabTLSCert)
	keyPEM, _, _ := s.store.GetSetting(settingCollabTLSKey)
	if certPEM == "" || keyPEM == "" {
		return nil, fmt.Errorf("collaborator TLS: no certificate stored")
	}
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("collaborator TLS: stored certificate is invalid: %w", err)
	}
	return &pair, nil
}

// generateCollabCert creates a new self-signed certificate and stores it,
// replacing any existing one. Its SANs are the loopback address plus whatever
// LAN and public IPs can be detected now, so a client that accepts self-signed
// certificates sees a name that matches the address it connected to. The public
// lookup is bounded by a short timeout so this never blocks long.
func (s *Server) generateCollabCert(ctx context.Context) error {
	ips := []net.IP{net.ParseIP("127.0.0.1")}
	if lan, err := collaborator.LocalIPv4(); err == nil {
		ips = append(ips, net.ParseIP(lan))
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if pub, err := collaborator.PublicIPv4(lookupCtx); err == nil {
		ips = append(ips, net.ParseIP(pub))
	}

	certPEM, keyPEM, err := collaborator.NewSelfSignedCert(ips, []string{"localhost"})
	if err != nil {
		return err
	}
	if err := s.store.SetSetting(settingCollabTLSCert, string(certPEM)); err != nil {
		return err
	}
	return s.store.SetSetting(settingCollabTLSKey, string(keyPEM))
}

// collabTLSStatusNow reads the current HTTPS state and, when a certificate is
// stored, its display details.
func (s *Server) collabTLSStatusNow() collabTLSStatus {
	st := collabTLSStatus{Enabled: s.collabTLSEnabled()}
	certPEM, _, _ := s.store.GetSetting(settingCollabTLSCert)
	if certPEM == "" {
		return st
	}
	st.HasCert = true
	if info, err := collaborator.DescribeCertPEM([]byte(certPEM)); err == nil {
		st.Cert = &info
	}
	return st
}

// handleGetCollabTLS returns whether HTTPS is on and the stored certificate's
// details (fingerprint, validity, names), for the Collaborator tab.
func (s *Server) handleGetCollabTLS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.collabTLSStatusNow())
}

// handleSetCollabTLS turns HTTPS on or off. Turning it on with no certificate
// stored generates one first, so the setting never points at nothing. Turning
// it off leaves the certificate in place, so re-enabling keeps the same
// fingerprint.
func (s *Server) handleSetCollabTLS(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Enabled {
		certPEM, _, _ := s.store.GetSetting(settingCollabTLSCert)
		if certPEM == "" {
			if err := s.generateCollabCert(r.Context()); err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
		}
	}
	val := "0"
	if req.Enabled {
		val = "1"
	}
	if err := s.store.SetSetting(settingCollabTLSEnabled, val); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, s.collabTLSStatusNow())
}

// handleRegenerateCollabTLS replaces the stored certificate with a new one,
// which changes its fingerprint. Used when the detected addresses have changed
// and the SANs should be refreshed, or to rotate the key.
func (s *Server) handleRegenerateCollabTLS(w http.ResponseWriter, r *http.Request) {
	if err := s.generateCollabCert(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, s.collabTLSStatusNow())
}
