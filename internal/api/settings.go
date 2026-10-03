package api

import (
	"encoding/json"
	"net/http"
)

// settingDNSDumpsterKey is the store.Setting key the DNSDumpster API key is
// persisted under (see runScan in handlers_scan.go, which reads it back).
const settingDNSDumpsterKey = "dnsdumpster_api_key"

// settingNVDAPIKey is the store.Setting key the NVD API key is persisted
// under (see lookupTechCVEs in handlers_scan.go, which reads it back).
// Optional -- NVD's keyword-search API works without one, just at a lower
// rate limit (5 req/30s vs 50 req/30s with a key, see internal/cve).
const settingNVDAPIKey = "nvd_api_key"

// settingHIBPAPIKey is the store.Setting key the HaveIBeenPwned API key is
// persisted under (see handleBreachCheck in handlers_breach.go). Unlike
// DNSDumpster/NVD, this one is required, not optional -- HIBP's
// breached-account endpoint has rejected keyless requests since 2024.
const settingHIBPAPIKey = "hibp_api_key"

// settingsResponse never echoes an API key itself back to the client --
// only whether one is configured -- so a page reload doesn't need to
// re-display (or silently leak, e.g. via browser devtools/history) a
// secret that was already saved.
type settingsResponse struct {
	DNSDumpsterAPIKeySet bool `json:"dnsdumpsterApiKeySet"`
	NVDAPIKeySet         bool `json:"nvdApiKeySet"`
	HIBPAPIKeySet        bool `json:"hibpApiKeySet"`
}

func (s *Server) settingsInfo() (settingsResponse, error) {
	ddKey, ddOK, err := s.store.GetSetting(settingDNSDumpsterKey)
	if err != nil {
		return settingsResponse{}, err
	}
	nvdKey, nvdOK, err := s.store.GetSetting(settingNVDAPIKey)
	if err != nil {
		return settingsResponse{}, err
	}
	hibpKey, hibpOK, err := s.store.GetSetting(settingHIBPAPIKey)
	if err != nil {
		return settingsResponse{}, err
	}
	return settingsResponse{
		DNSDumpsterAPIKeySet: ddOK && ddKey != "",
		NVDAPIKeySet:         nvdOK && nvdKey != "",
		HIBPAPIKeySet:        hibpOK && hibpKey != "",
	}, nil
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	info, err := s.settingsInfo()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

type setAPIKeyRequest struct {
	APIKey string `json:"apiKey"`
}

// handleSetDNSDumpsterKey saves (or, given an empty apiKey, clears) the
// DNSDumpster API key used by every scan's DNSDumpster check going forward
// -- see runScan in handlers_scan.go.
func (s *Server) handleSetDNSDumpsterKey(w http.ResponseWriter, r *http.Request) {
	var req setAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.SetSetting(settingDNSDumpsterKey, req.APIKey); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	info, err := s.settingsInfo()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// handleSetNVDKey saves (or, given an empty apiKey, clears) the NVD API key
// used by every scan's technology-fingerprint -> CVE lookups going forward
// -- see lookupTechCVEs in handlers_scan.go.
func (s *Server) handleSetNVDKey(w http.ResponseWriter, r *http.Request) {
	var req setAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.SetSetting(settingNVDAPIKey, req.APIKey); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	info, err := s.settingsInfo()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// handleSetHIBPKey saves (or, given an empty apiKey, clears) the
// HaveIBeenPwned API key used by the Breach Check tab -- see
// handleBreachCheck in handlers_breach.go.
func (s *Server) handleSetHIBPKey(w http.ResponseWriter, r *http.Request) {
	var req setAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.SetSetting(settingHIBPAPIKey, req.APIKey); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	info, err := s.settingsInfo()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}
