package api

import (
	"encoding/json"
	"net/http"
)

// settingDNSDumpsterKey is the store.Setting key the DNSDumpster API key is
// persisted under (see runScan in handlers_scan.go, which reads it back).
const settingDNSDumpsterKey = "dnsdumpster_api_key"

// settingsResponse never echoes the API key itself back to the client --
// only whether one is configured -- so a page reload doesn't need to
// re-display (or silently leak, e.g. via browser devtools/history) a
// secret that was already saved.
type settingsResponse struct {
	DNSDumpsterAPIKeySet bool `json:"dnsdumpsterApiKeySet"`
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	key, ok, err := s.store.GetSetting(settingDNSDumpsterKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, settingsResponse{DNSDumpsterAPIKeySet: ok && key != ""})
}

type setDNSDumpsterKeyRequest struct {
	APIKey string `json:"apiKey"`
}

// handleSetDNSDumpsterKey saves (or, given an empty apiKey, clears) the
// DNSDumpster API key used by every scan's DNSDumpster check going forward
// -- see runScan in handlers_scan.go.
func (s *Server) handleSetDNSDumpsterKey(w http.ResponseWriter, r *http.Request) {
	var req setDNSDumpsterKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.SetSetting(settingDNSDumpsterKey, req.APIKey); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, settingsResponse{DNSDumpsterAPIKeySet: req.APIKey != ""})
}
