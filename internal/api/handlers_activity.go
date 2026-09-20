package api

import "net/http"

// handleListActivity returns a case's activity log, newest first -- see
// store.ListActivity and its callers throughout this package for what gets
// logged.
func (s *Server) handleListActivity(w http.ResponseWriter, r *http.Request) {
	events, err := s.store.ListActivity(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, events)
}
