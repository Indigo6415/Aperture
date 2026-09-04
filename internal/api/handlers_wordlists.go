package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Indigo6415/Aperture/internal/wordlists"
)

func (s *Server) handleListWordlists(w http.ResponseWriter, r *http.Request) {
	list, err := wordlists.List(s.wordlistsDir)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleWordlistCatalog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, wordlists.Catalog())
}

type downloadWordlistRequest struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"` // omit to download a known Catalog entry by name
}

// handleDownloadWordlist saves a wordlist under Name, either from an
// explicit URL or by looking Name up in the built-in Catalog.
func (s *Server) handleDownloadWordlist(w http.ResponseWriter, r *http.Request) {
	var req downloadWordlistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("name is required"))
		return
	}

	url := req.URL
	if url == "" {
		for _, entry := range wordlists.Catalog() {
			if entry.Name == req.Name {
				url = entry.URL
				break
			}
		}
	}
	if url == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("no catalog entry named %q and no url given", req.Name))
		return
	}

	if err := wordlists.Download(r.Context(), s.wordlistsDir, req.Name, url); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteWordlist(w http.ResponseWriter, r *http.Request) {
	if err := wordlists.Delete(s.wordlistsDir, r.PathValue("name")); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type setCategoriesRequest struct {
	Categories []wordlists.Category `json:"categories"`
}

// handleSetWordlistCategories replaces the full category set a wordlist
// belongs to -- the drag-and-drop UI sends the complete resulting set on
// every drop rather than one add/remove at a time.
func (s *Server) handleSetWordlistCategories(w http.ResponseWriter, r *http.Request) {
	var req setCategoriesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := wordlists.SetCategories(s.wordlistsDir, r.PathValue("name"), req.Categories); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type duplicateWordlistRequest struct {
	NewName    string               `json:"newName"`
	Categories []wordlists.Category `json:"categories,omitempty"`
}

// handleDuplicateWordlist copies a wordlist under a new name so the same
// content can be tagged into a second category (e.g. drag "common.txt"
// into Misc too) without the original losing its own category.
func (s *Server) handleDuplicateWordlist(w http.ResponseWriter, r *http.Request) {
	var req duplicateWordlistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.NewName == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("newName is required"))
		return
	}
	if err := wordlists.Duplicate(s.wordlistsDir, r.PathValue("name"), req.NewName, req.Categories); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
