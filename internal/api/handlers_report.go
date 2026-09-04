package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/Indigo6415/Aperture/internal/report"
	"github.com/Indigo6415/Aperture/internal/store"
)

// handleScanReport is the "Download report" action: it bundles a scan's
// recon checks and every scanner run's findings into one document, in
// whichever of json/html/pdf the ?format= query param names (json is the
// default). This is what wires engine.KindExport's underlying idea to an
// actual UI action -- see internal/report's package doc for how it relates
// to the flow-node export.
func (s *Server) handleScanReport(w http.ResponseWriter, r *http.Request) {
	scanID := r.PathValue("id")
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	rep, err := report.Build(s.store, scanID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	filename := "aperture-report-" + rep.Scan.Domain
	switch format {
	case "json":
		b, err := rep.RenderJSON()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, filename))
		_, _ = w.Write(b)
	case "html":
		b, err := rep.RenderHTML()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.html"`, filename))
		_, _ = w.Write(b)
	case "pdf":
		b, err := rep.RenderPDF(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.pdf"`, filename))
		_, _ = w.Write(b)
	default:
		writeError(w, http.StatusBadRequest, fmt.Errorf("report: unknown format %q (want json, html, or pdf)", format))
	}
}
