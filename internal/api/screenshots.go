package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Indigo6415/Aperture/internal/adapters"
	"github.com/Indigo6415/Aperture/internal/store"
)

// screenshotCaptureTimeout bounds one capture end to end (launching headless
// Chrome, navigating, saving the PNG) -- generous enough for a slow site
// without letting one hung capture linger indefinitely in the background.
const screenshotCaptureTimeout = 30 * time.Second

// captureScreenshot renders url headlessly and persists it, unless a
// screenshot for this scan+hostname already exists -- called (in the
// background, best-effort) from runScan's onCheck every time a host's HTTP
// recon check resolves a live URL, so a restarted scan re-observing the
// same host doesn't re-launch a browser for it. s.screenshotSem bounds how
// many of these run concurrently across the whole server, since each is a
// real browser process.
func (s *Server) captureScreenshot(scanID, hostname, url string) {
	if already, err := s.store.HasScreenshot(scanID, hostname); err != nil || already {
		return
	}

	s.screenshotSem <- struct{}{}
	defer func() { <-s.screenshotSem }()

	ctx, cancel := context.WithTimeout(context.Background(), screenshotCaptureTimeout)
	defer cancel()

	image, err := adapters.CaptureScreenshot(ctx, url)
	if err != nil {
		// Best-effort: a missing screenshot just means no thumbnail for
		// this host, not a scan failure -- most likely no headless-Chrome-
		// compatible browser is installed, which every capture attempt
		// would fail on identically.
		return
	}
	if err := s.store.SaveScreenshot(scanID, hostname, url, image); err != nil {
		return
	}
	s.hub.publish(scanID, RunEvent{Type: "screenshot", Message: hostname})
}

func (s *Server) handleListScreenshots(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListScreenshots(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleGetScreenshot(w http.ResponseWriter, r *http.Request) {
	image, err := s.store.GetScreenshot(r.PathValue("id"), r.PathValue("hostname"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(image)
}
