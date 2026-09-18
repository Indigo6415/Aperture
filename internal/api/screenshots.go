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

// screenshotPreviewEnabled is the on/off switch for the whole screenshot
// preview feature (capture + the thumbnails/tooltips that display it). Flip
// to true to re-enable.
const screenshotPreviewEnabled = false

// captureScreenshot renders url headlessly and persists it, unless a
// screenshot for this case+target already exists -- called (in the
// background, best-effort) from runIdentifyJob's onCheck every time a
// target's HTTP recon check resolves a live URL, so re-identifying the same
// target doesn't re-launch a browser for it. s.screenshotSem bounds how many
// of these run concurrently across the whole server, since each is a real
// browser process. jobID is only used to publish the "screenshot" event on
// that identify job's own channel.
func (s *Server) captureScreenshot(caseID, jobID, target, url string) {
	// The feature is disabled: skip launching headless Chrome entirely
	// rather than just hiding the result, since that's the expensive part.
	if !screenshotPreviewEnabled {
		return
	}
	if already, err := s.store.HasCaseScreenshot(caseID, target); err != nil || already {
		return
	}

	s.screenshotSem <- struct{}{}
	defer func() { <-s.screenshotSem }()

	ctx, cancel := context.WithTimeout(context.Background(), screenshotCaptureTimeout)
	defer cancel()

	image, err := adapters.CaptureScreenshot(ctx, url)
	if err != nil {
		// Best-effort: a missing screenshot just means no thumbnail for
		// this target, not a job failure -- most likely no headless-
		// Chrome-compatible browser is installed, which every capture
		// attempt would fail on identically.
		return
	}
	if err := s.store.SaveCaseScreenshot(caseID, target, url, image); err != nil {
		return
	}
	s.hub.publish(jobID, RunEvent{Type: "screenshot", Message: target})
}

func (s *Server) handleListCaseScreenshots(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListCaseScreenshots(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleGetCaseScreenshot(w http.ResponseWriter, r *http.Request) {
	image, err := s.store.GetCaseScreenshot(r.PathValue("id"), r.PathValue("target"))
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
