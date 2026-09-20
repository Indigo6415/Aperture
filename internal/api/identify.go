package api

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Indigo6415/Aperture/internal/cve"
	"github.com/Indigo6415/Aperture/internal/recon"
	"github.com/Indigo6415/Aperture/internal/store"
)

// cveCacheTTL is how long a cached NVD lookup (see store.GetCVECache) is
// trusted before lookupTechCVEs re-fetches it -- long enough that
// re-identifying the same target minutes/hours later doesn't re-hit NVD at
// all, short enough that a product/version doesn't go too long without
// picking up newly-published CVEs.
const cveCacheTTL = 7 * 24 * time.Hour

// runIdentifyJob is the "Identify" action: it runs passive/read-only recon
// (DNS/TLS/HTTP/WHOIS/subdomain discovery, internal/recon) against each of
// the job's targets in turn, streaming each recon.Check as it completes
// (including, per completed HTTP check, a best-effort technology-
// fingerprint -> CVE lookup, see lookupTechCVEs) and persisting them via
// SaveCaseCheck. Unlike an engine-backed job, there's no Flow/Run underneath
// -- store.FinishJob on the jobs row directly is authoritative for its
// status. Targets run sequentially, not concurrently: recon.Scan already
// bounds its own internal subdomain fan-out per target, and stacking N of
// those (each doing its own WHOIS/crt.sh lookups) at once would multiply
// that fan-out unbounded.
func (s *Server) runIdentifyJob(caseID, jobID string, targets []string) {
	ctx, cancel := context.WithCancel(context.Background())
	s.trackJobCancel(jobID, cancel)
	defer func() {
		s.untrackJobCancel(jobID)
		cancel()
	}()

	// DNSDumpster needs a per-installation API key recon.Scan itself has no
	// access to (it comes from a store-backed setting, not anything the
	// recon package knows about) -- fetched here and passed in; an empty
	// key makes Scan skip that check entirely rather than emit one that can
	// only ever fail.
	dnsdumpsterKey, _, err := s.store.GetSetting(settingDNSDumpsterKey)
	if err != nil {
		s.hub.publish(jobID, RunEvent{Type: "done", Message: "warning: failed to load DNSDumpster key: " + err.Error()})
	}

	onCheck := func(c recon.Check) {
		// A completed HTTP check reveals a live URL for whatever target it
		// ran against -- opportunistically capture a screenshot of it.
		// captureScreenshot itself skips targets it's already shot, so
		// re-identifying the same target is cheap.
		if c.Kind == recon.KindHTTP && c.Status == recon.StatusDone {
			if finalURL, ok := c.Data["finalUrl"].(string); ok && finalURL != "" {
				go s.captureScreenshot(caseID, jobID, c.Domain, finalURL)
			}
			go s.lookupTechCVEs(ctx, caseID, jobID, c.Domain, c.Data)
		}
		if err := s.store.SaveCaseCheck(caseID, jobID, c); err != nil {
			// The check is still delivered live below even if persisting it
			// failed, so a slow/broken disk doesn't stall the job.
			s.hub.publish(jobID, RunEvent{Type: "check", Check: &c, Message: "warning: failed to persist check: " + err.Error()})
			return
		}
		s.hub.publish(jobID, RunEvent{Type: "check", Check: &c})
	}

	for _, target := range targets {
		if ctx.Err() != nil {
			break
		}
		recon.Scan(ctx, target, dnsdumpsterKey, onCheck)
	}

	final := store.RunSucceeded
	if ctx.Err() != nil {
		final = store.RunCancelled
	}
	_ = s.store.FinishJob(jobID, final, "")
	_ = s.store.LogActivity(caseID, "job_finished", fmt.Sprintf("Job %s finished: %s", jobID, final))
	s.hub.publish(jobID, RunEvent{Type: "done", Message: string(final)})
}

// techCVEResult is one fingerprinted technology's version plus whatever
// CVEs were found for it -- the shape lookupTechCVEs assembles per target
// and publishes as a "technologies" Check (see recon.Check; this isn't a
// recon.CheckKind constant since the recon package has no store/NVD access
// of its own, same reasoning as CheckDNSDumpster's doc comment).
type techCVEResult struct {
	Name     string    `json:"name"`
	Category string    `json:"category"`
	Version  string    `json:"version,omitempty"`
	CVEs     []cve.CVE `json:"cves,omitempty"`
}

// lookupTechCVEs replaces the old nmap -sV "service profile" feature: given
// one target's completed HTTP check data (which already carries
// techfp-detected technologies, see recon/http.go), it looks up CVEs for
// every technology with a known version -- cached in SQLite
// (store.GetCVECache/SetCVECache, see cveCacheTTL) so repeat identify runs
// against common software don't re-hit NVD -- and publishes the aggregate
// as a "technologies" Check, the same way recon's own checks stream to the
// client. s.techSem bounds how many of these run at once across the whole
// server; called in the background (best-effort) from runIdentifyJob's
// onCheck so a slow/rate-limited NVD lookup never holds up the rest of
// recon.
func (s *Server) lookupTechCVEs(ctx context.Context, caseID, jobID, target string, httpData map[string]any) {
	raw, ok := httpData["technologies"].([]map[string]any)
	if !ok || len(raw) == 0 {
		return
	}

	s.techSem <- struct{}{}
	defer func() { <-s.techSem }()

	nvdKey, _, _ := s.store.GetSetting(settingNVDAPIKey)

	results := make([]techCVEResult, 0, len(raw))
	for _, t := range raw {
		name, _ := t["name"].(string)
		category, _ := t["category"].(string)
		version, _ := t["version"].(string)
		r := techCVEResult{Name: name, Category: category, Version: version}
		if version != "" {
			r.CVEs = s.cvesFor(ctx, name, version, nvdKey)
		}
		results = append(results, r)
	}

	c := recon.Check{
		Domain: target, Kind: "technologies", Status: recon.StatusDone,
		StartedAt: time.Now(), FinishedAt: time.Now(),
		Data: map[string]any{"technologies": results},
	}
	if err := s.store.SaveCaseCheck(caseID, jobID, c); err != nil {
		return
	}
	s.hub.publish(jobID, RunEvent{Type: "check", Check: &c})
}

// cvesFor returns product+version's CVEs, using the SQLite cache when
// there's a fresh-enough (within cveCacheTTL) entry and falling back to a
// live NVD lookup otherwise. A lookup failure (network error, rate limit
// exhausted, ...) just yields no CVEs for this technology rather than
// failing the whole check -- best-effort, same as screenshot capture.
func (s *Server) cvesFor(ctx context.Context, product, version, nvdKey string) []cve.CVE {
	if cached, fetchedAt, ok, err := s.store.GetCVECache(product, version); err == nil && ok && time.Since(fetchedAt) < cveCacheTTL {
		var cves []cve.CVE
		if json.Unmarshal([]byte(cached), &cves) == nil {
			return cves
		}
	}

	cves, err := cve.Lookup(ctx, product, version, nvdKey)
	if err != nil {
		return nil
	}
	// Layered on before caching, so a cache hit above already carries KEV/
	// EPSS too and doesn't need to re-fetch either on every repeat lookup.
	cve.EnrichExploitSignals(ctx, cves)
	if data, err := json.Marshal(cves); err == nil {
		_ = s.store.SetCVECache(product, version, string(data))
	}
	return cves
}
