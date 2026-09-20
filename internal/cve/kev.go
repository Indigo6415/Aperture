package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	kevFeedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	epssAPIURL = "https://api.first.org/data/v1/epss"

	// kevCatalogTTL bounds how long the in-memory KEV catalog is trusted
	// before EnrichExploitSignals re-fetches it -- CISA updates the feed a
	// few times a week at most, so a day-long cache avoids re-downloading
	// the ~1-2MB catalog on every lookup without meaningfully lagging
	// behind new entries.
	kevCatalogTTL = 24 * time.Hour
)

// kevCatalog mirrors the subset of CISA's KEV feed shape this package
// cares about -- see
// https://www.cisa.gov/known-exploited-vulnerabilities-catalog.
type kevCatalog struct {
	Vulnerabilities []struct {
		CveID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

// kevCache holds the whole catalog's CVE ID set process-wide, shared
// across every case/target rather than re-fetched per lookup -- guarded by
// kevMu like limiters above guards the rate limiter map.
var (
	kevMu        sync.Mutex
	kevSet       map[string]bool
	kevFetchedAt time.Time
)

// fetchKEV returns the current CVE ID set in CISA's Known Exploited
// Vulnerabilities catalog, using the cached copy when it's still within
// kevCatalogTTL.
func fetchKEV(ctx context.Context) (map[string]bool, error) {
	kevMu.Lock()
	if kevSet != nil && time.Since(kevFetchedAt) < kevCatalogTTL {
		set := kevSet
		kevMu.Unlock()
		return set, nil
	}
	kevMu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, kevFeedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("cve: build KEV request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cve: fetch KEV catalog: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cve: KEV catalog: unexpected status %d", resp.StatusCode)
	}

	var parsed kevCatalog
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("cve: decode KEV catalog: %w", err)
	}

	set := make(map[string]bool, len(parsed.Vulnerabilities))
	for _, v := range parsed.Vulnerabilities {
		set[v.CveID] = true
	}

	kevMu.Lock()
	kevSet, kevFetchedAt = set, time.Now()
	kevMu.Unlock()

	return set, nil
}

// epssResponse mirrors FIRST.org's EPSS API response shape -- see
// https://www.first.org/epss/api. Score/percentile arrive as decimal
// strings, not numbers.
type epssResponse struct {
	Data []struct {
		CVE  string `json:"cve"`
		EPSS string `json:"epss"`
	} `json:"data"`
}

// maxEPSSBatch caps how many CVE IDs one EPSS request asks for -- one
// fingerprinted technology rarely surfaces more than a handful of CVEs, so
// this is a safety bound on the query string length rather than something
// real callers hit.
const maxEPSSBatch = 100

// fetchEPSS returns exploit-probability scores (0-1) for the given CVE IDs
// in one batched request (EPSS's API accepts a comma-separated cve= list).
// A CVE with no EPSS score yet is simply absent from the returned map.
func fetchEPSS(ctx context.Context, ids []string) (map[string]float64, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	if len(ids) > maxEPSSBatch {
		ids = ids[:maxEPSSBatch]
	}

	q := url.Values{}
	q.Set("cve", strings.Join(ids, ","))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, epssAPIURL+"?"+q.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("cve: build EPSS request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cve: fetch EPSS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cve: EPSS: unexpected status %d", resp.StatusCode)
	}

	var parsed epssResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("cve: decode EPSS: %w", err)
	}

	out := make(map[string]float64, len(parsed.Data))
	for _, d := range parsed.Data {
		if f, err := strconv.ParseFloat(d.EPSS, 64); err == nil {
			out[d.CVE] = f
		}
	}
	return out, nil
}

// EnrichExploitSignals fills in KEV/EPSS on every entry of cves in place.
// Best-effort: a failed KEV or EPSS fetch (network error, rate limit,
// CISA/FIRST.org downtime) just leaves those CVEs' KEV/EPSS at their zero
// value rather than failing the whole lookup -- same posture as Lookup's
// own caller in api.cvesFor, where a CVE lookup failing yields no CVEs
// rather than erroring the check.
func EnrichExploitSignals(ctx context.Context, cves []CVE) {
	if len(cves) == 0 {
		return
	}

	if kev, err := fetchKEV(ctx); err == nil {
		for i := range cves {
			cves[i].KEV = kev[cves[i].ID]
		}
	}

	ids := make([]string, len(cves))
	for i, c := range cves {
		ids[i] = c.ID
	}
	if epss, err := fetchEPSS(ctx, ids); err == nil {
		for i := range cves {
			cves[i].EPSS = epss[cves[i].ID]
		}
	}
}
