// Package cve looks up known CVEs for a fingerprinted product+version
// against the NVD (National Vulnerability Database) REST API. Results are
// meant to be cached by the caller (see store.GetCVECache/SetCVECache) --
// this package only ever talks to the network.
package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"time"
)

// CVE is the subset of one NVD record Aperture surfaces.
type CVE struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"` // CRITICAL/HIGH/MEDIUM/LOW/unknown, uppercase to match NVD's own vocabulary
	Score       float64   `json:"score"`
	Published   time.Time `json:"published"`
	References  []string  `json:"references"`
	// MatchType says how this CVE was found: MatchRange (NVD checked the exact
	// version against the affected range) or MatchKeyword (free-text search).
	MatchType string `json:"matchType,omitempty"`
	// KEV/EPSS are exploit-likelihood signals layered on top of NVD's own
	// CVSS severity -- filled in by EnrichExploitSignals, not by Lookup
	// itself (NVD's API knows nothing about either). KEV is true when this
	// CVE is in CISA's Known Exploited Vulnerabilities catalog: confirmed
	// active exploitation, not a theoretical score. EPSS is FIRST.org's
	// predicted probability (0-1) of exploitation in the next 30 days, left
	// at zero when no EPSS score exists for this CVE yet (too new, or
	// withdrawn) -- indistinguishable from a genuinely near-zero score, but
	// EPSS itself treats those the same way (nothing to prioritize either).
	KEV  bool    `json:"kev,omitempty"`
	EPSS float64 `json:"epss,omitempty"`
}

// nvdEndpoint is a variable so tests can point the lookup at a fixture server.
var nvdEndpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"

const (
	// resultsPerLookup caps how many CVEs one product+version lookup keeps
	// -- NVD's keyword search can return far more than are useful to show
	// per detected technology.
	resultsPerLookup = 20
	// maxReferences caps how many reference links are kept per CVE, purely
	// so the cached JSON blob (and the UI rendering it) stays small.
	maxReferences = 3
)

// nvdResponse mirrors the subset of NVD's 2.0 API response shape this
// package cares about -- see https://nvd.nist.gov/developers/vulnerabilities.
type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
			Metrics struct {
				CVSSMetricV31 []nvdCVSSMetric `json:"cvssMetricV31"`
				CVSSMetricV30 []nvdCVSSMetric `json:"cvssMetricV30"`
				CVSSMetricV2  []nvdCVSSMetric `json:"cvssMetricV2"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVSSMetric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"` // CVSS v2 carries severity alongside, not inside, cvssData
}

// Lookup finds CVEs for a product at a version. When the product has a known
// CPE (see vendorProduct), NVD matches the version against each CVE's affected
// range, which is exact. Otherwise it falls back to a free-text keyword search,
// and every result is labeled with how it was found. apiKey is optional (raises
// NVD's rate limit, see rateLimiter). An empty version returns nothing without a
// request, since a versionless lookup cannot be scoped.
func Lookup(ctx context.Context, product, version, apiKey string) ([]CVE, error) {
	if version == "" {
		return nil, nil
	}

	if err := limiterFor(apiKey != "").wait(ctx); err != nil {
		return nil, err
	}

	q := url.Values{}
	matchType := MatchKeyword
	if cpe, ok := cpeMatchString(product, version); ok {
		q.Set("virtualMatchString", cpe)
		matchType = MatchRange
	} else {
		q.Set("keywordSearch", product+" "+version)
	}
	q.Set("resultsPerPage", fmt.Sprintf("%d", resultsPerLookup))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, nvdEndpoint+"?"+q.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("cve: build request: %w", err)
	}
	if apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cve: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("cve: NVD API key rejected (status %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cve: unexpected status %d", resp.StatusCode)
	}

	var parsed nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("cve: decode: %w", err)
	}

	out := make([]CVE, 0, len(parsed.Vulnerabilities))
	for _, v := range parsed.Vulnerabilities {
		c := CVE{ID: v.CVE.ID, MatchType: matchType}
		for _, d := range v.CVE.Descriptions {
			if d.Lang == "en" {
				c.Description = d.Value
				break
			}
		}
		if t, err := time.Parse("2006-01-02T15:04:05.000", v.CVE.Published); err == nil {
			c.Published = t
		}
		for i, r := range v.CVE.References {
			if i >= maxReferences {
				break
			}
			c.References = append(c.References, r.URL)
		}
		c.Score, c.Severity = bestCVSS(v.CVE.Metrics.CVSSMetricV31, v.CVE.Metrics.CVSSMetricV30, v.CVE.Metrics.CVSSMetricV2)
		out = append(out, c)
	}

	// Highest severity first, so the UI's top CVE badges are the ones that
	// matter most without the frontend needing its own severity ordering.
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out, nil
}

// bestCVSS picks the first non-empty metric list (v3.1, then v3.0, then
// v2), preferring the newer scoring scheme when NVD provides more than one.
func bestCVSS(sets ...[]nvdCVSSMetric) (score float64, severity string) {
	for _, set := range sets {
		if len(set) == 0 {
			continue
		}
		m := set[0]
		severity = m.CVSSData.BaseSeverity
		if severity == "" {
			severity = m.BaseSeverity
		}
		if severity == "" {
			severity = "unknown"
		}
		return m.CVSSData.BaseScore, severity
	}
	return 0, "unknown"
}
