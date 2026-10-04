package bypass403

import (
	"context"
	"encoding/json"
	"github.com/Indigo6415/Aperture/internal/netgov"
	"net/http"
	"net/url"
	"time"
)

// categoryArchive is its own category, separate from the four live-request
// ones in attempts.go -- checkWaybackMachine never touches the target at
// all, so it doesn't belong grouped alongside techniques that do.
const categoryArchive category = "archive"

// waybackTimeout is generous relative to requestTimeout -- archive.org's
// availability API is occasionally slow, and this check runs once per
// target (not once per technique), so it doesn't meaningfully add to a
// run's total time budget.
const waybackTimeout = 10 * time.Second

// waybackEndpoint is the Wayback Machine availability API. A variable rather
// than a constant so tests can point the check at a local server.
var waybackEndpoint = "https://archive.org/wayback/available"

// waybackResponse mirrors the subset of archive.org's Wayback Availability
// API response this package cares about -- see
// https://archive.org/help/wayback_api.php.
type waybackResponse struct {
	ArchivedSnapshots struct {
		Closest struct {
			Available bool   `json:"available"`
			URL       string `json:"url"`
			Timestamp string `json:"timestamp"`
			Status    string `json:"status"`
		} `json:"closest"`
	} `json:"archived_snapshots"`
}

// checkWaybackMachine asks archive.org whether it has ever crawled rawURL
// successfully -- a resource blocked today may simply never have had that
// protection when a crawler last saw it, in which case the historical copy
// is still sitting in the Wayback Machine regardless of what the live server
// does now. This never touches the target itself, so it always runs
// alongside the live techniques rather than only when the baseline looks
// blocked in a way those specifically address.
//
// A snapshot only counts as a bypass when the crawler got HTTP 200 for it. A
// snapshot taken while the page was itself a 403, 404 or redirect to login
// says nothing about the resource being open.
//
// Returns nil on any failure to reach archive.org -- this is a best-effort
// extra, not a core technique, so a third party being unreachable shouldn't
// clutter the result with a row that says nothing about the actual target.
func checkWaybackMachine(ctx context.Context, rawURL string) *Attempt {
	ctx, cancel := context.WithTimeout(ctx, waybackTimeout)
	defer cancel()

	endpoint := waybackEndpoint + "?url=" + url.QueryEscape(rawURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Aperture-403Bypass")

	// Goes through the shared governor like every other outbound request in
	// this package, rather than a bare default client.
	resp, err := netgov.NewClient(waybackTimeout, true).Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var wb waybackResponse
	if err := json.NewDecoder(resp.Body).Decode(&wb); err != nil {
		return nil
	}

	snapshot := wb.ArchivedSnapshots.Closest
	if !snapshot.Available || snapshot.URL == "" {
		return &Attempt{
			ID: "archive-wayback", Category: string(categoryArchive),
			Description: "No Wayback Machine snapshot was found for this URL",
			Target:      rawURL,
		}
	}

	when := snapshot.Timestamp
	if len(when) >= 8 {
		when = when[:4] + "-" + when[4:6] + "-" + when[6:8]
	}
	// Only a snapshot captured as HTTP 200 shows the resource itself opened
	// to a crawler; anything else is reported but not counted as a bypass.
	if snapshot.Status != "200" {
		return &Attempt{
			ID: "archive-wayback", Category: string(categoryArchive),
			Description: "The Wayback Machine has a snapshot from " + when + " but it was captured as HTTP " + snapshot.Status + ", not 200, so it is not counted as a bypass",
			Target:      snapshot.URL,
		}
	}
	return &Attempt{
		ID: "archive-wayback", Category: string(categoryArchive),
		Description: "The Wayback Machine has a snapshot from " + when + " captured as HTTP 200 -- it may still show the page without the current access control",
		Target:      snapshot.URL,
		Bypassed:    true,
	}
}
