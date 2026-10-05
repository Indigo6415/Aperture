package openredirect

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/netgov"
)

// commonCrawlCollections is Common Crawl's list of crawl collections. Each
// entry names the CDX index that answers URL queries for that crawl.
const commonCrawlCollections = "https://index.commoncrawl.org/collinfo.json"

// commonCrawlMaxRows caps how many index rows one discovery reads. Common
// Crawl returns rows in its own order, so the cap bounds the work, not the
// quality of the result.
const commonCrawlMaxRows = 1000

// commonCrawlFetch GETs one Common Crawl URL and returns its body. It is a
// variable so the tests can serve canned index responses. The default sends
// no credentials: discovery queries a third party, so none of the operator's
// headers may leave with it.
var commonCrawlFetch = func(ctx context.Context, rawURL string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Aperture-OpenRedirect")
	resp, err := netgov.NewClient(20*time.Second, true).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("common crawl returned %s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// redirectDorks match URLs whose query or path names a destination
// parameter, the shapes Oralyzer's crawl filter looks for. Each is a regex
// over the whole URL, matched case-insensitively.
var redirectDorks = regexp.MustCompile(`(?i)` + strings.Join([]string{
	`.*\?next=.*`,
	`.*\?url=.*`,
	`.*\?target=.*`,
	`.*\?rurl=.*`,
	`.*\/dest=.*`,
	`.*\/destination=.*`,
	`.*\?redir=.*`,
	`.*\?redirect_uri=.*`,
	`.*\?return=.*`,
	`.*\?return_path.*`,
	`.*\/cgi-bin\/redirect\.cgi\?.*`,
	`.*\?checkout_url=.*`,
	`.*\?image_url=.*`,
	`.*\/out\?.*`,
	`.*\?continue=.*`,
	`.*\?view=.*`,
	`.*\/redirect\/.*`,
	`.*\?go=.*`,
	`.*\?redirect=.*`,
	`.*\?externallink=.*`,
	`.*\?nextURL=.*`,
}, "|"))

// fetchCommonCrawlURLs returns the URLs Common Crawl's latest index holds
// under host, at most commonCrawlMaxRows of them. Any failure returns nil,
// since discovery is best-effort: it adds endpoints when it works and nothing
// when it doesn't.
func fetchCommonCrawlURLs(ctx context.Context, host string) []string {
	// The collection list names the newest crawl's query endpoint.
	listing, err := commonCrawlFetch(ctx, commonCrawlCollections)
	if err != nil {
		return nil
	}
	var collections []struct {
		CDXAPI string `json:"cdx-api"`
	}
	if err := json.Unmarshal([]byte(listing), &collections); err != nil || len(collections) == 0 || collections[0].CDXAPI == "" {
		return nil
	}

	// Ask the index for every URL under host, successful responses only.
	query := fmt.Sprintf("%s?url=%s/*&output=json&filter=status:200&limit=%d", collections[0].CDXAPI, url.QueryEscape(host), commonCrawlMaxRows)
	body, err := commonCrawlFetch(ctx, query)
	if err != nil {
		return nil
	}

	var urls []string
	// The index answers with one JSON object per line. Each line is parsed on
	// its own, so one malformed row costs that row and no more.
	for _, line := range strings.Split(body, "\n") {
		if len(urls) >= commonCrawlMaxRows {
			break
		}
		var row struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil || row.URL == "" {
			continue
		}
		urls = append(urls, row.URL)
	}
	return urls
}

// discoverEndpoints returns up to maxDiscoveredEndpoints redirect-shaped URLs
// under target's own host, one per path, in the order Common Crawl gave them.
// The target's own path is left out, since the operator's scan already covers
// it. The URL keeps its historical query string, so the parameters that
// redirected in the past are the ones the scan tests.
func discoverEndpoints(ctx context.Context, target *url.URL) []string {
	var out []string
	seenPath := map[string]bool{target.Path: true}
	// Candidates keep the index's order, so the first matching path wins.
	for _, raw := range fetchCommonCrawlURLs(ctx, target.Host) {
		if len(out) >= maxDiscoveredEndpoints {
			break
		}
		if !redirectDorks.MatchString(raw) {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || !strings.EqualFold(u.Host, target.Host) || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		// One endpoint per path, so a route with many historical query strings
		// doesn't take up the whole budget.
		if seenPath[u.Path] {
			continue
		}
		seenPath[u.Path] = true
		out = append(out, raw)
	}
	return out
}
