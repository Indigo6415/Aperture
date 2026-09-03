package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// crtshEntry mirrors the subset of crt.sh's JSON output we care about. One
// certificate can cover several names, all newline-joined into name_value.
type crtshEntry struct {
	NameValue string `json:"name_value"`
}

// checkSubdomains queries crt.sh's certificate-transparency log search for
// every name any issued certificate has covered, and returns both the
// Check (for streaming to the UI) and the deduped, sorted subdomain list
// (for the caller to fan further checks out to) since -- unlike the other
// checks -- its result feeds back into Scan's control flow.
//
// Data shape: {"subdomains": []string, "count": int}
func checkSubdomains(ctx context.Context, domain string) (Check, []string) {
	start := time.Now()
	cctx, cancel := context.WithTimeout(ctx, apexTimeout)
	defer cancel()

	names, err := queryCrtSh(cctx, domain)
	c := Check{Domain: domain, Kind: KindSubdomains, StartedAt: start, FinishedAt: time.Now()}
	if err != nil {
		c.Status = StatusError
		c.Error = err.Error()
		return c, nil
	}
	c.Status = StatusDone
	c.Data = map[string]any{"subdomains": names, "count": len(names)}
	return c, names
}

func queryCrtSh(ctx context.Context, domain string) ([]string, error) {
	reqURL := "https://crt.sh/?q=" + url.QueryEscape("%."+domain) + "&output=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("crt.sh: build request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh: unexpected status %d", resp.StatusCode)
	}

	var entries []crtshEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("crt.sh: decode: %w", err)
	}

	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		// One certificate entry can list multiple names separated by
		// newlines (SAN certs), so split before deduping.
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.ToLower(strings.TrimSpace(name))
			name = strings.TrimPrefix(name, "*.")
			if name == "" || name == domain || seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}
