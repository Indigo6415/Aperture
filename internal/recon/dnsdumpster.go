package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// KindDNSDumpster identifies a DNSDumpster API lookup (see CheckDNSDumpster).
// Unlike every other CheckKind, it needs a caller-supplied API key, so it's
// not one of the five checks Scan fans out on its own -- the api package
// runs it alongside Scan, using whatever key it has on hand (see
// store.GetSetting).
const KindDNSDumpster CheckKind = "dnsdumpster"

// dnsdumpsterHostRecord mirrors one entry of api.dnsdumpster.com's "a"/"ns"/
// "mx"/"cname" arrays: a hostname plus whichever IPs (with light ASN/geo
// enrichment) it resolved to at scan time.
type dnsdumpsterHostRecord struct {
	Host string `json:"host"`
	IPs  []struct {
		IP         string `json:"ip"`
		ASN        string `json:"asn"`
		ASNName    string `json:"asn_name"`
		Country    string `json:"country"`
		CountryISO string `json:"country_code"`
	} `json:"ips"`
}

// dnsdumpsterResponse mirrors the subset of api.dnsdumpster.com's domain
// lookup response Aperture surfaces -- see
// https://docs.dnsdumpster.com for the full schema.
type dnsdumpsterResponse struct {
	Domain     string                  `json:"domain"`
	A          []dnsdumpsterHostRecord `json:"a"`
	NS         []dnsdumpsterHostRecord `json:"ns"`
	MX         []dnsdumpsterHostRecord `json:"mx"`
	TXT        []string                `json:"txt"`
	CNAME      []dnsdumpsterHostRecord `json:"cname"`
	TotalARecs int                     `json:"total_a_recs"`
}

// CheckDNSDumpster queries DNSDumpster's paid API
// (https://api.dnsdumpster.com) for domain's DNS footprint -- A/NS/MX/TXT/
// CNAME records plus per-IP ASN and geolocation, which is more than the
// bare records checkDNS's stdlib resolver can get. It's exported (unlike
// the check* functions Scan drives internally) because apiKey is only ever
// known to the caller: it comes from a per-installation setting stored in
// SQLite (see store.GetSetting), not anything recon itself has access to.
// A blank apiKey isn't validated here -- the caller is expected to skip
// calling this at all when no key is configured, same as it would for any
// other optional integration.
//
// Data shape: {"domain": string, "totalARecords": int,
// "a": []{"host": string, "ips": []{"ip", "asn", "asnName", "country",
// "countryCode"}}, "ns": [...same shape...], "mx": [...same shape...],
// "cname": [...same shape...], "txt": []string, "subdomains": []string}
//
// subdomains is Aperture's own addition: every distinct hostname named
// across a/ns/mx/cname, deduped and sorted, for the UI to show as a quick
// list without re-deriving it from the nested arrays itself.
func CheckDNSDumpster(ctx context.Context, domain, apiKey string) Check {
	return runCheck(ctx, domain, KindDNSDumpster, apexTimeout, func(c context.Context) (map[string]any, error) {
		return queryDNSDumpster(c, domain, apiKey)
	})
}

func queryDNSDumpster(ctx context.Context, domain, apiKey string) (map[string]any, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("dnsdumpster: no API key configured")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.dnsdumpster.com/domain/"+domain, nil)
	if err != nil {
		return nil, fmt.Errorf("dnsdumpster: build request: %w", err)
	}
	req.Header.Set("X-API-Key", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dnsdumpster: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("dnsdumpster: API key rejected (status %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dnsdumpster: unexpected status %d", resp.StatusCode)
	}

	var parsed dnsdumpsterResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("dnsdumpster: decode: %w", err)
	}

	toMaps := func(records []dnsdumpsterHostRecord) []map[string]any {
		out := make([]map[string]any, 0, len(records))
		for _, r := range records {
			ips := make([]map[string]any, 0, len(r.IPs))
			for _, ip := range r.IPs {
				ips = append(ips, map[string]any{
					"ip": ip.IP, "asn": ip.ASN, "asnName": ip.ASNName,
					"country": ip.Country, "countryCode": ip.CountryISO,
				})
			}
			out = append(out, map[string]any{"host": r.Host, "ips": ips})
		}
		return out
	}

	seen := map[string]bool{}
	var subdomains []string
	for _, records := range [][]dnsdumpsterHostRecord{parsed.A, parsed.NS, parsed.MX, parsed.CNAME} {
		for _, r := range records {
			name := strings.ToLower(strings.TrimSuffix(r.Host, "."))
			if name == "" || name == domain || seen[name] {
				continue
			}
			seen[name] = true
			subdomains = append(subdomains, name)
		}
	}
	sort.Strings(subdomains)

	return map[string]any{
		"domain":        parsed.Domain,
		"totalARecords": parsed.TotalARecs,
		"a":             toMaps(parsed.A),
		"ns":            toMaps(parsed.NS),
		"mx":            toMaps(parsed.MX),
		"cname":         toMaps(parsed.CNAME),
		"txt":           parsed.TXT,
		"subdomains":    subdomains,
	}, nil
}
