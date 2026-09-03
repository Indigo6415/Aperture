package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// rdapResponse mirrors the common subset of RFC 9083's RDAP domain
// response shape. Real-world registries vary in which optional fields they
// populate, so every field here is read defensively in checkWHOIS.
type rdapResponse struct {
	LDHName  string   `json:"ldhName"`
	Status   []string `json:"status"`
	Entities []struct {
		Roles      []string `json:"roles"`
		VCardArray []any    `json:"vcardArray"`
	} `json:"entities"`
	Events []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
}

// checkWHOIS looks up domain registration data via the RDAP protocol
// (RFC 9083), the modern structured-JSON successor to WHOIS. rdap.org runs
// IANA's public bootstrap redirector, which forwards the request to
// whichever registry actually holds the record -- one HTTP call covers any
// TLD without Aperture needing its own bootstrap-registry list.
//
// Data shape: {"registrar": string, "status": []string, "createdAt":
// string, "expiresAt": string, "nameServers": []string, "raw": json.RawMessage}
func checkWHOIS(ctx context.Context, domain string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://rdap.org/domain/"+domain, nil)
	if err != nil {
		return nil, fmt.Errorf("whois: build request: %w", err)
	}
	req.Header.Set("Accept", "application/rdap+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("whois: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("whois: no RDAP record found for %s", domain)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("whois: unexpected status %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("whois: read response: %w", err)
	}
	var parsed rdapResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("whois: decode: %w", err)
	}

	registrar := ""
	for _, e := range parsed.Entities {
		// A registrar entity's vCard array conventionally carries its name
		// as vcardArray[1][i] == ["fn", {}, "text", "<name>"]; walk it
		// defensively since RDAP's vCard-in-JSON shape is loosely typed.
		if !contains(e.Roles, "registrar") {
			continue
		}
		if name := vcardFN(e.VCardArray); name != "" {
			registrar = name
			break
		}
	}

	var created, expires string
	for _, ev := range parsed.Events {
		switch ev.Action {
		case "registration":
			created = ev.Date
		case "expiration":
			expires = ev.Date
		}
	}

	var nameServers []string
	for _, ns := range parsed.Nameservers {
		nameServers = append(nameServers, ns.LDHName)
	}

	return map[string]any{
		"registrar":   registrar,
		"status":      parsed.Status,
		"createdAt":   created,
		"expiresAt":   expires,
		"nameServers": nameServers,
		"raw":         json.RawMessage(raw),
	}, nil
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// vcardFN pulls the "fn" (formatted name) property out of an RDAP vCard
// array, whose shape per RFC 9083 is ["vcard", [["fn", {}, "text", "name"], ...]].
func vcardFN(vcard []any) string {
	if len(vcard) < 2 {
		return ""
	}
	props, ok := vcard[1].([]any)
	if !ok {
		return ""
	}
	for _, p := range props {
		field, ok := p.([]any)
		if !ok || len(field) < 4 {
			continue
		}
		name, _ := field[0].(string)
		if name != "fn" {
			continue
		}
		if v, ok := field[3].(string); ok {
			return v
		}
	}
	return ""
}
