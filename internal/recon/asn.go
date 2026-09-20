package recon

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// checkASN resolves ip's hosting network -- ASN, owning organization,
// announced prefix, and country -- via Team Cymru's DNS-based IP-to-ASN
// service (https://team-cymru.com/community-services/ip-asn-mapping/#dns):
// two plain TXT lookups, no API key, matching the rest of this package's
// passive/stdlib-only posture. IPv4 only -- Team Cymru's IPv6 origin
// lookup lives under a different zone this package doesn't query.
//
// Data shape: {"ip": string, "asn": string, "org": string,
// "country": string, "prefix": string}
func checkASN(ctx context.Context, ip string) (map[string]any, error) {
	reversed, err := reverseIPv4(ip)
	if err != nil {
		return nil, err
	}

	resolver := net.DefaultResolver
	originRecords, err := resolver.LookupTXT(ctx, reversed+".origin.asn.cymru.com")
	if err != nil || len(originRecords) == 0 {
		return nil, fmt.Errorf("recon: no ASN record for %s", ip)
	}
	// Record shape: "ASN | prefix | CC | registry | allocated date"
	fields := splitPipeFields(originRecords[0])
	if len(fields) < 3 {
		return nil, fmt.Errorf("recon: unexpected ASN record shape for %s", ip)
	}
	asn, prefix, country := fields[0], fields[1], fields[2]

	org := ""
	if asnRecords, err := resolver.LookupTXT(ctx, "AS"+asn+".asn.cymru.com"); err == nil && len(asnRecords) > 0 {
		// Record shape: "ASN | CC | registry | allocated date | AS Name"
		if asnFields := splitPipeFields(asnRecords[0]); len(asnFields) >= 5 {
			org = asnFields[4]
		}
	}

	return map[string]any{
		"ip": ip, "asn": "AS" + asn, "org": org, "country": country, "prefix": prefix,
	}, nil
}

// reverseIPv4 octet-reverses an IPv4 address for a Team Cymru-style DNS
// lookup ("1.2.3.4" -> "4.3.2.1"); errors on anything else (IPv6, garbage).
func reverseIPv4(ip string) (string, error) {
	parsed := net.ParseIP(ip)
	v4 := parsed.To4()
	if v4 == nil {
		return "", fmt.Errorf("recon: %q is not an IPv4 address", ip)
	}
	return fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0]), nil
}

// splitPipeFields splits one Team Cymru "a | b | c" TXT record into its
// trimmed fields.
func splitPipeFields(record string) []string {
	parts := strings.Split(record, "|")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return parts
}

// firstIPv4 returns the first IPv4 address from a completed checkDNS
// result's "a" field, or "" if there isn't one -- checkASN has nothing to
// look up for an IPv6-only or unresolved host.
func firstIPv4(dnsData map[string]any) string {
	a, _ := dnsData["a"].([]string)
	if len(a) == 0 {
		return ""
	}
	return a[0]
}
