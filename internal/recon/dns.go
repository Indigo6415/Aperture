package recon

import (
	"context"
	"net"
	"sort"
)

// checkDNS resolves A/AAAA/CNAME/NS/MX/TXT records for domain. Records are
// looked up independently and a missing record type (e.g. no MX) is not an
// error -- checkDNS only fails if every lookup fails, which usually means
// the domain doesn't resolve at all.
//
// Data shape: {"a": []string, "aaaa": []string, "cname": string,
// "ns": []string, "mx": []string, "txt": []string}
func checkDNS(ctx context.Context, domain string) (map[string]any, error) {
	resolver := net.DefaultResolver

	var a, aaaa []string
	if ips, err := resolver.LookupIPAddr(ctx, domain); err == nil {
		for _, ip := range ips {
			// IPv4 addresses have a non-nil 4-byte form; IPv6-only addresses don't.
			if ip.IP.To4() != nil {
				a = append(a, ip.IP.String())
			} else {
				aaaa = append(aaaa, ip.IP.String())
			}
		}
	}

	var cname string
	if cn, err := resolver.LookupCNAME(ctx, domain); err == nil {
		cname = cn
	}

	var ns []string
	if records, err := resolver.LookupNS(ctx, domain); err == nil {
		for _, r := range records {
			ns = append(ns, r.Host)
		}
	}

	var mx []string
	if records, err := resolver.LookupMX(ctx, domain); err == nil {
		for _, r := range records {
			mx = append(mx, r.Host)
		}
	}

	var txt []string
	if records, err := resolver.LookupTXT(ctx, domain); err == nil {
		txt = records
	}

	if len(a) == 0 && len(aaaa) == 0 && cname == "" && len(ns) == 0 && len(mx) == 0 && len(txt) == 0 {
		// Every independent lookup came back empty/failed -- treat that as
		// one clear error instead of five silently-empty fields.
		return nil, &net.DNSError{Err: "no records found", Name: domain, IsNotFound: true}
	}

	sort.Strings(a)
	sort.Strings(aaaa)
	return map[string]any{
		"a":     a,
		"aaaa":  aaaa,
		"cname": cname,
		"ns":    ns,
		"mx":    mx,
		"txt":   txt,
	}, nil
}
