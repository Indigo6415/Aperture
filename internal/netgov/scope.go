package netgov

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// ErrOutOfScope is returned for any request whose host falls outside the
// scope its context carries. It is a refusal, not a block: nothing was sent.
var ErrOutOfScope = errors.New("netgov: host is outside this case's scope")

// Scope is an allowlist of hosts a scan may touch. It is checked in RoundTrip
// before any request leaves, so it covers every scanner and every redirect hop
// that goes through netgov. A nil *Scope allows everything, which is what a
// case with no scope rules gets.
//
// Pattern forms accepted by NewScope:
//   - "example.com"    the host itself and every subdomain of it
//   - "*.example.com"  subdomains only, not example.com itself
//   - "10.0.0.5"       one IP address
//   - "10.0.0.0/24"    a CIDR range
type Scope struct {
	exact    map[string]bool
	suffixes []string // ".example.com" matches a.example.com and example.com
	subsOnly []string // ".example.com" from "*.example.com": subdomains only
	prefixes []netip.Prefix
}

// NewScope parses patterns into a Scope. An empty list returns nil, meaning
// unrestricted. Patterns are case-insensitive, and a trailing dot is ignored.
func NewScope(patterns []string) (*Scope, error) {
	if len(patterns) == 0 {
		return nil, nil
	}
	s := &Scope{exact: map[string]bool{}}
	for _, raw := range patterns {
		p := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(raw), ".")))
		if p == "" {
			continue
		}
		// CIDR first, since its "/" would otherwise fall through to hostname handling.
		if strings.Contains(p, "/") {
			pfx, err := netip.ParsePrefix(p)
			if err != nil {
				return nil, fmt.Errorf("scope: invalid range %q: %w", raw, err)
			}
			s.prefixes = append(s.prefixes, pfx.Masked())
			continue
		}
		if ip, err := netip.ParseAddr(p); err == nil {
			s.exact[ip.String()] = true
			continue
		}
		if strings.HasPrefix(p, "*.") {
			base := p[2:]
			if !validHostname(base) {
				return nil, fmt.Errorf("scope: invalid wildcard %q", raw)
			}
			s.subsOnly = append(s.subsOnly, "."+base)
			continue
		}
		if !validHostname(p) {
			return nil, fmt.Errorf("scope: invalid host %q", raw)
		}
		s.suffixes = append(s.suffixes, "."+p)
		s.exact[p] = true
	}
	if len(s.exact) == 0 && len(s.suffixes) == 0 && len(s.subsOnly) == 0 && len(s.prefixes) == 0 {
		return nil, nil
	}
	return s, nil
}

// validHostname reports whether p looks like a DNS name: non-empty labels of
// letters, digits, and hyphens, with at least one dot. Single-label names are
// rejected because they make an easy mistake ("localhost" is fine as an exact
// host, but it can't be expressed as a suffix rule).
func validHostname(p string) bool {
	if p == "" || len(p) > 253 || !strings.Contains(p, ".") {
		return p == "localhost"
	}
	for _, label := range strings.Split(p, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Allows reports whether host (with or without a port, and IPv6 in brackets)
// is inside the scope. A nil Scope allows everything.
func (s *Scope) Allows(host string) bool {
	if s == nil {
		return true
	}
	h := hostOnly(host)
	if h == "" {
		return false
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		if s.exact[ip.String()] {
			return true
		}
		for _, pfx := range s.prefixes {
			if pfx.Contains(ip) {
				return true
			}
		}
		return false
	}
	if s.exact[h] {
		return true
	}
	for _, suf := range s.subsOnly {
		if strings.HasSuffix(h, suf) {
			return true
		}
	}
	for _, suf := range s.suffixes {
		if strings.HasSuffix(h, suf) {
			return true
		}
	}
	return false
}

// hostOnly strips a port and any IPv6 brackets from a host, lowercases it, and
// drops a trailing dot, so the rule and request forms compare equal.
func hostOnly(host string) string {
	h := host
	if strings.Contains(host, ":") {
		if hp, _, err := net.SplitHostPort(host); err == nil {
			h = hp
		}
	}
	h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
	return strings.ToLower(strings.TrimSuffix(h, "."))
}
