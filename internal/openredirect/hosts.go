package openredirect

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// idnaDots are the ideographic and fullwidth full stops that IDNA maps to an
// ASCII "." when a browser resolves a host. "evil。example" is the same host as
// "evil.example", so a filter that looks only for the ASCII dot misses it.
var idnaDots = strings.NewReplacer("。", ".", "．", ".", "｡", ".")

// splitAuthority splits a "host[:port]" string into its host and port. An
// IPv6 literal may be bracketed, with or without a port. The port is "" when
// none is given.
func splitAuthority(s string) (host, port string) {
	if h, p, err := net.SplitHostPort(s); err == nil {
		return h, p
	}
	// No port (or a bare IPv6 literal, which SplitHostPort rejects): drop the
	// brackets, if any, and keep the rest as the host.
	return strings.TrimSuffix(strings.TrimPrefix(s, "["), "]"), ""
}

// canonicalHost reduces a host to the form a browser's URL parser would
// resolve it to, so two spellings of one address compare equal. Fullwidth
// dots become ASCII dots, an IPv4-mapped IPv6 address becomes its IPv4 form,
// and any inet_aton spelling of an IPv4 address (decimal, hex, octal, or
// shortened to fewer than four parts) becomes dotted-quad. Everything else is
// lowercased and returned as is.
func canonicalHost(host string) string {
	host = strings.ToLower(idnaDots.Replace(host))
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ip.String()
	}
	if ip := inetAton(host); ip != nil {
		return ip.String()
	}
	return host
}

// inetAton parses host the way the C library's inet_aton does, accepting
// 1 to 4 dot-separated parts, each in decimal, octal (leading 0), or hex
// (leading 0x). The last part fills whatever bytes the earlier parts leave.
// It returns nil when host is not such a spelling, e.g. a real domain name.
func inetAton(host string) net.IP {
	parts := strings.Split(host, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return nil
	}
	vals := make([]uint64, len(parts))
	// Each part is parsed in its own notation, so one spelling can mix with another.
	for i, p := range parts {
		v, ok := parseInetPart(p)
		if !ok {
			return nil
		}
		vals[i] = v
	}
	var n uint64
	// Every part but the last is a single byte, most significant first.
	for i, v := range vals[:len(vals)-1] {
		if v > 255 {
			return nil
		}
		n |= v << (8 * (3 - i))
	}
	// The last part covers the remaining bytes, so it may be wider than one.
	last := vals[len(vals)-1]
	if last >= 1<<(8*(4-(len(vals)-1))) {
		return nil
	}
	n |= last
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// parseInetPart reads one inet_aton component in its decimal, octal, or hex
// spelling. It reports false for anything else, including an empty part.
func parseInetPart(p string) (uint64, bool) {
	// The 0x prefix means hex, a bare leading 0 means octal, anything else is decimal.
	switch {
	case p == "":
		return 0, false
	case strings.HasPrefix(p, "0x") || strings.HasPrefix(p, "0X"):
		v, err := strconv.ParseUint(p[2:], 16, 64)
		return v, err == nil
	case len(p) > 1 && p[0] == '0':
		v, err := strconv.ParseUint(p[1:], 8, 64)
		return v, err == nil
	default:
		v, err := strconv.ParseUint(p, 10, 64)
		return v, err == nil
	}
}

// defaultPort returns port, or the scheme's default port when port is empty,
// so "https://host" and "https://host:443" compare equal.
func defaultPort(port, scheme string) string {
	if port != "" {
		return port
	}
	switch scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}

// sameCallbackHost reports whether loc, a redirect's Location, points at the
// callback authority cbHost ("host[:port]"). Host spellings are compared after
// canonicalHost, and ports after defaultPort, so an IP-literal or Unicode-dot
// form of the callback still matches.
func sameCallbackHost(loc *url.URL, cbHost string) bool {
	cbH, cbP := splitAuthority(cbHost)
	lH, lP := splitAuthority(loc.Host)
	if canonicalHost(lH) != canonicalHost(cbH) {
		return false
	}
	return defaultPort(lP, loc.Scheme) == defaultPort(cbP, loc.Scheme)
}

// ipForm is one spelling of an IP address: kind names the notation (for the
// identifier label and the finding), host is the spelling itself with its port.
type ipForm struct{ kind, host string }

// ipLiteralForms returns the IP-literal spellings of cbHost's address, for an
// IPv4 callback, in the forms Oralyzer's payload list tries against an
// allowlist or blocklist that matches the dotted-quad only. It returns nil when
// the callback is a domain, since a domain has no address to spell out here.
// Each form keeps cbHost's port.
func ipLiteralForms(cbHost string) []ipForm {
	h, port := splitAuthority(cbHost)
	v4 := net.ParseIP(h).To4()
	if v4 == nil {
		return nil
	}
	a, b, c, d := v4[0], v4[1], v4[2], v4[3]
	dword := uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d)

	// withPort appends the callback's own port, bracketing the IPv6 form first.
	withPort := func(s string, bracket bool) string {
		if bracket {
			s = "[" + s + "]"
		}
		if port != "" {
			return s + ":" + port
		}
		return s
	}
	return []ipForm{
		{"decimal", withPort(strconv.FormatUint(uint64(dword), 10), false)},
		{"hex", withPort(fmt.Sprintf("0x%08x", dword), false)},
		{"octal", withPort(fmt.Sprintf("0%o.0%o.0%o.0%o", a, b, c, d), false)},
		{"mixed", withPort(fmt.Sprintf("0x%x.0x%x.%d.%d", a, b, c, d), false)},
		{"ipv6-mapped", withPort(fmt.Sprintf("::ffff:%d.%d.%d.%d", a, b, c, d), true)},
	}
}

// poisonAt is d.poison with the callback's host replaced by host, keeping the
// callback's path and then the identifier. It builds the address for an
// alternative spelling of the callback host.
func (d runDeps) poisonAt(host, identifier string) string {
	_, rest, _ := strings.Cut(d.req.CallbackBase, "/")
	return host + "/" + rest + "/" + identifier
}

// fullwidthHost rewrites the host part of poison (the "host/path..." string
// from d.poison) to use an ideographic full stop in place of each ASCII dot.
// The path is left alone, since the identifier must still match exactly.
func fullwidthHost(poison string) string {
	host, rest, hasRest := strings.Cut(poison, "/")
	host = strings.ReplaceAll(host, ".", "。")
	if !hasRest {
		return host
	}
	return host + "/" + rest
}
