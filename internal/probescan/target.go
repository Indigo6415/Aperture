// Package probescan is a Go port of the standalone `probe` misconfiguration
// scanner (originally a Python CLI): point it at a URL, hostname, or IP and
// it runs a suite of read/write-nothing-destructive HTTP checks for common
// web server misconfigurations -- exposed .git/.svn, sensitive files, open
// admin panels, dev artifacts, API endpoints, WordPress/Flask/Django issues,
// TLS problems, and injection points. Every check is a GET/POST against a
// path the target either does or doesn't expose; nothing here writes to the
// target.
package probescan

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Target is the disassembled form of whatever the caller typed in --
// "example.com", "10.10.10.10", "https://example.com:8443", etc. Ported
// from probe's dependencies/target.py.
type Target struct {
	Raw      string `json:"raw"`
	URL      string `json:"url"`
	Hostname string `json:"hostname"`
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port"`
}

// ResolveTarget parses raw into a Target, resolving its hostname to an IP
// where possible. Mirrors Target.disassemble()'s normalization: a scheme is
// added if missing so url.Parse behaves predictably, and the rebuilt URL
// only carries an explicit port when the caller gave one (or gave no scheme
// at all, in which case the inferred default port is made explicit too).
// A bare hostname/IP with no scheme (e.g. "target.htb", "10.10.10.10")
// defaults to https, not http -- almost every real target speaks TLS today,
// and probing plaintext by default against one that doesn't (or redirects)
// just wastes every module's request on a 30x/reset instead of the real page.
func ResolveTarget(raw string) *Target {
	t := &Target{Raw: raw, Port: 443}

	hadScheme := strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://")
	s := raw
	if !hadScheme {
		s = "https://" + s
	}
	s = strings.TrimRight(s, "/")

	u, err := url.Parse(s)
	if err != nil || u.Hostname() == "" {
		// Not parseable as a URL at all -- treat the raw input as a bare
		// hostname so the scan still has something to probe.
		t.Hostname = raw
		t.URL = "https://" + raw
		resolveIP(t)
		return t
	}

	t.Hostname = u.Hostname()
	explicitPort := u.Port() != ""
	if explicitPort {
		p, _ := strconv.Atoi(u.Port())
		t.Port = p
	} else if u.Scheme == "https" {
		t.Port = 443
	} else {
		t.Port = 80
	}

	if explicitPort || !hadScheme {
		t.URL = fmt.Sprintf("%s://%s:%d", u.Scheme, t.Hostname, t.Port)
	} else {
		t.URL = fmt.Sprintf("%s://%s", u.Scheme, t.Hostname)
	}

	resolveIP(t)
	return t
}

func resolveIP(t *Target) {
	if t.Hostname == "" {
		return
	}
	if ip := net.ParseIP(t.Hostname); ip != nil {
		t.IP = t.Hostname
		return
	}
	if ips, err := net.LookupHost(t.Hostname); err == nil && len(ips) > 0 {
		t.IP = ips[0]
	}
}
