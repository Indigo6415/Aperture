// Package robots applies robots.txt to the link-following crawlers. Only the
// discovery of new pages is governed: the page a scan was asked to test is
// always requested, and so is every payload request. A crawler that ignored
// robots.txt would walk into areas the site owner has asked search tools to
// leave alone, which is also the first thing a reviewer of an engagement asks
// about.
package robots

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Indigo6415/Aperture/internal/netgov"
)

// maxRobotsBytes caps how much of robots.txt is read. Real files are a few
// kilobytes; the cap keeps a hostile one from consuming memory.
const maxRobotsBytes = 512 << 10

// Policy holds the Disallow prefixes that apply to Aperture. A nil Policy
// allows everything, so callers never need to check for one.
type Policy struct {
	disallow []string
}

// Load fetches robots.txt from the origin of seed and parses it. As the
// standard specifies, a missing or unreadable file allows everything.
func Load(ctx context.Context, client *http.Client, seed *url.URL, headers map[string]string) *Policy {
	robotsURL := url.URL{Scheme: seed.Scheme, Host: seed.Host, Path: "/robots.txt"}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, robotsURL.String(), nil)
	if err != nil {
		return nil
	}
	netgov.ApplyHeaders(req, headers)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRobotsBytes))
	if err != nil {
		return nil
	}
	return Parse(string(body))
}

// Parse reads robots.txt content and keeps the Disallow rules of the groups
// that apply to Aperture: those addressed to "*" or to "Aperture". Allow rules
// are not used. Ignoring them can only over-restrict a crawl, never let it into
// an area the site disallowed, which is the safer direction.
func Parse(body string) *Policy {
	p := &Policy{}
	inGroup := false
	lastWasAgent := false
	for _, raw := range strings.Split(body, "\n") {
		line := raw
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		field, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		field = strings.ToLower(strings.TrimSpace(field))
		value = strings.TrimSpace(value)
		switch field {
		case "user-agent":
			// Consecutive user-agent lines share one group. A new group starts
			// after any rule line.
			if !lastWasAgent {
				inGroup = false
			}
			agent := strings.ToLower(value)
			if agent == "*" || agent == "aperture" {
				inGroup = true
			}
			lastWasAgent = true
			continue
		case "disallow":
			if inGroup && value != "" {
				p.disallow = append(p.disallow, value)
			}
		}
		lastWasAgent = false
	}
	return p
}

// Allowed reports whether u may be followed. It matches Disallow rules as path
// prefixes, which is how the common robots.txt syntax is read in practice.
func (p *Policy) Allowed(u *url.URL) bool {
	if p == nil || u == nil {
		return true
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	for _, d := range p.disallow {
		if strings.HasPrefix(path, d) {
			return false
		}
	}
	return true
}
