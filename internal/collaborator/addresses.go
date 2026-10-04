package collaborator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// publicIPServices are plain-text "what's my IP" endpoints tried in order.
// The first that returns a valid IPv4 address wins, so one service being down
// or rate-limiting doesn't break detection.
var publicIPServices = []string{
	"https://api.ipify.org",
	"https://icanhazip.com",
	"https://ifconfig.me/ip",
}

// publicIPTTL is how long a successful public-IP lookup is reused. The address
// rarely changes, and this avoids hitting the lookup services on every UI load.
const publicIPTTL = 10 * time.Minute

var (
	publicIPMu      sync.Mutex
	publicIPCached  string
	publicIPFetched time.Time
)

// LocalIPv4 returns this host's LAN IPv4 address, read from the local network
// interfaces (no network traffic). Private (RFC 1918) addresses are preferred,
// since those are what a LAN target would reach. If none is found, the first
// non-loopback IPv4 address is returned. An error is returned when the host has
// no usable IPv4 address.
func LocalIPv4() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	var fallback string
	for _, iface := range ifaces {
		// Skip interfaces that are down or loopback (127.0.0.1 is not reachable from other hosts).
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip, _, err := net.ParseCIDR(a.String())
			if err != nil {
				continue
			}
			v4 := ip.To4()
			if v4 == nil || v4.IsLoopback() || v4.IsLinkLocalUnicast() {
				continue
			}
			if v4.IsPrivate() {
				return v4.String(), nil
			}
			if fallback == "" {
				fallback = v4.String()
			}
		}
	}
	if fallback != "" {
		return fallback, nil
	}
	return "", errors.New("no non-loopback IPv4 address found on this host")
}

// PublicIPv4 returns this host's public IPv4 address as seen by an external
// lookup service. A successful result is cached for publicIPTTL. ctx bounds the
// total lookup time across all services.
func PublicIPv4(ctx context.Context) (string, error) {
	publicIPMu.Lock()
	defer publicIPMu.Unlock()

	// Serve the cached address while it's still fresh.
	if publicIPCached != "" && time.Since(publicIPFetched) < publicIPTTL {
		return publicIPCached, nil
	}

	client := &http.Client{Timeout: 5 * time.Second}
	var lastErr error
	for _, svc := range publicIPServices {
		// Stop early if the caller's context was cancelled or timed out.
		if err := ctx.Err(); err != nil {
			return "", err
		}
		ip, err := fetchPlainIP(ctx, client, svc)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", svc, err)
			continue
		}
		publicIPCached = ip
		publicIPFetched = time.Now()
		return ip, nil
	}
	return "", fmt.Errorf("public IP lookup failed: %w", lastErr)
}

// fetchPlainIP GETs a "what's my IP" service and returns its trimmed body,
// which must parse as an IPv4 address.
func fetchPlainIP(ctx context.Context, client *http.Client, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	// The body is a single IP, so a small limit is enough and guards against a misbehaving service.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", err
	}
	ip := net.ParseIP(strings.TrimSpace(string(body)))
	if ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("not an IPv4 address: %q", strings.TrimSpace(string(body)))
	}
	return ip.String(), nil
}
