package probescan

import (
	"context"
	"fmt"
	"net"
)

// HealthSummary is a quick, non-blocking reachability check run before the
// module suite -- ported from probe's healthcheck.py, minus the ping/curl
// subprocess calls (ICMP is usually unavailable/blocked from a hosted
// service anyway, and curl added nothing net.Dial/http.Client don't already
// give directly). Unlike the original CLI, an unhealthy target never blocks
// the scan -- there's no interactive "continue anyway?" prompt in a web UI,
// so this is purely informational.
type HealthSummary struct {
	TCP   bool `json:"tcp"`
	HTTP  bool `json:"http"`
	HTTPS bool `json:"https"`
}

func checkHealth(ctx context.Context, t *Target) HealthSummary {
	var h HealthSummary

	addr := net.JoinHostPort(t.Hostname, fmt.Sprint(t.Port))
	if conn, err := (&net.Dialer{Timeout: probeTimeout}).DialContext(ctx, "tcp", addr); err == nil {
		h.TCP = true
		conn.Close()
	}

	httpc := newProbeClient(1, nil)
	if r, err := httpc.get(ctx, fmt.Sprintf("http://%s:%d", t.Hostname, t.Port), false); err == nil && r.StatusCode > 0 {
		h.HTTP = true
	}
	if r, err := httpc.get(ctx, fmt.Sprintf("https://%s:%d", t.Hostname, t.Port), false); err == nil && r.StatusCode > 0 {
		h.HTTPS = true
	}

	return h
}
