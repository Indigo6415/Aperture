package ssrf

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// protocolModule is the module that probes internal services a server can
// reach over a non-HTTP scheme: gopher:// (raw TCP with a payload chosen by
// the URL) and dict:// (a memcached/redis-style command line). An SSRF that
// fetches with libcurl, or any client that honors those schemes, will
// otherwise carry these requests straight to a loopback or internal port.
//
// The probes here are detection-only. Each one asks a service for something
// it answers without changing state -- a Redis INFO, a memcached stats, an
// SMTP EHLO, a FastCGI GET_VALUES, the MySQL handshake greeting -- and only
// reports when the response carries that service's own signature, absent
// from the normal responses. Nothing here writes to a service, so a finding
// shows the internal service is reachable and speaking its protocol, not that
// it can be abused. Turning such a foothold into command execution is a
// separate, deliberately manual step.
var protocolModule = moduleMeta{id: "internal-service", name: "Internal service reachable via gopher:// or dict://", severity: "high"}

// serviceProbe is one protocol-level request: the scheme, the target service,
// and the signature that proves the service answered.
type serviceProbe struct {
	service string
	// scheme is "gopher" or "dict". A gopher probe sends raw bytes after the
	// "_" type marker; a dict probe sends a command line.
	scheme string
	host   string
	port   int
	// raw is the exact bytes sent (gopher) or the dict command. It is
	// percent-encoded into the URL, so binary and CRLF are safe to write here.
	raw string
	sig *regexp.Regexp
	// confidence is "confirmed" for a signature only that service produces,
	// and "likely" for one a generic banner could also match.
	confidence string
}

// fastCGIGetValues is a FastCGI GET_VALUES management record: version 1, type 9,
// request id 0, no content. A FastCGI application answers it with its own
// capability names, and it has no side effects.
const fastCGIGetValues = "\x01\x09\x00\x00\x00\x00\x00\x00"

// protocolProbes are the service probes every point is tested against. Each
// one targets loopback on that service's standard port, which is where an
// SSRF pivots to from the server itself.
var protocolProbes = []serviceProbe{
	{
		service: "Redis", scheme: "gopher", host: "127.0.0.1", port: 6379,
		raw: "INFO\r\n", confidence: ConfidenceConfirmed,
		sig: regexp.MustCompile(`redis_version:\d|-NOAUTH Authentication required|-DENIED Redis is running`),
	},
	{
		// Redis again over dict://, which some clients use in place of gopher
		// and which sends its own command line. Same signature as above.
		service: "Redis (dict://)", scheme: "dict", host: "127.0.0.1", port: 6379,
		raw: "info", confidence: ConfidenceConfirmed,
		sig: regexp.MustCompile(`redis_version:\d|-NOAUTH Authentication required|-DENIED Redis is running|CONFIG REWRITE`),
	},
	{
		service: "memcached", scheme: "gopher", host: "127.0.0.1", port: 11211,
		raw: "stats\r\n", confidence: ConfidenceConfirmed,
		sig: regexp.MustCompile(`STAT (pid|uptime|version) \S+`),
	},
	{
		// SMTP sends its banner on connect, so the 220 line is in the response
		// even though this probe's EHLO is only a courtesy. Banner-only, hence
		// "likely" rather than "confirmed".
		service: "SMTP", scheme: "gopher", host: "127.0.0.1", port: 25,
		raw: "EHLO aperture.invalid\r\nQUIT\r\n", confidence: ConfidenceLikely,
		sig: regexp.MustCompile(`(?m)^220[ -][^\r\n]*(ESMTP|SMTP|[Mm]ail)`),
	},
	{
		service: "FastCGI", scheme: "gopher", host: "127.0.0.1", port: 9000,
		raw: fastCGIGetValues, confidence: ConfidenceConfirmed,
		sig: regexp.MustCompile(`FCGI_(MAX_CONNS|MAX_REQS|MPXS_CONNS)`),
	},
	{
		// MySQL and MariaDB send the handshake greeting on connect, which names
		// the auth plugin. An empty payload is enough to draw it out.
		service: "MySQL", scheme: "gopher", host: "127.0.0.1", port: 3306,
		raw: "", confidence: ConfidenceLikely,
		sig: regexp.MustCompile(`mysql_native_password|caching_sha2_password|MariaDB`),
	},
}

// protocolURL builds the URL a server would be handed to reach one probe. The
// gopher form is gopher://host:port/_<percent-encoded raw bytes>, and the dict
// form is dict://host:port/<command>. Every byte outside the unreserved set is
// percent-encoded, so CRLF and binary bytes survive the trip through the URL.
func (p serviceProbe) protocolURL() string {
	if p.scheme == "dict" {
		return fmt.Sprintf("dict://%s:%d/%s", p.host, p.port, p.raw)
	}
	var b strings.Builder
	// Each raw byte is either kept as-is or escaped to its two-digit hex form.
	for i := 0; i < len(p.raw); i++ {
		c := p.raw[i]
		// Unreserved bytes need no escaping, and everything else must be
		// escaped so CRLF and binary bytes reach the service intact.
		if isUnreserved(c) {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return fmt.Sprintf("gopher://%s:%d/_%s", p.host, p.port, b.String())
}

// isUnreserved reports whether c can stand in a URL unescaped.
func isUnreserved(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// protocolProbeURLs returns the URL of every protocol probe, for the echo list
// -- a server can reflect a gopher or dict URL back, and that reflection must
// not be mistaken for the service answering.
func protocolProbeURLs() []string {
	out := make([]string, 0, len(protocolProbes))
	// Build each probe's URL once, in the same order as protocolProbes.
	for _, p := range protocolProbes {
		out = append(out, p.protocolURL())
	}
	return out
}

// runProtocolModule sends each protocol probe at every parameter point and
// reports a response carrying the service's signature when the normal
// responses do not. The scrubbed echo list stops a reflected gopher URL from
// counting as a service answer.
func runProtocolModule(ctx context.Context, deps runDeps) []Finding {
	return runPointChecks(deps, protocolModule, func(pt probePoint) []Finding {
		normal := normalBodies(ctx, deps, pt)

		var mu sync.Mutex
		var out []Finding
		var wg sync.WaitGroup
		// One goroutine per service probe; the shared request semaphore bounds
		// how many of them are in flight at once.
		for _, probe := range protocolProbes {
			wg.Add(1)
			go func(probe serviceProbe) {
				defer wg.Done()
				res := fetchPointThrottled(ctx, deps, pt, probe.protocolURL())
				if res.Err != nil {
					return
				}
				hits := novelMatches(probe.sig, scrubEchoes(res.Body, deps.echoes), normal)
				if len(hits) == 0 {
					return
				}
				mu.Lock()
				out = append(out, protocolFinding(pt, deps.method, probe, hits[0], res))
				mu.Unlock()
			}(probe)
		}
		wg.Wait()
		return out
	})
}

// protocolFinding builds the finding for one service that answered through
// the parameter. A header point is never used for these probes, so the
// finding always reads as a parameter.
func protocolFinding(pt probePoint, method string, probe serviceProbe, evidence string, res *ssrfResult) Finding {
	scheme := probe.scheme + "://"
	// Label names the service and scheme so the operator sees which protocol
	// reached it.
	return Finding{
		Label: fmt.Sprintf("Parameter %q reaches internal %s service via %s", pt.name, probe.service, scheme),
		Detail: fmt.Sprintf(
			"Set %s and the response carries the %s service's own signature, which the normal responses do not. The server opened a raw connection to %s:%d on its own behalf. This is a read-only detection: it shows the service is reachable from the server, and does not by itself show it can be written to.",
			describePoint(pt, probe.protocolURL()), probe.service, probe.host, probe.port,
		),
		Evidence:   truncateEvidence(evidence),
		Method:     method,
		StatusCode: res.StatusCode,
		Request:    &res.Request,
		Confidence: probe.confidence,
	}
}
