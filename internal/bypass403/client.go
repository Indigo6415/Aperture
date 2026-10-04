package bypass403

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/Indigo6415/Aperture/internal/netgov"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// requestTimeout bounds a single attempt's round trip -- same posture as
// probescan.probeTimeout, just a little more generous since a forbidden
// front-end can sit behind a slower WAF/proxy hop than a plain probe target.
const requestTimeout = 8 * time.Second

// maxBodyBytes caps how much of a response body any one attempt reads. A
// bypass attempt only needs enough of the body to run looksBlocked's
// substring checks and report an accurate length, not the whole page.
const maxBodyBytes = 512 * 1024

// httpResult is the trimmed-down response shape every attempt is judged by.
type httpResult struct {
	StatusCode    int
	ContentLength int // len(Body) actually read, capped by maxBodyBytes
	BodyLower     string
	// Location and ContentType are the response headers the judging rules
	// read: a redirect's destination (sign-in detection) and the body's type.
	Location    string
	ContentType string
}

// newHTTPResult builds the trimmed response every attempt is judged by from a
// raw http.Response and its already-read body.
func newHTTPResult(resp *http.Response, body []byte) *httpResult {
	return &httpResult{
		StatusCode:    resp.StatusCode,
		ContentLength: len(body),
		BodyLower:     strings.ToLower(string(body)),
		Location:      resp.Header.Get("Location"),
		ContentType:   resp.Header.Get("Content-Type"),
	}
}

// doAttempt issues one bypass attempt's request. literalTarget is the exact,
// already-escaped request-target (path + optional "?query") to send on the
// wire -- callers build it themselves (see attempts.go) rather than handing
// this a URL string, because several path-manipulation techniques rely on
// bytes (raw "%2561", a trailing "%00", a doubled slash) that net/url would
// otherwise silently re-normalize away if parsed as an ordinary URL string.
// Setting URL.Opaque to that literal string sidesteps that: url.URL.RequestURI
// returns Opaque verbatim whenever it's set and doesn't start with "//",
// which is exactly the raw request-line text this engine needs to control.
//
// connectHost is who the client actually dials; hostHeader is what's sent in
// the request's Host header/authority -- normally the same value, but a
// technique that spoofs the Host header (see attempts.go's "header-host-*"
// entries) needs to keep dialing the real target while lying about which
// virtual host it thinks it's asking for.
func doAttempt(ctx context.Context, client *http.Client, method, scheme, connectHost, hostHeader, literalTarget string, headers map[string]string) (*httpResult, error) {
	req := &http.Request{
		Method: method,
		URL:    &url.URL{Scheme: scheme, Host: connectHost, Opaque: literalTarget},
		Header: make(http.Header),
		Host:   hostHeader,
	}
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "Aperture-403Bypass")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}
	return newHTTPResult(resp, body), nil
}

// rawRequestOptions tunes doRawRequest beyond the request line itself.
type rawRequestOptions struct {
	// proto is the version string on the request line -- "1.0" or "1.1".
	proto string
	// omitHostHeader skips sending a Host header at all (HTTP/1.1 requires
	// one, but plenty of servers/frameworks tolerate its absence anyway --
	// worth trying since a virtual-host or path rule keyed off Host stops
	// matching when there's nothing for it to read).
	omitHostHeader bool
}

// doRawRequest sends literalTarget over a raw connection this package builds
// and parses itself, bypassing net/http's client entirely for the two things
// it has no knob for: forcing the wire protocol version down to HTTP/1.0,
// and omitting the Host header altogether. Both are commonly-cited 403/401
// bypasses (a proxy rule or app-level check scoped to "1.1 with a Host
// header" stops applying), and both are narrow, well-formed requests -- this
// never sends malformed or ambiguous framing (that's request-smuggling
// territory, a different, much riskier class of technique this engine
// doesn't attempt).
func doRawRequest(ctx context.Context, scheme, connectHost, hostHeader, literalTarget string, headers map[string]string, opts rawRequestOptions) (*httpResult, error) {
	addr := connectHost
	if !strings.Contains(addr, ":") {
		if scheme == "https" {
			addr += ":443"
		} else {
			addr += ":80"
		}
	}

	// Raw sockets bypass http.Client, so this request takes its slot from the
	// shared per-host governor explicitly, and reports back below.
	release, admitErr := netgov.Admit(ctx, connectHost)
	if admitErr != nil {
		return nil, admitErr
	}
	defer release()

	netDialer := &net.Dialer{Timeout: requestTimeout}
	var conn net.Conn
	var err error
	if scheme == "https" {
		hostname, _, splitErr := net.SplitHostPort(addr)
		if splitErr != nil {
			hostname = addr
		}
		tlsDialer := &tls.Dialer{NetDialer: netDialer, Config: &tls.Config{InsecureSkipVerify: true, ServerName: hostname}} //nolint:gosec // deliberate: authorized testing against lab/CTF/self-signed targets
		conn, err = tlsDialer.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = netDialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(requestTimeout))
	}

	var b strings.Builder
	fmt.Fprintf(&b, "GET %s HTTP/%s\r\n", literalTarget, opts.proto)
	if !opts.omitHostHeader {
		fmt.Fprintf(&b, "Host: %s\r\n", hostHeader)
	}
	fmt.Fprintf(&b, "User-Agent: Aperture-403Bypass\r\n")
	for k, v := range headers {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("Connection: close\r\n\r\n")

	if _, err := conn.Write([]byte(b.String())); err != nil {
		return nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}
	// Feed the outcome to the governor so a WAF blocking raw requests pauses
	// the host the same way it would pause http.Client traffic.
	netgov.Report(connectHost, resp.StatusCode, resp.Header, body)
	return newHTTPResult(resp, body), nil
}
