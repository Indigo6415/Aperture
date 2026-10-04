package netgov

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// maxCapturedBody bounds how much of each request and response body an
// Exchange keeps. Bodies past this are cut off with a marker, so one large
// download cannot balloon a scan's stored request log.
const maxCapturedBody = 64 << 10

// Exchange is one request this Transport actually put on the wire and what
// came back. It exists so a scan's traffic can be inspected after the fact.
type Exchange struct {
	Method string
	URL    string
	Host   string
	// Status is the response status code, or 0 when the request failed
	// before any response arrived (Error then says why).
	Status int
	// Size is the response body size: the declared Content-Length when the
	// server sent one, otherwise the number of body bytes actually read.
	Size int64
	// TTFB is the time from sending the request until the response headers
	// arrived.
	TTFB  time.Duration
	Error string
	// RequestRaw and ResponseRaw are human-readable renderings of the request
	// line/headers/body and the status line/headers/body, body capped.
	RequestRaw  string
	ResponseRaw string
	Timestamp   time.Time
	// Ref names this exchange; FromRef is the Ref of the 3xx exchange whose
	// redirect led to it, or "" when the request wasn't reached by a redirect.
	Ref     string
	FromRef string
	// Location is the Location header of a 3xx response, empty for any other
	// status. It names the next request, which may be one this client never makes
	// (a server-side redirect to a callback host, say).
	Location string
}

// Recorder receives every Exchange made on a context that carries it.
type Recorder interface {
	Record(Exchange)
}

// RecorderFunc adapts an ordinary function to the Recorder interface.
type RecorderFunc func(Exchange)

// Record calls f(e).
func (f RecorderFunc) Record(e Exchange) { f(e) }

type recorderKey struct{}

// WithRecorder returns a context whose requests are reported to r once each
// exchange completes. Requests made on a context without a recorder are not
// captured at all, so only scans that ask for a log pay for one.
func WithRecorder(ctx context.Context, r Recorder) context.Context {
	return context.WithValue(ctx, recorderKey{}, r)
}

// LimitRecorder returns a Recorder that forwards at most limit exchanges to
// next and drops the rest. It is safe for concurrent use, since one scan's
// requests arrive from many goroutines at once.
func LimitRecorder(next Recorder, limit int64) Recorder {
	var passed atomic.Int64
	return RecorderFunc(func(e Exchange) {
		// Add first, then compare, so concurrent requests can't all slip under
		// the cap; the value past the cap is simply dropped.
		if passed.Add(1) > limit {
			return
		}
		next.Record(e)
	})
}

// recorderFrom returns the recorder on ctx, or nil when there is none.
func recorderFrom(ctx context.Context) Recorder {
	r, _ := ctx.Value(recorderKey{}).(Recorder)
	return r
}

// observeResponse arranges for the completed exchange to be recorded once
// the caller closes resp.Body. It must run after classify, so the body it
// wraps already replays any bytes classify peeked at.
func observeResponse(req *http.Request, resp *http.Response, sent time.Time, ttfb time.Duration) {
	rec := recorderFrom(req.Context())
	if rec == nil {
		return
	}
	ref := newExchangeRef()
	notePendingRedirect(req, resp, ref)
	// Snapshot the request now: its body is read through GetBody, which is
	// only safe to do before the transport has consumed the original.
	requestRaw := rawRequest(req, requestBodyCopy(req))
	resp.Body = &captureBody{
		ReadCloser: resp.Body,
		finish: func(body []byte, read int64) {
			size := read
			if resp.ContentLength >= 0 {
				size = resp.ContentLength
			}
			rec.Record(Exchange{
				Method:      req.Method,
				URL:         req.URL.String(),
				Host:        hostOf(req),
				Status:      resp.StatusCode,
				Size:        size,
				TTFB:        ttfb,
				RequestRaw:  requestRaw,
				ResponseRaw: rawResponse(resp, body, read),
				Timestamp:   sent,
				Ref:         ref,
				FromRef:     fromRefFrom(req.Context()),
				Location:    redirectLocation(resp),
			})
		},
	}
}

// recordFailure reports a request that was sent but produced no response at
// all, such as a refused connection, a TLS failure, or a timeout.
func recordFailure(req *http.Request, sent time.Time, err error) {
	rec := recorderFrom(req.Context())
	if rec == nil {
		return
	}
	rec.Record(Exchange{
		Method:     req.Method,
		URL:        req.URL.String(),
		Host:       hostOf(req),
		Error:      err.Error(),
		RequestRaw: rawRequest(req, requestBodyCopy(req)),
		Timestamp:  sent,
		Ref:        newExchangeRef(),
		FromRef:    fromRefFrom(req.Context()),
	})
}

// captureBody keeps the first maxCapturedBody bytes the caller reads and
// reports the exchange exactly once, when the body is closed.
type captureBody struct {
	io.ReadCloser
	buf    bytes.Buffer
	read   int64
	once   sync.Once
	finish func(body []byte, read int64)
}

// Read passes through to the wrapped body while keeping a copy of what it
// returns, up to the capture limit.
func (c *captureBody) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.read += int64(n)
	// Only the first maxCapturedBody bytes are kept; anything after is still
	// counted in read so the size stays accurate.
	if room := maxCapturedBody - c.buf.Len(); room > 0 && n > 0 {
		c.buf.Write(p[:min(n, room)])
	}
	return n, err
}

// Close closes the wrapped body and records the exchange on the first call.
func (c *captureBody) Close() error {
	err := c.ReadCloser.Close()
	c.once.Do(func() { c.finish(c.buf.Bytes(), c.read) })
	return err
}

// requestBodyCopy returns up to maxCapturedBody bytes of the request body,
// read through GetBody so the transport's own copy is left alone. It returns
// nil when the body cannot be re-read.
func requestBodyCopy(req *http.Request) []byte {
	if req.Body == nil || req.Body == http.NoBody || req.GetBody == nil {
		return nil
	}
	rc, err := req.GetBody()
	if err != nil {
		return nil
	}
	defer rc.Close()
	body, _ := io.ReadAll(io.LimitReader(rc, maxCapturedBody+1))
	return body
}

// rawRequest renders a request as the wire would show it, with body appended
// and capped. The Host shown is the one actually sent, so an override applied
// through ApplyHeaders is visible here.
func rawRequest(req *http.Request, body []byte) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\n", req.Method, req.URL.RequestURI())
	fmt.Fprintf(&b, "Host: %s\n", hostOf(req))
	writeHeader(&b, wireHeader(req))
	b.WriteString("\n")
	// requestBodyCopy reads one byte past the cap so overflow is detectable;
	// trim it here so the rendering never shows that extra byte.
	truncated := len(body) > maxCapturedBody
	if truncated {
		body = body[:maxCapturedBody]
	}
	b.WriteString(cappedBody(body, truncated))
	return b.String()
}

// wireHeader returns the headers the transport will actually send. That is
// the caller's own headers plus the defaults net/http adds on its own
// (User-Agent, Accept-Encoding, and Content-Length), so the log shows the
// request as it went out rather than only what the scanner set.
func wireHeader(req *http.Request) http.Header {
	h := http.Header{}
	for k, v := range req.Header {
		h[k] = append([]string(nil), v...)
	}
	if h.Get("User-Agent") == "" {
		h.Set("User-Agent", "Go-http-client/1.1")
	}
	// The transport requests gzip unless the caller set its own encoding or a
	// Range, and never for HEAD.
	if h.Get("Accept-Encoding") == "" && h.Get("Range") == "" && req.Method != http.MethodHead {
		h.Set("Accept-Encoding", "gzip")
	}
	if req.ContentLength > 0 && h.Get("Content-Length") == "" {
		h.Set("Content-Length", strconv.FormatInt(req.ContentLength, 10))
	}
	return h
}

// rawResponse renders a response's status line and headers, followed by the
// body bytes captured so far. read is the total body size actually consumed,
// which tells whether the captured copy is complete.
func rawResponse(resp *http.Response, body []byte, read int64) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n", resp.Proto, resp.Status)
	writeHeader(&b, resp.Header)
	b.WriteString("\n")
	b.WriteString(cappedBody(body, read > int64(len(body))))
	return b.String()
}

// cappedBody returns body as text, with a marker appended when it was cut
// short (either by our own capture limit or by the caller stopping early).
func cappedBody(body []byte, truncated bool) string {
	if !truncated {
		return string(body)
	}
	return string(body) + "\n[... body truncated ...]"
}

// writeHeader writes headers one per line, sorted by name so the rendering
// is stable from one request to the next.
func writeHeader(b *strings.Builder, h http.Header) {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range h[k] {
			fmt.Fprintf(b, "%s: %s\n", k, v)
		}
	}
}

// hostOf returns the Host a request is sent with: an explicit Host override
// when one is set, otherwise the URL's host.
func hostOf(req *http.Request) string {
	if req.Host != "" {
		return req.Host
	}
	return req.URL.Host
}

// redirectLocation returns the Location header of a 3xx response, or "" for any
// other status, so only redirects carry a next-hop address into the log.
func redirectLocation(resp *http.Response) string {
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return ""
	}
	return resp.Header.Get("Location")
}
