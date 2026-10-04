// Package paramminer discovers undocumented request parameters on an
// endpoint, so every injection-style scanner (SSRF, open redirect, XSS,
// path traversal, SSTI, ...) can test parameters that never appear in a
// link or form on the page.
//
// The method is the same one internal/apienum uses for its own query-param
// sweep, generalized so any scanner can call it:
//
//   - Two identical baseline requests first. An endpoint that does not answer
//     the same way twice cannot be diffed, so mining returns nothing rather
//     than reporting noise.
//   - Candidate names are sent in chunks, each name set to a plain canary
//     value. A chunk whose response differs from the baseline (status or body
//     content, via internal/fingerprint) or that reflects the canary is split
//     in half and retried until every responsive name stands alone.
//   - A name counts when it changes the response or is reflected back. The
//     result is a list of names for the caller to fold into its own candidate
//     set. Mining never reports a finding itself.
//
// Chunking keeps the cost near one request per chunk for an endpoint that
// ignores everything, which is the common case.
package paramminer

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Indigo6415/Aperture/internal/fingerprint"
)

// chunkSize is how many candidate names one probe request carries. A chunk
// that changes the response is bisected, so a larger chunk means fewer
// requests when nothing responds, and more bisection when something does.
const chunkSize = 12

// canary is the value every mined parameter is set to. It has no digits or
// symbols, so a reflection check can find it and it is never mistaken for an
// ID or a boolean.
const canary = "aperturecanary"

// maxBodyBytes caps how much of each probe response is read. Mining only
// needs the body's shape and whether the canary appears, not all of it.
const maxBodyBytes = 256 * 1024

// Options is one mining run's configuration.
type Options struct {
	// URL is the endpoint to mine. Its own query parameters are left alone:
	// they are already known, so Known should list them and they are skipped.
	URL *url.URL
	// Method is GET (default) or POST. A POST sends the probe names as a
	// form-encoded body, same as the scanners' own POST fetches.
	Method  string
	Headers map[string]string
	// Client is the HTTP client every probe goes through. Callers pass their
	// own so timeouts and the rest of their transport settings apply.
	Client *http.Client
	// Known are names already in the caller's candidate set. They are not
	// probed again.
	Known []string
	// Names overrides the built-in Wordlist. Nil uses Wordlist.
	Names []string
}

// Result is what one mining run found.
type Result struct {
	// Names are the parameter names whose presence changes the response, in
	// the order they were found.
	Names []string
	// Reflected is the subset of Names whose canary came back in the body.
	// A reflected parameter is a stronger lead for reflection-based checks
	// (XSS, SSTI) than one that only changes the status.
	Reflected []string
	// Requests is how many probe requests were sent, baseline included.
	Requests int
}

// Mine runs the discovery described in the package comment against opts.URL.
// It returns an empty Result, not an error, when the endpoint is unstable or
// nothing is found, so a caller can fold the names in without special-casing.
// It only returns an error when the context is cancelled.
func Mine(ctx context.Context, opts Options) (Result, error) {
	var res Result
	if opts.URL == nil || opts.Client == nil {
		return res, nil
	}
	method := opts.Method
	if method == "" {
		method = http.MethodGet
	}

	// Two identical requests first. If they disagree, any later difference
	// would be noise, so bail out before probing.
	b1, err := probe(ctx, opts, method, nil)
	res.Requests++
	if err != nil {
		return res, ctx.Err()
	}
	b2, err := probe(ctx, opts, method, nil)
	res.Requests++
	if err != nil {
		return res, ctx.Err()
	}
	if b1.StatusCode != b2.StatusCode || !fingerprint.Similar(observe(b1), observe(b2)) {
		return res, nil
	}
	baseline := observe(b1)

	known := map[string]bool{}
	for _, k := range opts.Known {
		known[k] = true
	}
	for k := range opts.URL.Query() {
		known[k] = true
	}
	var candidates []string
	for _, name := range pickWordlist(opts.Names) {
		if name != "" && !known[name] {
			candidates = append(candidates, name)
		}
	}

	for start := 0; start < len(candidates); start += chunkSize {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		end := min(start+chunkSize, len(candidates))
		bisect(ctx, opts, method, candidates[start:end], baseline, &res)
	}
	return res, ctx.Err()
}

// bisect sends names as one probe. If that probe differs from the baseline it
// splits names in half and recurses until each responsive name is alone, and
// records each one it reaches.
func bisect(ctx context.Context, opts Options, method string, names []string, baseline fingerprint.Observation, res *Result) {
	if len(names) == 0 || ctx.Err() != nil {
		return
	}
	set := make(map[string]string, len(names))
	for _, n := range names {
		set[n] = canary
	}
	resp, err := probe(ctx, opts, method, set)
	res.Requests++
	if err != nil {
		return
	}
	reflected := bytes.Contains([]byte(resp.Body), []byte(canary))
	changed := resp.StatusCode != baseline.Status || !fingerprint.Similar(baseline, observe(resp))
	if !changed && !reflected {
		return
	}
	if len(names) == 1 {
		res.Names = append(res.Names, names[0])
		if reflected {
			res.Reflected = append(res.Reflected, names[0])
		}
		return
	}
	mid := len(names) / 2
	bisect(ctx, opts, method, names[:mid], baseline, res)
	bisect(ctx, opts, method, names[mid:], baseline, res)
}

// probeResponse is the part of a probe's answer mining needs.
type probeResponse struct {
	StatusCode int
	Header     http.Header
	Body       string
}

// probe sends one request to opts.URL with every name in set given the
// canary value. A nil set is the plain baseline request. GET puts the names
// in the query string and POST in a form body.
func probe(ctx context.Context, opts Options, method string, set map[string]string) (probeResponse, error) {
	reqURL := *opts.URL
	var body io.Reader
	if method == http.MethodPost {
		form := url.Values{}
		for k, v := range set {
			form.Set(k, v)
		}
		body = strings.NewReader(form.Encode())
	} else {
		q := reqURL.Query()
		for k, v := range set {
			q.Set(k, v)
		}
		reqURL.RawQuery = q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL.String(), body)
	if err != nil {
		return probeResponse{}, err
	}
	req.Header.Set("User-Agent", "Aperture-ParamMiner")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range opts.Headers {
		req.Header.Set(k, v)
	}

	resp, err := opts.Client.Do(req)
	if err != nil {
		return probeResponse{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return probeResponse{}, err
	}
	return probeResponse{StatusCode: resp.StatusCode, Header: resp.Header, Body: string(raw)}, nil
}

// observe turns a probe response into the fingerprint used for comparison.
func observe(r probeResponse) fingerprint.Observation {
	return fingerprint.Observe(r.StatusCode, r.Header.Get("Content-Type"), []byte(r.Body))
}

// pickWordlist returns names when given, else the built-in Wordlist.
func pickWordlist(names []string) []string {
	if names != nil {
		return names
	}
	return Wordlist
}

// Names mines u with a GET and returns just the discovered names. It is the
// shape the scanners want: each one folds the result into its own Params list,
// so mining feeds every existing candidate-building path without changing
// it. Errors and cancellation both come back as an empty list, since a
// scanner that loses its mining should still run its own checks.
func Names(ctx context.Context, u *url.URL, headers map[string]string, client *http.Client, known []string) []string {
	res, _ := Mine(ctx, Options{URL: u, Headers: headers, Client: client, Known: known})
	return res.Names
}
