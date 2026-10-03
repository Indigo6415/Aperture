// Package fingerprint reduces an HTTP response to a small, comparable shape
// (status, size, title, body simhash) and builds a per-host "catch-all"
// profile from requests for paths that cannot exist. Scanners use the profile
// to tell a real hit apart from the soft-404 page a single-page app or a
// catch-all route serves for everything -- the single biggest source of false
// positives in path-based checks.
package fingerprint

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"hash/fnv"
	"io"
	"math/bits"
	"net/http"
	"regexp"
	"strings"
)

// Observation is the comparable summary of one response.
type Observation struct {
	Status      int    `json:"status"`
	Length      int    `json:"length"`
	Title       string `json:"title,omitempty"`
	Simhash     uint64 `json:"simhash"`
	ContentType string `json:"contentType,omitempty"`
}

// maxSimhashDistance is how many of the 64 simhash bits two bodies may
// disagree on and still count as "the same page". Unrelated pages differ by
// about 32 bits on average, so 8 leaves a wide margin, while dynamic tokens
// (timestamps, CSRF tokens, request ids) flip only a handful of bits.
const maxSimhashDistance = 8

// minLengthSlack is the absolute byte tolerance used when comparing sizes, so
// tiny pages are not treated as different just because a token changed.
const minLengthSlack = 64

var (
	// scriptOrStylePattern removes code and styling, which are noisy and
	// carry no page identity.
	scriptOrStylePattern = regexp.MustCompile(`(?is)<(script|style)[^>]*>.*?</(script|style)>`)
	// tagPattern strips every remaining markup tag before tokenizing.
	tagPattern = regexp.MustCompile(`(?s)<[^>]*>`)
	// titlePattern extracts the document title used as a cheap page identity.
	titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	// wordPattern splits visible text into lowercase alphanumeric tokens.
	wordPattern = regexp.MustCompile(`[a-z0-9]+`)
)

// Observe summarizes one response. body may be truncated by the caller; the
// summary is only as complete as the bytes it is given.
func Observe(status int, contentType string, body []byte) Observation {
	text := string(body)
	obs := Observation{
		Status:      status,
		Length:      len(body),
		Simhash:     Simhash(text),
		ContentType: contentType,
	}
	// Titles only exist in markup; skip the regex for non-HTML bodies.
	if m := titlePattern.FindStringSubmatch(text); m != nil {
		obs.Title = strings.Join(strings.Fields(strings.ToLower(m[1])), " ")
	}
	return obs
}

// Simhash computes a 64-bit simhash over the word 3-grams of the visible text
// of body. Two pages that differ only in a few dynamic tokens produce hashes
// with a small Hamming distance. Empty or markup-free input returns 0.
func Simhash(body string) uint64 {
	// Remove code and markup first so only visible words contribute.
	visible := scriptOrStylePattern.ReplaceAllString(body, " ")
	visible = tagPattern.ReplaceAllString(visible, " ")
	words := wordPattern.FindAllString(strings.ToLower(visible), -1)
	if len(words) == 0 {
		return 0
	}

	// Each word 3-gram votes on every bit of the final hash.
	var weights [64]int
	shingleCount := len(words) - 2
	if shingleCount < 1 {
		shingleCount = 1
	}
	for i := 0; i < shingleCount; i++ {
		// Shorter inputs use whatever words exist as a single shingle.
		end := i + 3
		if end > len(words) {
			end = len(words)
		}
		h := fnv.New64a()
		h.Write([]byte(strings.Join(words[i:end], " ")))
		sum := h.Sum64()
		for bit := 0; bit < 64; bit++ {
			if sum&(1<<uint(bit)) != 0 {
				weights[bit]++
			} else {
				weights[bit]--
			}
		}
	}

	var out uint64
	for bit := 0; bit < 64; bit++ {
		if weights[bit] > 0 {
			out |= 1 << uint(bit)
		}
	}
	return out
}

// Distance returns the Hamming distance between two simhashes.
func Distance(a, b uint64) int {
	return bits.OnesCount64(a ^ b)
}

// Similar reports whether two observations describe the same kind of page:
// same status, sizes within tolerance, and matching title or near-identical
// body.
func Similar(a, b Observation) bool {
	if a.Status != b.Status {
		return false
	}
	if !lengthsClose(a.Length, b.Length) {
		return false
	}
	// A matching non-empty title is a strong identity signal on its own.
	if a.Title != "" && a.Title == b.Title {
		return true
	}
	return Distance(a.Simhash, b.Simhash) <= maxSimhashDistance
}

// lengthsClose reports whether two sizes differ by at most the larger of the
// absolute slack and five percent of the bigger size.
func lengthsClose(a, b int) bool {
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	bigger := a
	if b > bigger {
		bigger = b
	}
	slack := bigger / 20
	if slack < minLengthSlack {
		slack = minLengthSlack
	}
	return diff <= slack
}

// Profile is the catch-all fingerprint of one host: what a path that cannot
// exist looks like there. A profile only filters when its samples agree with
// each other; if the server answers random paths inconsistently, filtering
// would hide real content, so Profile.Matches returns false instead.
type Profile struct {
	Samples []Observation `json:"samples"`
	// Stable is true when every sample is Similar to the first one.
	Stable bool `json:"stable"`
}

// probeShapes are the nonexistent-path shapes sampled for a profile: a bare
// random segment, one with a common file extension, and one under a
// directory-like prefix. Covering all three catches routers that treat files
// and directories differently.
var probeShapes = []string{"%s", "%s.html", "dir-%s/"}

// BuildProfile requests a few random nonexistent paths under base (a scheme
// and host, optionally with a path prefix) and summarizes the answers. client
// should already route through the shared governor so the probes respect
// per-host limits. Individual request failures are skipped; an error is only
// returned when no sample could be taken at all.
func BuildProfile(ctx context.Context, client *http.Client, base string, headers map[string]string) (*Profile, error) {
	var samples []Observation
	for _, shape := range probeShapes {
		// Each probe uses a fresh random name so no cached or real path can match.
		name := randomName()
		target := strings.TrimRight(base, "/") + "/" + strings.Replace(shape, "%s", name, 1)
		obs, err := fetchObservation(ctx, client, target, headers)
		if err != nil {
			continue
		}
		samples = append(samples, obs)
	}
	if len(samples) == 0 {
		return nil, context.DeadlineExceeded
	}

	// Stable means every probe is Similar to the first. Otherwise the host
	// is answering random paths with varied content and nothing is filtered.
	return NewProfile(samples), nil
}

// NewProfile builds a Profile from already-collected samples. It is the path
// for callers that gather their own probes, such as webfuzz calibration. An
// empty sample list yields a profile that never matches.
func NewProfile(samples []Observation) *Profile {
	stable := len(samples) > 0
	for i := 1; i < len(samples); i++ {
		if !Similar(samples[0], samples[i]) {
			stable = false
			break
		}
	}
	return &Profile{Samples: samples, Stable: stable}
}

// Matches reports whether obs is indistinguishable from the catch-all page.
// An unstable or empty profile never matches, so real content is never hidden
// on hosts whose catch-all behavior is unclear.
func (p *Profile) Matches(obs Observation) bool {
	if p == nil || !p.Stable || len(p.Samples) == 0 {
		return false
	}
	return Similar(p.Samples[0], obs)
}

// MatchesSize is the reduced check for tools that report only status and
// size (ffuf and feroxbuster output): it compares status and size bands, not
// bodies, so it is weaker than Matches but needs no extra requests.
func (p *Profile) MatchesSize(status, length int) bool {
	if p == nil || !p.Stable || len(p.Samples) == 0 {
		return false
	}
	ref := p.Samples[0]
	return status == ref.Status && lengthsClose(ref.Length, length)
}

// fetchObservation performs one GET and summarizes the result, reading at
// most a few hundred kilobytes so a huge response cannot exhaust memory.
func fetchObservation(ctx context.Context, client *http.Client, target string, headers map[string]string) (Observation, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return Observation{}, err
	}
	for k, v := range headers {
		// Host must be set on the request, not in the header map, or Go
		// silently ignores it.
		if strings.EqualFold(k, "Host") {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return Observation{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxObserveBytes))
	if err != nil {
		return Observation{}, err
	}
	return Observe(resp.StatusCode, resp.Header.Get("Content-Type"), body), nil
}

// maxObserveBytes caps how much of a response is read for fingerprinting.
const maxObserveBytes = 256 << 10

// randomName returns an unguessable lowercase token for probe paths.
func randomName() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing means the system entropy source is broken;
		// a fixed fallback still produces a path that does not exist.
		return "aperture-fallback"
	}
	return "aperture-" + hex.EncodeToString(b[:])
}
