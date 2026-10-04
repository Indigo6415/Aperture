package apienum

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"

	"github.com/Indigo6415/Aperture/internal/fingerprint"
)

// profileCache remembers, per directory on the target, what a path that cannot
// exist looks like there. Routes and brute-force guesses are compared against
// that answer, so a host that serves the same 200 "not found" page (or the
// same 401 gate) for everything doesn't turn every guess into a hit.
type profileCache struct {
	mu      sync.Mutex
	entries map[string]*profileEntry
}

// profileEntry is one directory's cached answers. Each part is computed at most
// once per run, however many goroutines ask for it at the same time.
type profileEntry struct {
	profileOnce sync.Once
	profile     *fingerprint.Profile
	gateOnce    sync.Once
	gate        string
}

// newProfileCache returns an empty cache for one run.
func newProfileCache() *profileCache {
	return &profileCache{entries: map[string]*profileEntry{}}
}

// entry returns the cache slot for key, creating it on first use.
func (pc *profileCache) entry(key string) *profileEntry {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	e, ok := pc.entries[key]
	if !ok {
		e = &profileEntry{}
		pc.entries[key] = e
	}
	return e
}

// catchAllDir normalizes a directory path into the cache key used for it: "" is
// the root, and any other directory has no trailing slash.
func catchAllDir(p string) string {
	p = strings.TrimRight(p, "/")
	return p
}

// parentDir returns the directory a path lives in, normalized by catchAllDir --
// "/api" for "/api/users", "" for "/users".
func parentDir(p string) string {
	i := strings.LastIndexByte(p, '/')
	if i <= 0 {
		return ""
	}
	return catchAllDir(p[:i])
}

// catchAllFor returns the soft-404 profile of dir (a path such as "" or
// "/api"), built from the run's own headers so it's comparable with the
// route requests it judges. It returns nil when no sample could be taken,
// and a nil profile matches nothing.
func (c *apiClient) catchAllFor(ctx context.Context, t *Target, dir string) *fingerprint.Profile {
	e := c.profiles.entry("profile:" + dir)
	e.profileOnce.Do(func() {
		var samples []fingerprint.Observation
		for _, res := range c.sampleNonexistent(ctx, t, dir, false) {
			samples = append(samples, observe(res))
		}
		if len(samples) > 0 {
			e.profile = fingerprint.NewProfile(samples)
		}
	})
	return e.profile
}

// gateVerdict returns the auth verdict a nonexistent, unauthenticated path in
// dir gets. A route whose own unauthenticated verdict is the same one is behind
// a gate that covers the whole directory, not a control of its own.
func (c *apiClient) gateVerdict(ctx context.Context, t *Target, dir string) string {
	e := c.profiles.entry("gate:" + dir)
	e.gateOnce.Do(func() {
		samples := c.sampleNonexistent(ctx, t, dir, true)
		if len(samples) == 0 {
			return
		}
		// Only the first sample is used: it's the bare-name shape, the closest to a route.
		verdict, _ := authVerdictFor(samples[0], false)
		e.gate = verdict
	})
	return e.gate
}

// sampleNonexistent requests a few random names in dir and returns the raw
// response each one got. skipBaseline selects the unauthenticated variant.
func (c *apiClient) sampleNonexistent(ctx context.Context, t *Target, dir string, skipBaseline bool) []*apiResult {
	base := strings.TrimRight(t.URL, "/") + dir
	shapes := []string{"%s", "%s.html", "%s/"}
	var out []*apiResult
	for _, shape := range shapes {
		if ctx.Err() != nil {
			break
		}
		name := randomProbeSegment()
		target := base + "/" + strings.Replace(shape, "%s", name, 1)
		res, err := c.doNoFollow(ctx, "GET", target, nil, skipBaseline, nil)
		if err != nil {
			continue
		}
		out = append(out, res)
	}
	return out
}

// observe summarizes one apiResult the way the fingerprint package compares
// responses.
func observe(res *apiResult) fingerprint.Observation {
	return fingerprint.Observe(res.StatusCode, res.Header.Get("Content-Type"), res.Body)
}

// randomProbeSegment returns an unguessable path segment for nonexistent-path
// probes, so no real or cached path can match it.
func randomProbeSegment() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing means the system entropy source is broken;
		// a fixed fallback still names a path that does not exist.
		return "aperture-fallback"
	}
	return "aperture-" + hex.EncodeToString(b[:])
}
