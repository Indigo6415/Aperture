package apienum

import (
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

//go:embed assets/default.txt
var defaultWordlistRaw []byte

// maxBruteforceRequests bounds how many path guesses one run will ever
// fire, regardless of how many roots (bare target + every discovered API
// group, plus version-sibling guesses) end up in play -- a target with a
// dozen discovered API groups times a ~250-line wordlist could otherwise
// mean thousands of requests, which starts to look like exactly the kind
// of flood the package doc's rate-limiting guardrail exists to avoid.
const maxBruteforceRequests = 1500

// defaultWordlist returns the bundled API path-segment list, one entry per
// non-empty, non-comment line.
func defaultWordlist() []string {
	var out []string
	for line := range strings.SplitSeq(string(defaultWordlistRaw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

var versionSegment = regexp.MustCompile(`^v([0-9]+)$`)

// bruteforceRoots is every base path to try the wordlist under: the bare
// target root, plus every API-shaped group already discovered (so e.g.
// "login" gets tried both as "/login" and "/api/v1/login"), plus a
// version-sibling guess for any discovered root ending in "v<N>" -- a
// target that versions one route typically versions its whole API the
// same way, so finding /api/v1 is a reason to go looking for /api/v2.
func bruteforceRoots(existing []Route) []string {
	roots := map[string]bool{"": true}
	for _, r := range existing {
		g := r.Group
		if g == "" || g == "/" {
			continue
		}
		roots[g] = true
		segs := strings.Split(strings.TrimPrefix(g, "/"), "/")
		last := segs[len(segs)-1]
		if m := versionSegment.FindStringSubmatch(last); m != nil {
			n, _ := strconv.Atoi(m[1])
			// Newer versions, and the two versions just below: an older
			// deprecated version often keeps routes that a newer one has locked down.
			for _, next := range versionSiblings(n) {
				segs[len(segs)-1] = fmt.Sprintf("v%d", next)
				roots["/"+strings.Join(segs, "/")] = true
			}
		}
	}
	out := make([]string, 0, len(roots))
	for r := range roots {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// versionSiblings returns the version numbers worth guessing next to a
// discovered version n: the two below it (down to v1) and the two above.
func versionSiblings(n int) []int {
	var out []int
	for v := n - 2; v < n; v++ {
		if v >= 1 {
			out = append(out, v)
		}
	}
	return append(out, n+1, n+2)
}

// bruteforcePaths tries every wordlist entry (the bundled default plus any
// caller-supplied extra) under every root concurrently -- bounded by the
// client's own concurrency cap and rate limiter, so this phase paces
// itself exactly like every other request this package sends.
//
// A guess is kept only when it answers something other than a 404 or a 502
// (a gateway error says nothing about the route), and when it does not match
// the directory's soft-404 profile: a host that answers every unknown path with
// the same 200 page would otherwise make every word a "route". Requests go
// through the no-redirect client, so a redirect is recorded as the answer it
// is. Each kept path becomes an uncertain-bucket Route (Confirmed: false, same
// posture as mineJS's finds), left for characterize.go to decide confirmed or
// not from an actual per-method probe.
func bruteforcePaths(ctx context.Context, c *apiClient, t *Target, roots, extra []string, onProgress func(done, total int)) []Route {
	words := append(append([]string{}, defaultWordlist()...), extra...)

	seen := map[string]bool{}
	var tasks []string
	for _, root := range roots {
		for _, w := range words {
			p := root + "/" + strings.TrimPrefix(w, "/")
			if seen[p] {
				continue
			}
			seen[p] = true
			tasks = append(tasks, p)
			if len(tasks) >= maxBruteforceRequests {
				break
			}
		}
		if len(tasks) >= maxBruteforceRequests {
			break
		}
	}

	total := len(tasks)
	var mu sync.Mutex
	var found []Route
	var done atomic.Int32
	var wg sync.WaitGroup
	for _, p := range tasks {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			defer func() {
				if onProgress != nil {
					onProgress(int(done.Add(1)), total)
				}
			}()
			if ctx.Err() != nil {
				return
			}
			res, err := c.getNoFollow(ctx, t.URL+p)
			// A plain 404 means "not here" and a 502 means a gateway in front
			// of the app couldn't reach an upstream -- neither says anything
			// about whether the route exists. Everything else (2xx, a 401/
			// 403 that proves the route exists but needs auth, a 500 that's
			// at least not "unmapped") is worth keeping for characterization
			// to make the real confirmed/uncertain call on.
			if err != nil || res.StatusCode == http.StatusNotFound || res.StatusCode == http.StatusBadGateway {
				return
			}
			// The directory's own "not found" answer is not a route, even when
			// it's a 200. The profile is per directory, so a guess is judged
			// against the same directory it sits in.
			if prof := c.catchAllFor(ctx, t, catchAllDir(parentDir(p))); prof.Matches(observe(res)) {
				return
			}
			mu.Lock()
			found = append(found, Route{
				ID: routeID("bruteforce", p), Path: p, Group: pathGroup(p), Source: "bruteforce",
				Methods: []MethodProbe{{Method: "GET"}},
			})
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	return found
}
