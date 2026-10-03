package collaborator

import (
	"context"
	"time"
)

// WaitForCallbacks polls for interactions every interval until at least one
// new interaction has arrived and then stays quiet for quiet, or until maxWait
// elapses. Everything collected is returned, deduplicated by interaction ID.
//
// It replaces a fixed sleep followed by one poll. A single poll misses a
// callback that lands after it, while this keeps polling through the whole
// window, and it returns as soon as the callbacks have stopped arriving.
func WaitForCallbacks(ctx context.Context, poll func(context.Context) ([]Interaction, error), interval, quiet, maxWait time.Duration) ([]Interaction, error) {
	deadline := time.Now().Add(maxWait)
	var all []Interaction
	seen := map[string]bool{}
	var lastHit time.Time
	var lastErr error

	for {
		hits, err := poll(ctx)
		if err != nil {
			lastErr = err
		}
		// Keep only interactions not already collected on an earlier poll.
		for _, h := range hits {
			if seen[h.ID] {
				continue
			}
			seen[h.ID] = true
			all = append(all, h)
			lastHit = time.Now()
		}
		// Callbacks have arrived and stopped: no reason to keep waiting.
		if !lastHit.IsZero() && time.Since(lastHit) >= quiet {
			return all, nil
		}
		if !time.Now().Before(deadline) {
			// Hits gathered before the deadline are real even if the last poll failed.
			if len(all) > 0 {
				return all, nil
			}
			return all, lastErr
		}
		select {
		case <-ctx.Done():
			return all, ctx.Err()
		case <-time.After(interval):
		}
	}
}

// Defaults for OOB waits. A callback usually lands within a second or two of
// the probe that triggered it, so the quiet period ends the wait early; the
// maximum bounds the cost when nothing calls back at all.
const (
	DefaultPollInterval = 2 * time.Second
	DefaultQuietPeriod  = 3 * time.Second
	DefaultMaxWait      = 10 * time.Second
)

// WaitForRegistry waits, using WaitForCallbacks, until no new interaction has
// arrived on any of tokens. The interactions stay in the registry, so callers
// read them afterwards with Registry.Poll as before.
func WaitForRegistry(ctx context.Context, reg *Registry, tokens []string, interval, quiet, maxWait time.Duration) {
	// The returned list is unused: only the quiet-period timing matters here.
	_, _ = WaitForCallbacks(ctx, func(context.Context) ([]Interaction, error) {
		var out []Interaction
		for _, t := range tokens {
			out = append(out, reg.Poll(t)...)
		}
		return out, nil
	}, interval, quiet, maxWait)
}
