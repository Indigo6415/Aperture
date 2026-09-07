package cve

import (
	"context"
	"sync"
	"time"
)

// rateLimiter enforces NVD's published rate limits (5 requests/30s without
// an API key, 50/30s with one) via a sliding window over recent request
// timestamps -- request volume here is low (at most a handful of
// technologies per scanned host), so a timestamp log is simpler than a
// token-bucket implementation and plenty efficient at this scale.
type rateLimiter struct {
	mu         sync.Mutex
	window     time.Duration
	limit      int
	timestamps []time.Time
}

var (
	limitersMu sync.Mutex
	limiters   = map[bool]*rateLimiter{}
)

// limiterFor returns the shared limiter for one NVD rate class (with or
// without an API key), creating it on first use. Shared across the process
// since NVD enforces its limit per API key/IP, not per goroutine.
func limiterFor(hasKey bool) *rateLimiter {
	limitersMu.Lock()
	defer limitersMu.Unlock()
	if l, ok := limiters[hasKey]; ok {
		return l
	}
	limit := 5
	if hasKey {
		limit = 50
	}
	l := &rateLimiter{window: 30 * time.Second, limit: limit}
	limiters[hasKey] = l
	return l
}

// wait blocks until a request is allowed under the limit, or ctx is
// cancelled first.
func (l *rateLimiter) wait(ctx context.Context) error {
	for {
		l.mu.Lock()
		now := time.Now()
		cutoff := now.Add(-l.window)
		kept := l.timestamps[:0]
		for _, t := range l.timestamps {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		l.timestamps = kept
		if len(l.timestamps) < l.limit {
			l.timestamps = append(l.timestamps, now)
			l.mu.Unlock()
			return nil
		}
		wait := l.timestamps[0].Add(l.window).Sub(now)
		l.mu.Unlock()

		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
