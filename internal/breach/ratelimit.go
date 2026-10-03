package breach

import (
	"context"
	"sync"
	"time"
)

// limiter enforces HIBP's published rate limit for its lowest-tier
// subscription key (10 requests/minute) -- a single shared limiter is
// simplest here since Aperture only ever has one HIBP key configured at a
// time (see internal/api/settings.go), same sliding-window approach as
// internal/cve's own rateLimiter.
type rateLimiter struct {
	mu         sync.Mutex
	window     time.Duration
	limit      int
	timestamps []time.Time
}

var limiter = &rateLimiter{window: 60 * time.Second, limit: 10}

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
