package apienum

import (
	"context"
	"sync"
	"time"
)

// rateLimiter paces every request one run issues to at most `limit` per
// second via a sliding one-second window, same approach as
// internal/cve/breach's own rateLimiter -- kept as its own per-run instance
// here rather than a package-global, since every call to RunScanStreaming
// has its own independent budget rather than sharing one across the whole
// process. A nil *rateLimiter (see newLimiter) makes wait a no-op, so an
// unlimited run doesn't pay for a limiter it doesn't need.
type rateLimiter struct {
	mu         sync.Mutex
	limit      int
	timestamps []time.Time
}

// newLimiter returns nil when perSecond is 0 or negative -- "unlimited",
// not "limited to zero".
func newLimiter(perSecond int) *rateLimiter {
	if perSecond <= 0 {
		return nil
	}
	return &rateLimiter{limit: perSecond}
}

// wait blocks until a request is allowed under the limit, or ctx is
// cancelled first.
func (l *rateLimiter) wait(ctx context.Context) error {
	if l == nil {
		return nil
	}
	for {
		l.mu.Lock()
		now := time.Now()
		cutoff := now.Add(-time.Second)
		kept := l.timestamps[:0]
		// Drop every timestamp that's aged out of the trailing one-second
		// window before deciding whether there's room for one more.
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
		waitFor := l.timestamps[0].Add(time.Second).Sub(now)
		l.mu.Unlock()

		select {
		case <-time.After(waitFor):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
