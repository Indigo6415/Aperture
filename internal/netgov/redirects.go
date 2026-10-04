package netgov

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// pendingTTL bounds how long a redirect hop waits to be claimed by the request
// it leads to. A 3xx that the caller never follows (a client built with
// followRedirects off) is never claimed, so its entry is dropped after this.
const pendingTTL = 2 * time.Minute

// exchangeSeq numbers exchanges within this process. processNonce is folded
// into every ref so refs from an earlier process can't collide with new ones.
var (
	exchangeSeq  atomic.Uint64
	processNonce = time.Now().UnixNano()
)

// newExchangeRef returns a reference for one exchange, unique within the process.
func newExchangeRef() string {
	return fmt.Sprintf("%x-%d", processNonce, exchangeSeq.Add(1))
}

// fromRefKey is the context key that carries the ref of the redirect that led
// to a request.
type fromRefKey struct{}

// withFromRef returns ctx carrying ref as the exchange that redirected here.
func withFromRef(ctx context.Context, ref string) context.Context {
	return context.WithValue(ctx, fromRefKey{}, ref)
}

// fromRefFrom returns the ref of the exchange that redirected to the request on
// ctx, or "" when that request was not reached by a redirect.
func fromRefFrom(ctx context.Context) string {
	ref, _ := ctx.Value(fromRefKey{}).(string)
	return ref
}

// redirectHop names one redirect: the URL that answered with a 3xx and the
// absolute URL that answer points to.
type redirectHop struct {
	from, to string
}

// pendingRedirect is a 3xx exchange waiting to be claimed by the hop it leads to.
type pendingRedirect struct {
	ref string
	at  time.Time
}

// pendingRedirects holds 3xx exchanges by hop. The HTTP client decides whether
// to follow a 3xx only after the exchange has been recorded, so the follow-up
// request has to find its parent here by URL pair.
var (
	pendingMu        sync.Mutex
	pendingRedirects = map[redirectHop][]pendingRedirect{}
)

// notePendingRedirect records a 3xx exchange so the request it redirects to can
// name it as the source. Responses without a usable Location are ignored, since
// nothing can follow them.
func notePendingRedirect(req *http.Request, resp *http.Response, ref string) {
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return
	}
	// Resolve the same way net/http does when it follows the redirect, so the
	// key matches the URL of the request that follows.
	target, err := req.URL.Parse(loc)
	if err != nil {
		return
	}
	hop := redirectHop{from: req.URL.String(), to: target.String()}
	now := time.Now()

	pendingMu.Lock()
	defer pendingMu.Unlock()
	// Sweep expired entries on each insert, so unclaimed hops don't pile up
	// over a long run.
	for k, queue := range pendingRedirects {
		kept := queue[:0]
		for _, p := range queue {
			if now.Sub(p.at) < pendingTTL {
				kept = append(kept, p)
			}
		}
		if len(kept) == 0 {
			delete(pendingRedirects, k)
		} else {
			pendingRedirects[k] = kept
		}
	}
	pendingRedirects[hop] = append(pendingRedirects[hop], pendingRedirect{ref: ref, at: now})
}

// claimPendingRedirect removes and returns the ref of the most recent 3xx that
// pointed from prev to next, or "" when there is none. The newest entry is
// taken because the hop being followed was just recorded, so it is the most
// likely match when several identical hops are waiting.
func claimPendingRedirect(prev, next string) string {
	hop := redirectHop{from: prev, to: next}
	pendingMu.Lock()
	defer pendingMu.Unlock()
	queue := pendingRedirects[hop]
	if len(queue) == 0 {
		return ""
	}
	last := queue[len(queue)-1]
	if len(queue) == 1 {
		delete(pendingRedirects, hop)
	} else {
		pendingRedirects[hop] = queue[:len(queue)-1]
	}
	return last.ref
}

// linkRedirect is called by the client just before it follows a redirect from
// prev to req. It stamps req's context with the ref of the 3xx that led there,
// so the exchange for req records where it came from.
func linkRedirect(req *http.Request, prev *http.Request) {
	ref := claimPendingRedirect(prev.URL.String(), req.URL.String())
	if ref == "" {
		return
	}
	// WithContext returns a shallow copy, so the client sends the same request
	// it passed to CheckRedirect, now carrying the link.
	*req = *req.WithContext(withFromRef(req.Context(), ref))
}
