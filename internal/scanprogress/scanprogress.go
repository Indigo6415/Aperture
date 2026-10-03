// Package scanprogress is how a scanner reports its own progress while it
// runs, independent of how that progress reaches anyone. Every scanner that
// runs a battery of checks against a target (one per parameter, path,
// module, ...) takes an optional Reporter and calls it as the work happens;
// the API layer supplies a Reporter that streams those calls to the browser
// over the scan's WebSocket (see internal/api/scan_stream.go), and a scanner
// run with no one watching simply gets Discard.
//
// The contract is deliberately small so every scanner reports the same way:
// Plan registers checks (and may be called again later in the run, when a
// scanner discovers more work -- a crawl turning up new parameters, say),
// Start/Done bracket each check's own execution, and Phase is an optional
// human-readable note about what the scan is doing as a whole. Because
// Plan can grow the set, a check total is only ever as large as what the
// scanner has actually committed to so far -- nothing is guessed up front.
package scanprogress

import "sync"

// Check is one unit of work a scan will run. ID is stable for the life of
// the scan and is what Start/Done refer back to; Label is what a UI shows
// for it (a parameter name, a path, a module name); Group optionally names
// the category it belongs to (e.g. "Cloud metadata"), so a UI can
// distinguish two checks against the same parameter that come from
// different modules.
type Check struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Group string `json:"group,omitempty"`
}

// Reporter receives a scan's progress as it happens. Every method may be
// called concurrently from many goroutines -- scanners fan checks out in
// parallel, so implementations must be safe for that.
type Reporter interface {
	// Plan registers one or more checks. Calling it again with new checks
	// adds to the set rather than replacing it.
	Plan(checks ...Check)
	// Start marks the check with id as now running.
	Start(id string)
	// Done marks the check with id as finished, recording how many findings
	// it produced and, when the check itself failed to run cleanly, err. A
	// check that errored still counts as finished -- it isn't going to make
	// further progress either way.
	Done(id string, findings int, err error)
	// Phase reports a coarse, scan-wide status line -- "Crawling same-origin
	// pages", "Waiting for out-of-band callbacks" -- for display alongside
	// the per-check progress.
	Phase(message string)
}

// discard is the Reporter used when nothing is watching a scan.
type discard struct{}

func (discard) Plan(...Check)           {}
func (discard) Start(string)            {}
func (discard) Done(string, int, error) {}
func (discard) Phase(string)            {}

// Discard is a Reporter that drops every call. It's what a scanner falls
// back to when its caller didn't supply one.
var Discard Reporter = discard{}

// Or returns r, or Discard when r is nil -- so scanners can call their
// Reporter unconditionally instead of checking for nil before every call.
func Or(r Reporter) Reporter {
	if r == nil {
		return Discard
	}
	return r
}

// Each runs fn once for every item, with at most limit calls in flight (a
// limit <= 0 means no bound), and reports each item as its own check. Every
// check is planned up front, all at once, so the whole grid is visible before
// anything runs. An item's check only gets Start-ed once it actually holds one
// of the limit slots, so anything still waiting for a slot correctly reads as
// queued rather than testing.
//
// fn returns how many findings the item produced, plus an error when the
// item itself couldn't run cleanly -- either way the check counts as finished.
// Each blocks until every item has finished.
func Each[T any](rep Reporter, limit int, items []T, check func(T) Check, fn func(T) (int, error)) {
	rep = Or(rep)

	checks := make([]Check, len(items))
	for i, item := range items {
		checks[i] = check(item)
	}
	rep.Plan(checks...)

	var wg sync.WaitGroup
	var slots chan struct{}
	if limit > 0 {
		slots = make(chan struct{}, limit)
	}
	for i, item := range items {
		wg.Add(1)
		go func(id string, item T) {
			defer wg.Done()
			// Hold a slot for the whole check. A nil slots channel (no limit)
			// makes both operations below no-ops, so unbounded fan-out costs
			// nothing extra here.
			if slots != nil {
				slots <- struct{}{}
				defer func() { <-slots }()
			}

			rep.Start(id)
			n, err := fn(item)
			rep.Done(id, n, err)
		}(checks[i].ID, item)
	}
	wg.Wait()
}
