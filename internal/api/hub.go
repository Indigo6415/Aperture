package api

import (
	"sync"

	"github.com/Indigo6415/Aperture/internal/engine"
	"github.com/Indigo6415/Aperture/internal/model"
	"github.com/Indigo6415/Aperture/internal/recon"
)

// RunEvent is one message streamed to WebSocket clients watching either a
// flow run ("finding"/"status"/"done") or a domain scan ("check"/"scanRun"/
// "done"). The hub itself doesn't care which -- it's keyed by an arbitrary
// string ID (a runID or a scanID), so both kinds of watcher share the same
// plumbing.
type RunEvent struct {
	Type    string            `json:"type"` // "finding" | "status" | "progress" | "check" | "scanRun" | "done"
	NodeID  string            `json:"nodeId,omitempty"`
	Finding *model.Finding    `json:"finding,omitempty"`
	Check   *recon.Check      `json:"check,omitempty"`
	Status  engine.NodeStatus `json:"status,omitempty"`
	Message string            `json:"message,omitempty"`
	// Done/Total are set only on a "progress" event -- Total == 0 means the
	// total is unknowable (see adapters.Progress), so the frontend should
	// render an indeterminate indicator rather than a percentage.
	Done  int `json:"done,omitempty"`
	Total int `json:"total,omitempty"`
	// Kind/FlowID/RunID are set only on a "scanRun" event, published once
	// one of a scan's scanners (content discovery, subdomain bruteforce,
	// vhost bruteforce) has had its flow built and started, so the client
	// knows which run to open GET /ws/runs/{runId} against and which
	// scanner tab it belongs to.
	Kind   string `json:"kind,omitempty"`
	FlowID string `json:"flowId,omitempty"`
	RunID  string `json:"runId,omitempty"`
	// Targets is set only on a "scanRun" event for a scanner with a
	// per-target concept (content discovery) -- the same list stored on
	// the run (store.ScanRun.Targets), in the order used to build that
	// run's flow nodes (ffuf-<i>/feroxbuster-<i> for targets[i]), so a
	// client can group per-node progress into one bar per target without
	// fetching the flow itself.
	Targets []string `json:"targets,omitempty"`
}

// hub fans out RunEvents to any number of WebSocket subscribers per run.
// A run that finishes before a client connects is fine: the client only
// misses live events, and can always fetch accumulated findings via REST.
type hub struct {
	mu   sync.Mutex
	subs map[string]map[chan RunEvent]bool
}

func newHub() *hub {
	return &hub{subs: map[string]map[chan RunEvent]bool{}}
}

func (h *hub) subscribe(runID string) chan RunEvent {
	ch := make(chan RunEvent, 256)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.subs[runID] == nil {
		h.subs[runID] = map[chan RunEvent]bool{}
	}
	h.subs[runID][ch] = true
	return ch
}

func (h *hub) unsubscribe(runID string, ch chan RunEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.subs[runID], ch)
	if len(h.subs[runID]) == 0 {
		delete(h.subs, runID)
	}
	close(ch)
}

func (h *hub) publish(runID string, ev RunEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs[runID] {
		select {
		case ch <- ev:
		default:
			// Slow consumer: drop the event rather than block the run.
		}
	}
}
