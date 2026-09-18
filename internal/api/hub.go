package api

import (
	"sync"

	"github.com/Indigo6415/Aperture/internal/engine"
	"github.com/Indigo6415/Aperture/internal/model"
	"github.com/Indigo6415/Aperture/internal/recon"
)

// RunEvent is one message streamed to WebSocket clients watching one job,
// whatever its tool: engine-backed jobs (feroxbuster/ffuf-subdomain/
// ffuf-vhost) emit "finding"/"status"/"progress"; an identify job emits
// "check"; every job emits a terminal "done". The hub itself doesn't care
// which -- it's keyed by an arbitrary string ID (a jobID), so every kind of
// watcher shares the same plumbing. There's no "a new job started"
// announcement event: every job is launched explicitly by the client, which
// already has its ID synchronously from the POST response that created it.
type RunEvent struct {
	Type    string            `json:"type"` // "finding" | "status" | "progress" | "check" | "done"
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
}

// hub fans out RunEvents to any number of WebSocket subscribers per job.
// A job that finishes before a client connects is fine: the client only
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
