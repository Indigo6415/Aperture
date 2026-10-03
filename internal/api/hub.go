package api

import (
	"encoding/json"
	"sync"

	"github.com/Indigo6415/Aperture/internal/apienum"
	"github.com/Indigo6415/Aperture/internal/domainscan"
	"github.com/Indigo6415/Aperture/internal/engine"
	"github.com/Indigo6415/Aperture/internal/model"
	"github.com/Indigo6415/Aperture/internal/probescan"
	"github.com/Indigo6415/Aperture/internal/recon"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
)

// RunEvent is one message streamed to WebSocket clients watching one job,
// whatever its tool: engine-backed jobs (feroxbuster/ffuf-subdomain/
// ffuf-vhost) emit "finding"/"status"/"progress"; an identify job emits
// "check"; a probe scan emits "module" as each check module finishes; a
// domain scan emits "domainModule" the same way; every job emits a terminal
// "done". The hub itself doesn't care which -- it's keyed by an arbitrary
// string ID (a jobID, a probe scan ID, or a domain scan ID), so every kind
// of watcher shares the same plumbing. There's no "a new job started"
// announcement event: every job is launched explicitly by the client, which
// already has its ID synchronously from the POST response that created it.
type RunEvent struct {
	Type    string            `json:"type"` // "finding" | "status" | "progress" | "check" | "module" | "domainModule" | "apiEnumPhase" | "apiEnumRoute" | "done"
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

	// Module is set on a "module" event: one probe check module just
	// finished, findings included. ProbeTarget/ProbeHealth are set
	// alongside Status on a probe scan's terminal "done" event, since a
	// probe scan has no case/job row a REST fallback could re-fetch them
	// from.
	Module      *probescan.ModuleResult  `json:"module,omitempty"`
	ProbeTarget *probescan.Target        `json:"probeTarget,omitempty"`
	ProbeHealth *probescan.HealthSummary `json:"probeHealth,omitempty"`

	// DomainModule/DomainTarget are domainscan's counterparts to Module/
	// ProbeTarget above -- see handleWatchDomainScan/runDomainScan in
	// handlers_domainscan.go. A domain scan has no health summary of its
	// own (every module does its own reachability handling as part of
	// crawling), so there's no DomainHealth to go with it.
	DomainModule *domainscan.ModuleResult `json:"domainModule,omitempty"`
	DomainTarget *domainscan.Target       `json:"domainTarget,omitempty"`

	// ApiEnumPhase/ApiEnumRoute are the API enumerator's own progress
	// events: ApiEnumPhase reports coarse phase progress (spec discovery,
	// GraphQL, crawl, brute force, characterization -- see
	// apienum.PhaseEvent), ApiEnumRoute fires once per route as its
	// characterization finishes, letting the UI's route tree fill in live
	// rather than waiting for the whole run. The terminal "done" event
	// carries everything else a case scan needs to re-render without
	// re-running the scan: the resolved target, schema/GraphQL summaries,
	// the injection-point staging list, and the run's own stats -- Routes
	// themselves are deliberately not repeated here, since the client has
	// already accumulated every one of them from ApiEnumRoute events (same
	// "collect from the stream, don't resend" posture as Module/
	// DomainModule above).
	ApiEnumPhase           *apienum.PhaseEvent      `json:"apiEnumPhase,omitempty"`
	ApiEnumRoute           *apienum.Route           `json:"apiEnumRoute,omitempty"`
	ApiEnumTarget          *apienum.Target          `json:"apiEnumTarget,omitempty"`
	ApiEnumSchema          *apienum.SchemaInfo      `json:"apiEnumSchema,omitempty"`
	ApiEnumGraphQL         *apienum.GraphQLSummary  `json:"apiEnumGraphql,omitempty"`
	ApiEnumInjectionPoints []apienum.InjectionPoint `json:"apiEnumInjectionPoints,omitempty"`
	ApiEnumStats           *apienum.Stats           `json:"apiEnumStats,omitempty"`

	// Checks is set on a "plan" event: checks a scan has registered (see
	// internal/scanprogress). CheckID is set on "checkStart"/"checkDone";
	// Findings is set on "checkDone" (Message carries its error, if any).
	// A "phase" event carries its text in Message. Result is set on a
	// streamed scan's terminal "done" event -- the full response the
	// scanner returned, for the frontend to hand to its results view.
	Checks   []scanprogress.Check `json:"checks,omitempty"`
	CheckID  string               `json:"checkId,omitempty"`
	Findings int                  `json:"findings,omitempty"`
	Result   json.RawMessage      `json:"result,omitempty"`
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
