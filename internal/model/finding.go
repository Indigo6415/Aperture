// Package model defines the common data model shared by every adapter, node,
// and API response in Aperture. A Finding is the single unit every tool
// output gets normalized into, so filters/merges/exports never need to know
// which scanner produced the data.
package model

import (
	"strconv"
	"time"
)

// TriageStatus is a finding's place in the operator's own review workflow --
// set after the fact via api.handleUpdateFindingTriage, never by an adapter.
// Every finding starts TriageNew the moment it's first persisted (see
// store.SaveFinding).
type TriageStatus string

const (
	TriageNew           TriageStatus = "new"
	TriageConfirmed     TriageStatus = "confirmed"
	TriageFalsePositive TriageStatus = "false_positive"
	TriageReported      TriageStatus = "reported"
)

// Finding is one normalized result (typically an HTTP response observed
// during a scan) flowing through the node graph.
type Finding struct {
	ID            string            `json:"id"`
	URL           string            `json:"url"`
	StatusCode    int               `json:"statusCode"`
	ContentLength int               `json:"contentLength"`
	Words         int               `json:"words"`
	Lines         int               `json:"lines"`
	ContentType   string            `json:"contentType,omitempty"`
	RedirectLoc   string            `json:"redirectLocation,omitempty"`
	Method        string            `json:"method,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	SourceTool    string            `json:"sourceTool"`
	SourceNodeID  string            `json:"sourceNodeId"`
	RunID         string            `json:"runId"`
	Tags          []string          `json:"tags,omitempty"`
	Timestamp     time.Time         `json:"timestamp"`
	// TriageStatus/TriageNote are the operator's own triage state on this
	// finding -- absent from whatever an adapter emits, filled in by
	// SaveFinding/ListFindings (defaulted to TriageNew) and updated
	// in-place by UpdateFindingTriage.
	TriageStatus TriageStatus `json:"triageStatus"`
	TriageNote   string       `json:"triageNote,omitempty"`
	// Detail fields, filled by adapters that identify the rule behind a result
	// (nuclei) and by checks that report how strongly they are sure. Template
	// is the rule ID, Severity the rule's own rating, Matcher the part of the
	// rule that fired, Reproduce a command that repeats the request, and
	// Confidence one of "confirmed", "likely", or "heuristic" (empty = not stated).
	Template   string `json:"template,omitempty"`
	Severity   string `json:"severity,omitempty"`
	Matcher    string `json:"matcher,omitempty"`
	Reproduce  string `json:"reproduce,omitempty"`
	Confidence string `json:"confidence,omitempty"`
}

// DedupKey identifies findings that represent the "same" result for the
// purposes of merge/dedup nodes: same URL + status code observed.
func (f Finding) DedupKey() string {
	return f.URL + "|" + strconv.Itoa(f.StatusCode)
}
