// Package model defines the common data model shared by every adapter, node,
// and API response in Aperture. A Finding is the single unit every tool
// output gets normalized into, so filters/merges/exports never need to know
// which scanner produced the data.
package model

import (
	"strconv"
	"time"
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
}

// DedupKey identifies findings that represent the "same" result for the
// purposes of merge/dedup nodes: same URL + status code observed.
func (f Finding) DedupKey() string {
	return f.URL + "|" + strconv.Itoa(f.StatusCode)
}
