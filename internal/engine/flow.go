// Package engine executes a Flow: a DAG of scan/filter/transform nodes
// wired together by edges that carry model.Finding downstream, streaming
// partial results as they arrive rather than waiting for each node to
// fully complete.
package engine

import "encoding/json"

// NodeKind identifies what a node does. Source kinds ("ffuf",
// "feroxbuster") map 1:1 to an adapters.Adapter; the rest are built-in
// transform/sink kinds implemented in this package.
type NodeKind string

const (
	KindFFuf        NodeKind = "ffuf"
	KindFeroxbuster NodeKind = "feroxbuster"
	KindNmap        NodeKind = "nmap"
	KindNuclei      NodeKind = "nuclei"
	KindFilter      NodeKind = "filter"
	KindMerge       NodeKind = "merge"
	KindTable       NodeKind = "table"
	KindExport      NodeKind = "export"
)

// IsSource reports whether a node kind is a scan node (no inputs, wraps an
// external tool via the adapters package) as opposed to a filter/merge/sink.
func (k NodeKind) IsSource() bool {
	return k == KindFFuf || k == KindFeroxbuster || k == KindNmap || k == KindNuclei
}

// Position is purely UI metadata (canvas layout) round-tripped through the
// backend so the frontend doesn't need a separate place to persist it.
type Position struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// Node is one step in a Flow. Config is kind-specific and decoded by
// whichever executor handles that kind.
type Node struct {
	ID       string          `json:"id"`
	Kind     NodeKind        `json:"kind"`
	Label    string          `json:"label,omitempty"`
	Config   json.RawMessage `json:"config,omitempty"`
	Position *Position       `json:"position,omitempty"`
}

// Edge connects one node's output to another node's input.
type Edge struct {
	ID   string `json:"id"`
	From string `json:"from"`
	To   string `json:"to"`
}

// Flow is a saved, runnable graph.
type Flow struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// NodeStatus is the lifecycle state of a node within one run, reported to
// the UI so it can light up nodes as they progress.
type NodeStatus string

const (
	StatusPending   NodeStatus = "pending"
	StatusRunning   NodeStatus = "running"
	StatusSucceeded NodeStatus = "succeeded"
	StatusFailed    NodeStatus = "failed"
	StatusCancelled NodeStatus = "cancelled"
)
