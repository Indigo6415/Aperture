package engine

import (
	"context"
	"fmt"
	"sync"

	"github.com/Indigo6415/Aperture/internal/adapters"
	"github.com/Indigo6415/Aperture/internal/model"
)

// ResultFunc is called for every Finding a node produces, as it happens.
type ResultFunc func(nodeID string, f model.Finding)

// StatusFunc is called whenever a node's lifecycle state changes.
type StatusFunc func(nodeID string, status NodeStatus, message string)

// Engine executes Flows.
type Engine struct{}

func New() *Engine { return &Engine{} }

// Execute runs every node in flow concurrently, wiring edges as buffered
// channels so results stream downstream as soon as they're produced
// instead of waiting for an upstream node to fully finish. It blocks until
// every node has finished (or ctx is cancelled) and returns the first
// node error encountered, if any.
func (e *Engine) Execute(ctx context.Context, flow Flow, runID string, onResult ResultFunc, onStatus StatusFunc) error {
	if len(flow.Nodes) == 0 {
		return nil
	}

	outgoing := map[string][]Edge{}
	incoming := map[string][]Edge{}
	indegree := map[string]int{}
	for _, n := range flow.Nodes {
		indegree[n.ID] = 0
	}
	for _, ed := range flow.Edges {
		outgoing[ed.From] = append(outgoing[ed.From], ed)
		incoming[ed.To] = append(incoming[ed.To], ed)
		indegree[ed.To]++
	}

	if err := checkAcyclic(flow, outgoing, indegree); err != nil {
		return err
	}

	// produced[id]: raw output of node id, before fan-out to its edges.
	produced := make(map[string]chan model.Finding, len(flow.Nodes))
	for _, n := range flow.Nodes {
		produced[n.ID] = make(chan model.Finding, 256)
	}
	// edgeCh[edge.ID]: one subscriber channel per outgoing edge, so a node
	// with multiple downstream consumers doesn't have one slow reader
	// starve the others.
	edgeCh := make(map[string]chan model.Finding, len(flow.Edges))
	for _, ed := range flow.Edges {
		edgeCh[ed.ID] = make(chan model.Finding, 256)
	}

	var fanoutWG sync.WaitGroup
	for _, n := range flow.Nodes {
		outs := outgoing[n.ID]
		src := produced[n.ID]
		fanoutWG.Add(1)
		go func() {
			defer fanoutWG.Done()
			defer func() {
				for _, ed := range outs {
					close(edgeCh[ed.ID])
				}
			}()
			for f := range src {
				for _, ed := range outs {
					select {
					case edgeCh[ed.ID] <- f:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	var wg sync.WaitGroup
	errCh := make(chan error, len(flow.Nodes))
	for _, n := range flow.Nodes {
		n := n
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer close(produced[n.ID])

			onStatus(n.ID, StatusRunning, "")
			emit := func(f model.Finding) { onResult(n.ID, f) }
			err := e.runNode(ctx, n, runID, incoming[n.ID], edgeCh, produced[n.ID], emit)
			if err != nil && ctx.Err() == nil {
				onStatus(n.ID, StatusFailed, err.Error())
				errCh <- fmt.Errorf("node %s (%s): %w", n.ID, n.Kind, err)
				return
			}
			onStatus(n.ID, StatusSucceeded, "")
		}()
	}

	wg.Wait()
	fanoutWG.Wait()
	close(errCh)

	var firstErr error
	for err := range errCh {
		if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (e *Engine) runNode(ctx context.Context, n Node, runID string, in []Edge, edgeCh map[string]chan model.Finding, out chan<- model.Finding, emit func(model.Finding)) error {
	inputs := make([]<-chan model.Finding, len(in))
	for i, ed := range in {
		inputs[i] = edgeCh[ed.ID]
	}

	if n.Kind.IsSource() {
		adapter, ok := adapters.Registry[string(n.Kind)]
		if !ok {
			return fmt.Errorf("unknown source node kind %q", n.Kind)
		}
		return adapter.Run(ctx, n.Config, adapters.RunMeta{RunID: runID, NodeID: n.ID}, func(f model.Finding) {
			_ = sendAndEmit(ctx, out, f, emit)
		})
	}

	switch n.Kind {
	case KindFilter:
		return runFilter(ctx, n, fanIn(ctx, inputs), out, emit)
	case KindMerge:
		return runMerge(ctx, n, inputs, out, emit)
	case KindTable:
		return runTable(ctx, n, fanIn(ctx, inputs), out, emit)
	case KindExport:
		return runExport(ctx, n, fanIn(ctx, inputs), out, emit)
	default:
		return fmt.Errorf("unknown node kind %q", n.Kind)
	}
}

// checkAcyclic runs Kahn's algorithm purely to detect cycles; execution
// order itself is driven by channel synchronization, not this ordering.
func checkAcyclic(flow Flow, outgoing map[string][]Edge, indegree map[string]int) error {
	work := make(map[string]int, len(indegree))
	for k, v := range indegree {
		work[k] = v
	}
	queue := make([]string, 0, len(flow.Nodes))
	for id, d := range work {
		if d == 0 {
			queue = append(queue, id)
		}
	}
	visited := 0
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		visited++
		for _, ed := range outgoing[id] {
			work[ed.To]--
			if work[ed.To] == 0 {
				queue = append(queue, ed.To)
			}
		}
	}
	if visited != len(flow.Nodes) {
		return fmt.Errorf("flow graph contains a cycle")
	}
	return nil
}
