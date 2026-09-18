package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/Indigo6415/Aperture/internal/adapters"
	"github.com/Indigo6415/Aperture/internal/engine"
	"github.com/Indigo6415/Aperture/internal/store"
	"github.com/Indigo6415/Aperture/internal/wordlists"
)

// Tool names a job can run. Every one of these is launched only when the
// user explicitly does so -- there is no automatic/background job creation
// anywhere in this package.
const (
	ToolFeroxbuster   = "feroxbuster"
	ToolFFufSubdomain = "ffuf-subdomain"
	ToolFFufVHost     = "ffuf-vhost"
	// ToolIdentify runs passive recon (internal/recon) directly rather than
	// an engine.Flow -- see runIdentifyJob in identify.go.
	ToolIdentify = "identify"
)

type startJobRequest struct {
	Tool    string             `json:"tool"`
	Targets []string           `json:"targets"`
	Options engine.ScanOptions `json:"options,omitempty"`
	// Scheme is the base scheme (http/https) used for a target that isn't
	// already a full URL -- feroxbuster and ffuf-subdomain only. Defaults
	// to "https".
	Scheme string `json:"scheme,omitempty"`
	// HostSuffix is ffuf-vhost only: the domain fuzzed into the Host
	// header while each target (an IP) is hit directly. A case Target is
	// just one string, and vhost fuzzing needs both an IP and a domain, so
	// this is a small field on the launch request rather than its own
	// Target.
	HostSuffix string `json:"hostSuffix,omitempty"`
}

type jobStartResult struct {
	JobID string `json:"jobId,omitempty"`
}

// resolveWordlist returns opts.Wordlist (an explicit filename the user
// chose for this job) when set, otherwise falls back to whatever's tagged
// cat.
func (s *Server) resolveWordlist(opts engine.ScanOptions, cat wordlists.Category, fallback string) string {
	if opts.Wordlist != "" {
		return filepath.Join(s.wordlistsDir, opts.Wordlist)
	}
	path, err := wordlists.CombinedForCategory(s.wordlistsDir, cat, fallback)
	if err != nil {
		return filepath.Join(s.wordlistsDir, fallback)
	}
	return path
}

// dedupeTargets collapses requested down to its unique values, case
// insensitively, preserving order. A target already covered by a
// running-or-succeeded job is intentionally *not* filtered out here --
// pressing run is always allowed to launch another pass over the same
// target (a new wordlist, or just wanting to scan it again).
func dedupeTargets(requested []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(requested))
	for _, t := range requested {
		key := strings.ToLower(t)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
	}
	return out
}

// buildToolFlow assembles the engine.Flow for one job, dispatching on tool.
// Every branch fans out one source node per target into a shared merge
// (dedup) + table sink via buildFanoutFlow.
func (s *Server) buildToolFlow(tool string, targets []string, req startJobRequest) (engine.Flow, error) {
	scheme := req.Scheme
	if scheme == "" {
		scheme = "https"
	}
	opts := req.Options.Resolved()

	switch tool {
	case ToolFeroxbuster:
		wordlistPath := s.resolveWordlist(opts, wordlists.CategoryDirectories, wordlists.DefaultName)
		extensions, _ := wordlists.ExtensionsForCategory(s.wordlistsDir)
		return buildFanoutFlow("Feroxbuster", targets, func(i int, target string) (engine.NodeKind, string, json.RawMessage) {
			base := target
			if !strings.Contains(base, "://") {
				base = scheme + "://" + base
			}
			cfg, _ := json.Marshal(adapters.FeroxbusterConfig{
				URL: base + "/", Wordlist: wordlistPath, Extensions: extensions,
				Threads: opts.Threads, Timeout: opts.TimeoutSeconds, RateLimit: opts.RateLimit,
				NoRecursion: !opts.Recursive,
			})
			return engine.KindFeroxbuster, "feroxbuster: " + target, cfg
		}), nil

	case ToolFFufSubdomain:
		wordlistPath := s.resolveWordlist(opts, wordlists.CategorySubdomains, wordlists.SubdomainsDefaultName)
		return buildFanoutFlow("FFuF subdomain enum", targets, func(i int, target string) (engine.NodeKind, string, json.RawMessage) {
			cfg, _ := json.Marshal(adapters.FFufConfig{
				URL: scheme + "://FUZZ." + target + "/", Wordlist: wordlistPath, AutoCalibrate: true,
				Threads: opts.Threads, Timeout: opts.TimeoutSeconds, RateLimit: opts.RateLimit,
			})
			return engine.KindFFuf, "ffuf: " + target, cfg
		}), nil

	case ToolFFufVHost:
		if req.HostSuffix == "" {
			return engine.Flow{}, fmt.Errorf("ffuf-vhost: hostSuffix is required")
		}
		wordlistPath := s.resolveWordlist(opts, wordlists.CategorySubdomains, wordlists.SubdomainsDefaultName)
		return buildFanoutFlow("FFuF vhost enum", targets, func(i int, target string) (engine.NodeKind, string, json.RawMessage) {
			cfg, _ := json.Marshal(adapters.FFufConfig{
				URL: scheme + "://" + target + "/", Wordlist: wordlistPath,
				Headers: map[string]string{"Host": "FUZZ." + req.HostSuffix}, AutoCalibrate: true,
				Threads: opts.Threads, Timeout: opts.TimeoutSeconds, RateLimit: opts.RateLimit,
			})
			return engine.KindFFuf, "ffuf: " + target, cfg
		}), nil

	default:
		return engine.Flow{}, fmt.Errorf("job: unknown tool %q", tool)
	}
}

// buildFanoutFlow wires one source node per target (built by nodeFor) into
// a shared merge(dedup)+table sink -- the fan-out/merge/table pattern every
// tool flow uses.
func buildFanoutFlow(name string, targets []string, nodeFor func(i int, target string) (engine.NodeKind, string, json.RawMessage)) engine.Flow {
	nodes := make([]engine.Node, 0, len(targets)+2)
	edges := make([]engine.Edge, 0, len(targets)+1)
	y := 40.0
	for i, target := range targets {
		kind, label, cfg := nodeFor(i, target)
		nodeID := fmt.Sprintf("%s-%d", kind, i)
		nodes = append(nodes, engine.Node{ID: nodeID, Kind: kind, Label: label, Config: cfg, Position: &engine.Position{X: 40, Y: y}})
		edges = append(edges, engine.Edge{ID: "e-" + nodeID + "-merge", From: nodeID, To: "merge"})
		y += 120
	}

	mergeCfg, _ := json.Marshal(engine.MergeConfig{Dedup: true})
	nodes = append(nodes,
		engine.Node{ID: "merge", Kind: engine.KindMerge, Label: "merge", Config: mergeCfg, Position: &engine.Position{X: 340, Y: 120}},
		engine.Node{ID: "table", Kind: engine.KindTable, Label: "results", Position: &engine.Position{X: 600, Y: 120}},
	)
	edges = append(edges, engine.Edge{ID: "e-merge-table", From: "merge", To: "table"})

	return engine.Flow{Name: name, Nodes: nodes, Edges: edges}
}

// handleStartJob launches one tool against one or more targets -- the only
// way any tool ever runs in Aperture. A target already covered by a
// running-or-succeeded job of the same tool is launched again anyway --
// pressing run is always allowed to start a fresh pass.
func (s *Server) handleStartJob(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("id")
	if _, err := s.store.GetCase(caseID); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	var req startJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(req.Targets) == 0 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("job: at least one target is required"))
		return
	}

	targets := dedupeTargets(req.Targets)

	// Identify has no engine.Flow underneath -- it runs internal/recon
	// directly against each target (see runIdentifyJob) -- so its job row
	// is created without a flow_id/run_id and it skips buildToolFlow
	// entirely.
	if req.Tool == ToolIdentify {
		jobID := newID()
		if err := s.store.CreateJob(store.Job{ID: jobID, CaseID: caseID, Tool: req.Tool, Targets: targets, Status: store.RunRunning}); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		go s.runIdentifyJob(caseID, jobID, targets)
		writeJSON(w, http.StatusAccepted, jobStartResult{JobID: jobID})
		return
	}

	flow, err := s.buildToolFlow(req.Tool, targets, req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	flow.ID = newID()
	if err := s.store.SaveFlow(flow); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	jobID := newID()
	runID := newID()
	if err := s.store.CreateRun(runID, flow.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	configJSON, _ := json.Marshal(req)
	if err := s.store.CreateJob(store.Job{
		ID: jobID, CaseID: caseID, Tool: req.Tool, FlowID: flow.ID, RunID: runID,
		Targets: targets, Config: string(configJSON), Status: store.RunRunning,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	go s.executeToolJob(flow, jobID, runID)

	writeJSON(w, http.StatusAccepted, jobStartResult{JobID: jobID})
}

func (s *Server) handleListCaseJobs(w http.ResponseWriter, r *http.Request) {
	jobs, err := s.store.ListCaseJobs(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	resp := make([]jobResponse, len(jobs))
	for i, j := range jobs {
		resp[i] = jobResponse{Job: j, Nodes: s.jobNodeDetails(j)}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request) {
	job, err := s.store.GetJob(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, jobResponse{Job: job, Nodes: s.jobNodeDetails(job)})
}

// jobResponse wraps a store.Job with its per-node scan details for the API
// response. Nodes is derived on read from the job's saved flow rather than
// stored on the job row, so it always reflects the config each node was
// actually launched with.
type jobResponse struct {
	store.Job
	Nodes []JobNodeDetail `json:"nodes,omitempty"`
}

// JobNodeDetail summarizes one target node's actual scan config -- which
// wordlist it's fuzzing with, how many candidate requests that implies, and
// any tuning that was applied -- so the UI (see TargetProgressPanel) can show
// this without the caller needing to fetch and decode the raw flow itself.
type JobNodeDetail struct {
	NodeID         string   `json:"nodeId"`
	Target         string   `json:"target"`
	Wordlist       string   `json:"wordlist,omitempty"`
	Extensions     []string `json:"extensions,omitempty"`
	Candidates     int      `json:"candidates,omitempty"`
	Threads        int      `json:"threads,omitempty"`
	TimeoutSeconds int      `json:"timeoutSeconds,omitempty"`
	RateLimit      int      `json:"rateLimit,omitempty"`
}

// jobNodeDetails derives each source node's scan config from a job's saved
// flow. Node IDs match TargetProgressPanel's "<kind>-<index>" key scheme
// one to one (see buildFanoutFlow), so the frontend can look a node up by
// the same key it already tracks live progress/status under. A job with no
// flow (e.g. identify) or a flow that fails to load returns nil rather than
// erroring the whole response.
func (s *Server) jobNodeDetails(job store.Job) []JobNodeDetail {
	if job.FlowID == "" {
		return nil
	}
	flow, err := s.store.GetFlow(job.FlowID)
	if err != nil {
		return nil
	}
	var details []JobNodeDetail
	for _, n := range flow.Nodes {
		switch n.Kind {
		case engine.KindFeroxbuster:
			var cfg adapters.FeroxbusterConfig
			if json.Unmarshal(n.Config, &cfg) != nil {
				continue
			}
			details = append(details, JobNodeDetail{
				NodeID: n.ID, Target: cfg.URL, Wordlist: filepath.Base(cfg.Wordlist),
				Extensions: cfg.Extensions, Candidates: candidateCount(cfg.Wordlist, cfg.Extensions),
				Threads: cfg.Threads, TimeoutSeconds: cfg.Timeout, RateLimit: cfg.RateLimit,
			})
		case engine.KindFFuf:
			var cfg adapters.FFufConfig
			if json.Unmarshal(n.Config, &cfg) != nil {
				continue
			}
			details = append(details, JobNodeDetail{
				NodeID: n.ID, Target: cfg.URL, Wordlist: filepath.Base(cfg.Wordlist),
				Extensions: cfg.Extensions, Candidates: candidateCount(cfg.Wordlist, cfg.Extensions),
				Threads: cfg.Threads, TimeoutSeconds: cfg.Timeout, RateLimit: cfg.RateLimit,
			})
		}
	}
	return details
}

// candidateCount estimates the number of requests a wordlist+extensions
// combination will fuzz: one per wordlist line, plus one more per extension
// per line -- mirroring the estimate adapters/ffuf.go and
// adapters.checkFuzzRequestCount both compute from the same wordlist file. A
// failure to count the wordlist is non-fatal (0 == unknown).
func candidateCount(wordlistPath string, extensions []string) int {
	lines, err := wordlists.CountLines(wordlistPath)
	if err != nil {
		return 0
	}
	return lines * (1 + len(extensions))
}
