package adapters

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/model"
	"github.com/Indigo6415/Aperture/internal/wordlists"
)

func init() {
	register(&FeroxbusterAdapter{})
}

// FeroxbusterConfig is the node-configurable shape for a feroxbuster run.
type FeroxbusterConfig struct {
	URL         string            `json:"url"`
	Wordlist    string            `json:"wordlist"`
	Extensions  []string          `json:"extensions,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Method      string            `json:"method,omitempty"`
	Threads     int               `json:"threads,omitempty"`
	Depth       int               `json:"depth,omitempty"` // 0 = ferox default; 1 = no recursion
	NoRecursion bool              `json:"noRecursion,omitempty"`
	Timeout     int               `json:"timeoutSeconds,omitempty"`
	RateLimit   int               `json:"rateLimit,omitempty"` // feroxbuster --rate-limit: requests/sec across the whole run; 0 = unlimited
	ExtraArgs   []string          `json:"extraArgs,omitempty"`
}

type FeroxbusterAdapter struct{}

func (a *FeroxbusterAdapter) Name() string { return "feroxbuster" }

// feroxResponse mirrors the subset of feroxbuster's --json line schema
// (type == "response") that Aperture cares about.
type feroxResponse struct {
	Type          string            `json:"type"`
	URL           string            `json:"url"`
	Status        int               `json:"status"`
	Method        string            `json:"method"`
	ContentLength int               `json:"content_length"`
	LineCount     int               `json:"line_count"`
	WordCount     int               `json:"word_count"`
	Headers       map[string]string `json:"headers"`
}

// feroxProgressEvery is how many completed requests pass between progress
// callbacks, so a fast-running feroxbuster doesn't flood the hub with one
// event per request.
const feroxProgressEvery = 25

// feroxNoiseThreshold caps how many times an identical response shape
// (status/size/words/lines) gets surfaced as a Finding before it's treated
// as repeated noise -- almost always the same soft-404/error page --
// rather than a distinct discovery. feroxbuster normally suppresses this
// itself (its own auto-filter, "wildcard" detection), but that filter is
// disabled below via --dont-filter so every completed request still
// produces a "response" JSON line for accurate progress counting (see
// reportProgress); without a stand-in dedup check here, a large wordlist's
// uniform 404 page would otherwise flood the findings table with one row
// per wordlist entry.
const feroxNoiseThreshold = 3

// feroxSignature identifies a response's shape for the noise check above.
type feroxSignature struct {
	status, size, words, lines int
}

func (a *FeroxbusterAdapter) Run(ctx context.Context, config json.RawMessage, meta RunMeta, emit Emit, progress Progress) error {
	var cfg FeroxbusterConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return &ErrConfig{Adapter: a.Name(), Err: err}
	}
	if cfg.URL == "" {
		return &ErrConfig{Adapter: a.Name(), Err: fmt.Errorf("url is required")}
	}
	if cfg.Wordlist == "" {
		return &ErrConfig{Adapter: a.Name(), Err: fmt.Errorf("wordlist is required")}
	}
	// Refuse a wordlist/extensions combination feroxbuster couldn't run
	// without exhausting RAM building its job queue (see
	// checkFuzzRequestCount) -- recursion can only make the real total
	// larger than this base-level estimate, so this still catches it.
	if err := checkFuzzRequestCount(a.Name(), cfg.Wordlist, cfg.Extensions); err != nil {
		return err
	}

	// --no-state prevents feroxbuster from writing a state file to disk on
	// every run, which otherwise accumulates and clogs up the file system.
	//
	// --dont-filter disables feroxbuster's own auto-filter, which normally
	// stops emitting "response" JSON lines for a repeated response shape
	// (typically a uniform 404/error page) once it's seen a few times. That
	// filter is meant to declutter human-facing output, but it also means
	// "done" below -- counted from response lines -- would stall well
	// short of the real request count on any target where most missing
	// paths return an identical page, which is the common case. Passing
	// --dont-filter trades that filter for feroxNoiseThreshold's cruder
	// stand-in below, in exchange for "done" always reflecting real,
	// live request throughput instead of silently going stale mid-scan.
	args := []string{"-u", cfg.URL, "-w", cfg.Wordlist, "--json", "--silent", "--no-state", "--dont-filter"}
	if cfg.Method != "" {
		args = append(args, "-m", cfg.Method)
	}
	if cfg.Threads > 0 {
		args = append(args, "-t", strconv.Itoa(cfg.Threads))
	}
	if cfg.Depth > 0 {
		args = append(args, "-d", strconv.Itoa(cfg.Depth))
	}
	if cfg.NoRecursion {
		args = append(args, "-n")
	}
	if cfg.Timeout > 0 {
		args = append(args, "--timeout", strconv.Itoa(cfg.Timeout))
	}
	if cfg.RateLimit > 0 {
		args = append(args, "--rate-limit", strconv.Itoa(cfg.RateLimit))
	}
	if len(cfg.Extensions) > 0 {
		args = append(args, "-x", strings.Join(cfg.Extensions, ","))
	}
	for k, v := range cfg.Headers {
		args = append(args, "-H", fmt.Sprintf("%s: %s", k, v))
	}
	args = append(args, cfg.ExtraArgs...)

	cmd := exec.CommandContext(ctx, "feroxbuster", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("feroxbuster: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("feroxbuster: start: %w (is feroxbuster installed and on PATH?)", err)
	}

	// baseTotal is the same wordlist-derived request-count estimate ffuf
	// uses (see its "total" comment) -- feroxbuster's default status-code
	// filter is "all", so nearly every completed request produces a
	// "response" JSON line, and this estimate holds until recursion into a
	// found directory adds another wordlist's worth of requests on top.
	// 0 means the wordlist couldn't be counted, same as ffuf's fallback.
	baseTotal := 0
	if lines, err := wordlists.CountLines(cfg.Wordlist); err == nil {
		multiplier := 1
		if len(cfg.Extensions) > 0 {
			multiplier += len(cfg.Extensions)
		}
		baseTotal = lines * multiplier
	}

	// reportProgress grows the reported total to match done once recursion
	// pushes actual progress past baseTotal, so the bar keeps advancing
	// sensibly instead of overflowing past 100% -- but only when baseTotal
	// is known; baseTotal == 0 stays indeterminate throughout.
	reportProgress := func(done int) {
		if progress == nil {
			return
		}
		total := baseTotal
		if total > 0 && done > total {
			total = done
		}
		progress(done, total)
	}

	reportProgress(0)

	done := 0
	seen := map[feroxSignature]int{}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var resp feroxResponse
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			continue // ignore lines that aren't the response schema we expect
		}
		if resp.Type != "response" {
			continue
		}
		// Every "response" line is now one completed request (see
		// --dont-filter above), so this is a true, live count -- but that
		// also means it includes the repeated soft-404/error-page hits
		// feroxbuster used to hide; feroxNoiseThreshold below decides
		// which of those still become a Finding.
		done++
		sig := feroxSignature{resp.Status, resp.ContentLength, resp.WordCount, resp.LineCount}
		seen[sig]++
		if seen[sig] <= feroxNoiseThreshold {
			emit(model.Finding{
				ID:            newFindingID(),
				URL:           resp.URL,
				StatusCode:    resp.Status,
				ContentLength: resp.ContentLength,
				Words:         resp.WordCount,
				Lines:         resp.LineCount,
				ContentType:   resp.Headers["content-type"],
				RedirectLoc:   resp.Headers["location"],
				Method:        resp.Method,
				Headers:       resp.Headers,
				SourceTool:    a.Name(),
				SourceNodeID:  meta.NodeID,
				RunID:         meta.RunID,
				Timestamp:     time.Now(),
			})
		}
		if done%feroxProgressEvery == 0 {
			reportProgress(done)
		}
	}

	waitErr := cmd.Wait()
	if scanErr := scanner.Err(); scanErr != nil {
		return fmt.Errorf("feroxbuster: reading output: %w", scanErr)
	}
	reportProgress(done)
	if waitErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("feroxbuster: %w", waitErr)
	}
	return nil
}
