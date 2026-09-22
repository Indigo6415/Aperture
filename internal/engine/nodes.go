package engine

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"sync"

	"github.com/Indigo6415/Aperture/internal/adapters"
	"github.com/Indigo6415/Aperture/internal/model"
)

// FilterConfig configures a filter node. A zero-value field means "no
// constraint" for that dimension; all set constraints must pass (AND).
type FilterConfig struct {
	StatusCodes      []int    `json:"statusCodes,omitempty"`
	StatusExclude    []int    `json:"statusExclude,omitempty"`
	MinContentLength *int     `json:"minContentLength,omitempty"`
	MaxContentLength *int     `json:"maxContentLength,omitempty"`
	MinWords         *int     `json:"minWords,omitempty"`
	MaxWords         *int     `json:"maxWords,omitempty"`
	MinLines         *int     `json:"minLines,omitempty"`
	MaxLines         *int     `json:"maxLines,omitempty"`
	URLRegex         string   `json:"urlRegex,omitempty"`
	Tags             []string `json:"tags,omitempty"`
}

func compileFilter(raw json.RawMessage) (func(model.Finding) bool, error) {
	var cfg FilterConfig
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, fmt.Errorf("filter: invalid config: %w", err)
		}
	}

	var urlRe *regexp.Regexp
	if cfg.URLRegex != "" {
		re, err := regexp.Compile(cfg.URLRegex)
		if err != nil {
			return nil, fmt.Errorf("filter: invalid urlRegex: %w", err)
		}
		urlRe = re
	}

	statusAllow := map[int]bool{}
	for _, c := range cfg.StatusCodes {
		statusAllow[c] = true
	}
	statusDeny := map[int]bool{}
	for _, c := range cfg.StatusExclude {
		statusDeny[c] = true
	}

	return func(f model.Finding) bool {
		if len(statusAllow) > 0 && !statusAllow[f.StatusCode] {
			return false
		}
		if statusDeny[f.StatusCode] {
			return false
		}
		if cfg.MinContentLength != nil && f.ContentLength < *cfg.MinContentLength {
			return false
		}
		if cfg.MaxContentLength != nil && f.ContentLength > *cfg.MaxContentLength {
			return false
		}
		if cfg.MinWords != nil && f.Words < *cfg.MinWords {
			return false
		}
		if cfg.MaxWords != nil && f.Words > *cfg.MaxWords {
			return false
		}
		if cfg.MinLines != nil && f.Lines < *cfg.MinLines {
			return false
		}
		if cfg.MaxLines != nil && f.Lines > *cfg.MaxLines {
			return false
		}
		if urlRe != nil && !urlRe.MatchString(f.URL) {
			return false
		}
		if len(cfg.Tags) > 0 {
			found := false
			for _, want := range cfg.Tags {
				for _, have := range f.Tags {
					if want == have {
						found = true
						break
					}
				}
			}
			if !found {
				return false
			}
		}
		return true
	}, nil
}

func runFilter(ctx context.Context, node Node, in <-chan model.Finding, out chan<- model.Finding, emit func(model.Finding)) error {
	keep, err := compileFilter(node.Config)
	if err != nil {
		return err
	}
	for f := range in {
		if !keep(f) {
			continue
		}
		f.SourceNodeID = node.ID
		if err := sendAndEmit(ctx, out, f, emit); err != nil {
			return err
		}
	}
	return nil
}

// MergeConfig configures a merge node: how multiple upstream Finding
// streams are combined into one.
type MergeConfig struct {
	Dedup bool `json:"dedup,omitempty"`
}

// sendAndEmit forwards f downstream and reports it to emit, or returns
// ctx.Err() if the run was cancelled first.
func sendAndEmit(ctx context.Context, out chan<- model.Finding, f model.Finding, emit func(model.Finding)) error {
	select {
	case out <- f:
		emit(f)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// fanIn combines N read-only channels into one, closing the result once
// every input has closed.
func fanIn(ctx context.Context, ins []<-chan model.Finding) <-chan model.Finding {
	out := make(chan model.Finding)
	var wg sync.WaitGroup
	wg.Add(len(ins))
	for _, in := range ins {
		go func(in <-chan model.Finding) {
			defer wg.Done()
			for f := range in {
				select {
				case out <- f:
				case <-ctx.Done():
					return
				}
			}
		}(in)
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

func runMerge(ctx context.Context, node Node, ins []<-chan model.Finding, out chan<- model.Finding, emit func(model.Finding)) error {
	var cfg MergeConfig
	if len(node.Config) > 0 {
		if err := json.Unmarshal(node.Config, &cfg); err != nil {
			return fmt.Errorf("merge: invalid config: %w", err)
		}
	}

	seen := map[string]bool{}
	merged := fanIn(ctx, ins)
	for f := range merged {
		if cfg.Dedup {
			key := f.DedupKey()
			if seen[key] {
				continue
			}
			seen[key] = true
		}
		f.SourceNodeID = node.ID
		if err := sendAndEmit(ctx, out, f, emit); err != nil {
			return err
		}
	}
	return nil
}

// runTable is a pass-through sink: it exists so the UI has a stable node
// to attach a live results table to. Every finding reaching it is reported
// via emit and forwarded unchanged, so table nodes can still feed further
// nodes (e.g. an export node) downstream.
func runTable(ctx context.Context, node Node, in <-chan model.Finding, out chan<- model.Finding, emit func(model.Finding)) error {
	for f := range in {
		if err := sendAndEmit(ctx, out, f, emit); err != nil {
			return err
		}
	}
	return nil
}

// HttpxVerifyConfig configures an httpx-verify node -- see runHttpxVerify.
type HttpxVerifyConfig struct {
	Headers   map[string]string `json:"headers,omitempty"`
	Threads   int               `json:"threads,omitempty"`
	Timeout   int               `json:"timeoutSeconds,omitempty"`
	RateLimit int               `json:"rateLimit,omitempty"`
}

// runHttpxVerify is subfinder's second stage: subdomain enumeration only
// ever tells you a name was seen by some OSINT source, not that anything
// is actually listening there today, so every hostname the upstream
// node(s) produce is collected here (not forwarded as-is) until their
// stream closes, then probed in one batched httpx run -- emitting a real
// status/size/words/lines Finding for every host that's actually alive,
// and silently dropping the rest, exactly like piping subfinder into
// httpx on the command line. Hostnames are de-duplicated and stripped down
// to bare host (no scheme/path) before probing so httpx's own default
// scheme-negotiation (try https, fall back to http) decides how each one
// is actually reached, rather than locking every target to whatever
// scheme the upstream node happened to emit.
func runHttpxVerify(ctx context.Context, node Node, in <-chan model.Finding, out chan<- model.Finding, emit func(model.Finding), progress func(done, total int), runID string) error {
	var cfg HttpxVerifyConfig
	if len(node.Config) > 0 {
		if err := json.Unmarshal(node.Config, &cfg); err != nil {
			return fmt.Errorf("httpx-verify: invalid config: %w", err)
		}
	}

	seen := map[string]bool{}
	var targets []string
	for f := range in {
		host := f.URL
		if u, err := url.Parse(f.URL); err == nil && u.Host != "" {
			host = u.Host
		}
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		targets = append(targets, host)
	}
	if len(targets) == 0 {
		if progress != nil {
			progress(0, 0)
		}
		return nil
	}

	httpxCfg, err := json.Marshal(adapters.HttpxConfig{
		Targets: targets, Headers: cfg.Headers,
		Threads: cfg.Threads, Timeout: cfg.Timeout, RateLimit: cfg.RateLimit,
	})
	if err != nil {
		return fmt.Errorf("httpx-verify: marshal config: %w", err)
	}

	adapter, ok := adapters.Registry["httpx"]
	if !ok {
		return fmt.Errorf("httpx-verify: httpx adapter not registered")
	}
	return adapter.Run(ctx, httpxCfg, adapters.RunMeta{RunID: runID, NodeID: node.ID}, func(f model.Finding) {
		_ = sendAndEmit(ctx, out, f, emit)
	}, adapters.Progress(progress))
}

// ExportConfig configures where/how an export node writes accumulated
// findings once its input stream closes.
type ExportConfig struct {
	Format string `json:"format"` // "json" | "csv"
	Path   string `json:"path"`
}

func runExport(ctx context.Context, node Node, in <-chan model.Finding, out chan<- model.Finding, emit func(model.Finding)) error {
	var cfg ExportConfig
	if len(node.Config) > 0 {
		if err := json.Unmarshal(node.Config, &cfg); err != nil {
			return fmt.Errorf("export: invalid config: %w", err)
		}
	}
	if cfg.Path == "" {
		return fmt.Errorf("export: path is required")
	}
	if cfg.Format == "" {
		cfg.Format = "json"
	}

	var collected []model.Finding
	for f := range in {
		collected = append(collected, f)
		if err := sendAndEmit(ctx, out, f, emit); err != nil {
			return err
		}
	}

	switch cfg.Format {
	case "json":
		b, err := json.MarshalIndent(collected, "", "  ")
		if err != nil {
			return fmt.Errorf("export: marshal json: %w", err)
		}
		if err := os.WriteFile(cfg.Path, b, 0o644); err != nil {
			return fmt.Errorf("export: write file: %w", err)
		}
	case "csv":
		file, err := os.Create(cfg.Path)
		if err != nil {
			return fmt.Errorf("export: create file: %w", err)
		}
		defer file.Close()
		w := csv.NewWriter(file)
		_ = w.Write([]string{"url", "statusCode", "contentLength", "words", "lines", "method", "contentType", "sourceTool"})
		for _, f := range collected {
			_ = w.Write([]string{
				f.URL,
				strconv.Itoa(f.StatusCode),
				strconv.Itoa(f.ContentLength),
				strconv.Itoa(f.Words),
				strconv.Itoa(f.Lines),
				f.Method,
				f.ContentType,
				f.SourceTool,
			})
		}
		w.Flush()
		if err := w.Error(); err != nil {
			return fmt.Errorf("export: write csv: %w", err)
		}
	default:
		return fmt.Errorf("export: unknown format %q", cfg.Format)
	}
	return nil
}
