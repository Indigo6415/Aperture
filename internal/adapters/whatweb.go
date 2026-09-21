package adapters

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/model"
)

func init() {
	register(&WhatWebAdapter{})
}

// WhatWebConfig is the node-configurable shape for a WhatWeb run --
// WhatWeb's plugin database is a second, independently-maintained
// fingerprint source alongside Aperture's own internal/techfp signatures,
// run as an opt-in comparison/second-opinion pass rather than a
// replacement for it.
type WhatWebConfig struct {
	Targets   []string          `json:"targets"`
	Headers   map[string]string `json:"headers,omitempty"`
	Threads   int               `json:"threads,omitempty"` // whatweb --max-threads
	ExtraArgs []string          `json:"extraArgs,omitempty"`
}

type WhatWebAdapter struct{}

func (a *WhatWebAdapter) Name() string { return "whatweb" }

// whatwebResult mirrors one --log-json line: one JSON object per target,
// e.g. {"target":"https://example.com/","http_status":200,"plugins":{"Apache":{"version":["2.4.41"]},...}}.
// plugins' values vary in shape per plugin (some carry "version"/"string"
// arrays, others are just present with no detail), so only the key names
// -- the detected technology names themselves -- are used here rather than
// trying to fully type every plugin's payload.
type whatwebResult struct {
	Target     string                     `json:"target"`
	HTTPStatus json.Number                `json:"http_status"`
	Plugins    map[string]json.RawMessage `json:"plugins"`
}

func (a *WhatWebAdapter) Run(ctx context.Context, config json.RawMessage, meta RunMeta, emit Emit, progress Progress) error {
	var cfg WhatWebConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return &ErrConfig{Adapter: a.Name(), Err: err}
	}
	if len(cfg.Targets) == 0 {
		return &ErrConfig{Adapter: a.Name(), Err: fmt.Errorf("targets is required")}
	}

	targetFile, err := os.CreateTemp("", "aperture-whatweb-targets-*.txt")
	if err != nil {
		return fmt.Errorf("whatweb: create targets file: %w", err)
	}
	defer os.Remove(targetFile.Name())
	for _, t := range cfg.Targets {
		fmt.Fprintln(targetFile, t)
	}
	if err := targetFile.Close(); err != nil {
		return fmt.Errorf("whatweb: write targets file: %w", err)
	}

	// Unlike the projectdiscovery tools above, WhatWeb's JSON logger writes
	// to a named file rather than supporting a real stdout stream, so
	// results are only available once the whole run has finished -- one
	// batch of Findings at the end instead of a live per-line stream. Only
	// the *path* is wanted here, not an actual file -- WhatWeb's log writer
	// opens it itself, and (like a number of Ruby CLI loggers) refuses to
	// run at all if the path already exists, which is exactly what
	// os.CreateTemp leaves behind; grab a unique name from it, then delete
	// the placeholder immediately so WhatWeb creates the real file itself.
	outputFile, err := os.CreateTemp("", "aperture-whatweb-output-*.json")
	if err != nil {
		return fmt.Errorf("whatweb: create output file: %w", err)
	}
	outputPath := outputFile.Name()
	_ = outputFile.Close()
	if err := os.Remove(outputPath); err != nil {
		return fmt.Errorf("whatweb: remove output file placeholder: %w", err)
	}
	defer os.Remove(outputPath)

	args := []string{"-i", targetFile.Name(), "--log-json=" + outputPath, "-q"}
	if cfg.Threads > 0 {
		args = append(args, "--max-threads", strconv.Itoa(cfg.Threads))
	}
	for k, v := range cfg.Headers {
		args = append(args, "--header", fmt.Sprintf("%s: %s", k, v))
	}
	args = append(args, cfg.ExtraArgs...)

	cmd := exec.CommandContext(ctx, "whatweb", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("whatweb: start: %w (is whatweb installed and on PATH?)", err)
	}

	if progress != nil {
		progress(0, len(cfg.Targets))
	}

	waitErr := cmd.Wait()
	if waitErr != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	// WhatWeb prints the reason it couldn't run at all (bad flag, Ruby gem
	// error, ...) to stderr, not into the JSON log -- surfaced here so a
	// hard failure shows an actual reason instead of a bare exit status.
	if waitErr != nil {
		if errText := strings.TrimSpace(stderr.String()); errText != "" {
			return fmt.Errorf("whatweb: %w: %s", waitErr, errText)
		}
	}

	// Parse whatever the log file holds even if whatweb itself exited
	// non-zero (e.g. one unreachable target among several) -- best-effort,
	// same reasoning as recon's per-check error isolation.
	f, openErr := os.Open(outputPath)
	if openErr != nil {
		if waitErr != nil {
			return fmt.Errorf("whatweb: %w", waitErr)
		}
		return fmt.Errorf("whatweb: open output: %w", openErr)
	}
	defer f.Close()

	done := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var res whatwebResult
		_ = json.Unmarshal([]byte(line), &res)
		if res.Target == "" {
			continue
		}
		status, _ := res.HTTPStatus.Int64()
		tags := make([]string, 0, len(res.Plugins))
		for name := range res.Plugins {
			tags = append(tags, name)
		}
		sort.Strings(tags)
		emit(model.Finding{
			ID:           newFindingID(),
			URL:          res.Target,
			StatusCode:   int(status),
			Method:       "GET",
			Tags:         tags,
			SourceTool:   a.Name(),
			SourceNodeID: meta.NodeID,
			RunID:        meta.RunID,
			Timestamp:    time.Now(),
		})
		done++
		if progress != nil {
			progress(done, len(cfg.Targets))
		}
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return fmt.Errorf("whatweb: reading output: %w", scanErr)
	}
	if waitErr != nil {
		return fmt.Errorf("whatweb: %w", waitErr)
	}
	return nil
}
