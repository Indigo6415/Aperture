package adapters

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/model"
)

func init() {
	register(&FFufAdapter{})
}

// FFufConfig is the node-configurable shape for an ffuf run. URL must
// contain the fuzz keyword (FUZZ by default) exactly as ffuf expects.
type FFufConfig struct {
	URL        string            `json:"url"`
	Wordlist   string            `json:"wordlist"`
	Extensions []string          `json:"extensions,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Method     string            `json:"method,omitempty"`
	Threads    int               `json:"threads,omitempty"`
	MatchCodes string            `json:"matchCodes,omitempty"` // ffuf -mc value; defaults to "all" so downstream filter nodes see everything
	Timeout    int               `json:"timeoutSeconds,omitempty"`
	ExtraArgs  []string          `json:"extraArgs,omitempty"`
}

type FFufAdapter struct{}

func (a *FFufAdapter) Name() string { return "ffuf" }

// ffuf's default (non-silent, non-color) stdout line looks like:
//
//	<input><padding>[Status: 200, Size: 6, Words: 1, Lines: 2, Duration: 8ms]
//
// prefixed by a carriage return + "clear line" ANSI escape and suffixed
// with a "reset" ANSI escape used to redraw the line in place.
var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
var ffufResultLine = regexp.MustCompile(`^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+),\s*Words:\s*(\d+),\s*Lines:\s*(\d+),\s*Duration:\s*\d+ms\]$`)

func (a *FFufAdapter) Run(ctx context.Context, config json.RawMessage, meta RunMeta, emit Emit) error {
	var cfg FFufConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return &ErrConfig{Adapter: a.Name(), Err: err}
	}
	if cfg.URL == "" || !strings.Contains(cfg.URL, "FUZZ") {
		return &ErrConfig{Adapter: a.Name(), Err: fmt.Errorf("url must be set and contain FUZZ")}
	}
	if cfg.Wordlist == "" {
		return &ErrConfig{Adapter: a.Name(), Err: fmt.Errorf("wordlist is required")}
	}

	matchCodes := cfg.MatchCodes
	if matchCodes == "" {
		matchCodes = "all"
	}

	args := []string{"-u", cfg.URL, "-w", cfg.Wordlist, "-mc", matchCodes}
	if cfg.Method != "" {
		args = append(args, "-X", cfg.Method)
	}
	if cfg.Threads > 0 {
		args = append(args, "-t", strconv.Itoa(cfg.Threads))
	}
	if cfg.Timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(cfg.Timeout))
	}
	if len(cfg.Extensions) > 0 {
		args = append(args, "-e", strings.Join(cfg.Extensions, ","))
	}
	for k, v := range cfg.Headers {
		args = append(args, "-H", fmt.Sprintf("%s: %s", k, v))
	}
	args = append(args, cfg.ExtraArgs...)

	cmd := exec.CommandContext(ctx, "ffuf", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("ffuf: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("ffuf: start: %w (is ffuf installed and on PATH?)", err)
	}

	method := cfg.Method
	if method == "" {
		method = "GET"
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := ansiEscape.ReplaceAllString(scanner.Text(), "")
		line = strings.Trim(line, "\r \t")
		if line == "" {
			continue
		}
		m := ffufResultLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		status, _ := strconv.Atoi(m[2])
		size, _ := strconv.Atoi(m[3])
		words, _ := strconv.Atoi(m[4])
		lines, _ := strconv.Atoi(m[5])
		emit(model.Finding{
			ID:            newFindingID(),
			URL:           strings.Replace(cfg.URL, "FUZZ", m[1], 1),
			StatusCode:    status,
			ContentLength: size,
			Words:         words,
			Lines:         lines,
			Method:        method,
			SourceTool:    a.Name(),
			SourceNodeID:  meta.NodeID,
			RunID:         meta.RunID,
			Timestamp:     time.Now(),
		})
	}

	waitErr := cmd.Wait()
	if scanErr := scanner.Err(); scanErr != nil {
		return fmt.Errorf("ffuf: reading output: %w", scanErr)
	}
	if waitErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("ffuf: %w", waitErr)
	}
	return nil
}
