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

// feroxProgressEvery is how many parsed response lines pass between
// progress callbacks (see progressEvery in ffuf.go for why this exists).
const feroxProgressEvery = 10

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

	args := []string{"-u", cfg.URL, "-w", cfg.Wordlist, "--json", "--silent"}
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

	if progress != nil {
		// Recursion means the total request count is unknowable upfront --
		// total 0 tells callers to render this as indeterminate progress.
		progress(0, 0)
	}

	done := 0
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
		done++
		if progress != nil && done%feroxProgressEvery == 0 {
			progress(done, 0)
		}
	}

	waitErr := cmd.Wait()
	if scanErr := scanner.Err(); scanErr != nil {
		return fmt.Errorf("feroxbuster: reading output: %w", scanErr)
	}
	if progress != nil {
		progress(done, 0)
	}
	if waitErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("feroxbuster: %w", waitErr)
	}
	return nil
}
