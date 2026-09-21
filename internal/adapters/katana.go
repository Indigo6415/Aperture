package adapters

import (
	"bufio"
	"bytes"
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
	register(&KatanaAdapter{})
}

// KatanaConfig is the node-configurable shape for a katana crawl: unlike
// ffuf/feroxbuster's wordlist-driven guessing, katana discovers real URLs
// by actually parsing HTML/JS as it crawls from URL -- a natural sibling
// content-discovery source alongside them rather than a replacement.
type KatanaConfig struct {
	URL       string            `json:"url"`
	Depth     int               `json:"depth,omitempty"` // katana -depth; 0 leaves katana's own default (3)
	Headers   map[string]string `json:"headers,omitempty"`
	Timeout   int               `json:"timeoutSeconds,omitempty"`
	RateLimit int               `json:"rateLimit,omitempty"`
	ExtraArgs []string          `json:"extraArgs,omitempty"`
}

type KatanaAdapter struct{}

func (a *KatanaAdapter) Name() string { return "katana" }

// katanaResult mirrors the subset of katana's -jsonl line schema Aperture
// cares about -- each line is one crawled request/response pair.
type katanaResult struct {
	Request struct {
		Method   string `json:"method"`
		Endpoint string `json:"endpoint"`
	} `json:"request"`
	Response struct {
		StatusCode    int `json:"status_code"`
		ContentLength int `json:"content_length"`
	} `json:"response"`
}

func (a *KatanaAdapter) Run(ctx context.Context, config json.RawMessage, meta RunMeta, emit Emit, progress Progress) error {
	var cfg KatanaConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return &ErrConfig{Adapter: a.Name(), Err: err}
	}
	if cfg.URL == "" {
		return &ErrConfig{Adapter: a.Name(), Err: fmt.Errorf("url is required")}
	}

	args := []string{"-u", cfg.URL, "-jsonl", "-silent"}
	if cfg.Depth > 0 {
		args = append(args, "-depth", strconv.Itoa(cfg.Depth))
	}
	if cfg.Timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(cfg.Timeout))
	}
	if cfg.RateLimit > 0 {
		args = append(args, "-rate-limit", strconv.Itoa(cfg.RateLimit))
	}
	for k, v := range cfg.Headers {
		args = append(args, "-H", fmt.Sprintf("%s: %s", k, v))
	}
	args = append(args, cfg.ExtraArgs...)

	cmd := exec.CommandContext(ctx, "katana", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("katana: stdout pipe: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("katana: start: %w (is katana installed and on PATH?)", err)
	}

	if progress != nil {
		// A crawl's total URL count is only known once it's finished --
		// indeterminate, same as feroxbuster's recursive crawling.
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
		var res katanaResult
		_ = json.Unmarshal([]byte(line), &res)
		if res.Request.Endpoint == "" {
			continue
		}
		method := res.Request.Method
		if method == "" {
			method = "GET"
		}
		emit(model.Finding{
			ID:            newFindingID(),
			URL:           res.Request.Endpoint,
			StatusCode:    res.Response.StatusCode,
			ContentLength: res.Response.ContentLength,
			Method:        method,
			SourceTool:    a.Name(),
			SourceNodeID:  meta.NodeID,
			RunID:         meta.RunID,
			Timestamp:     time.Now(),
		})
		done++
		if progress != nil {
			progress(done, 0)
		}
	}

	waitErr := cmd.Wait()
	if scanErr := scanner.Err(); scanErr != nil {
		return fmt.Errorf("katana: reading output: %w", scanErr)
	}
	if progress != nil {
		progress(done, 0)
	}
	if waitErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errText := strings.TrimSpace(stderr.String()); errText != "" {
			return fmt.Errorf("katana: %w: %s", waitErr, errText)
		}
		return fmt.Errorf("katana: %w", waitErr)
	}
	return nil
}
