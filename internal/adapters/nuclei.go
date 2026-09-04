package adapters

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/model"
)

func init() {
	register(&NucleiAdapter{})
}

// NucleiConfig is the node-configurable shape for a nuclei run against a set
// of already-discovered URLs (typically a content-discovery run's hits),
// flagging known CVEs/misconfigurations on top of the raw status/size data
// those URLs were found with.
type NucleiConfig struct {
	Targets   []string `json:"targets"`
	Severity  string   `json:"severity,omitempty"` // nuclei -severity value, e.g. "medium,high,critical"; empty = all severities
	RateLimit int      `json:"rateLimit,omitempty"`
	ExtraArgs []string `json:"extraArgs,omitempty"`
}

type NucleiAdapter struct{}

func (a *NucleiAdapter) Name() string { return "nuclei" }

// nucleiResult mirrors the subset of nuclei's -jsonl line schema Aperture
// cares about.
type nucleiResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"info"`
	Host      string `json:"host"`
	MatchedAt string `json:"matched-at"`
}

func (a *NucleiAdapter) Run(ctx context.Context, config json.RawMessage, meta RunMeta, emit Emit, progress Progress) error {
	var cfg NucleiConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return &ErrConfig{Adapter: a.Name(), Err: err}
	}
	if len(cfg.Targets) == 0 {
		return &ErrConfig{Adapter: a.Name(), Err: fmt.Errorf("targets is required")}
	}

	// nuclei's -l flag reads targets from a file, one per line -- simplest
	// way to hand it however many URLs content discovery turned up without
	// hitting a shell argv length limit the way one -u flag per URL might.
	targetFile, err := os.CreateTemp("", "aperture-nuclei-targets-*.txt")
	if err != nil {
		return fmt.Errorf("nuclei: create targets file: %w", err)
	}
	defer os.Remove(targetFile.Name())
	for _, t := range cfg.Targets {
		fmt.Fprintln(targetFile, t)
	}
	if err := targetFile.Close(); err != nil {
		return fmt.Errorf("nuclei: write targets file: %w", err)
	}

	args := []string{"-l", targetFile.Name(), "-jsonl", "-silent"}
	if cfg.Severity != "" {
		args = append(args, "-severity", cfg.Severity)
	}
	if cfg.RateLimit > 0 {
		args = append(args, "-rate-limit", strconv.Itoa(cfg.RateLimit))
	}
	args = append(args, cfg.ExtraArgs...)

	cmd := exec.CommandContext(ctx, "nuclei", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("nuclei: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("nuclei: start: %w (is nuclei installed and on PATH?)", err)
	}

	if progress != nil {
		// The number of templates nuclei will run per target isn't knowable
		// upfront without a dry run -- indeterminate, same as feroxbuster.
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
		var res nucleiResult
		if err := json.Unmarshal([]byte(line), &res); err != nil {
			continue // ignore lines that aren't the jsonl schema we expect
		}
		url := res.MatchedAt
		if url == "" {
			url = res.Host
		}
		emit(model.Finding{
			ID:           newFindingID(),
			URL:          url,
			ContentType:  res.Info.Name,
			Method:       "VULN",
			Tags:         []string{res.Info.Severity, res.TemplateID},
			SourceTool:   a.Name(),
			SourceNodeID: meta.NodeID,
			RunID:        meta.RunID,
			Timestamp:    time.Now(),
		})
		done++
		if progress != nil {
			progress(done, 0)
		}
	}

	waitErr := cmd.Wait()
	if scanErr := scanner.Err(); scanErr != nil {
		return fmt.Errorf("nuclei: reading output: %w", scanErr)
	}
	if progress != nil {
		progress(done, 0)
	}
	if waitErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("nuclei: %w", waitErr)
	}
	return nil
}
