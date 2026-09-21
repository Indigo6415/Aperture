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
	register(&SubfinderAdapter{})
}

// SubfinderConfig is the node-configurable shape for a subfinder run.
// Subfinder has no natural fit in model.Finding either (same problem as
// nmap's ports) -- a discovered subdomain is emitted as a Finding whose URL
// is a "https://<host>/" pseudo-URL (matching the shape ffuf-subdomain
// findings already use, so promoting either into a case Target works the
// same way) with Method "SUBDOMAIN" and Tags carrying the passive source(s)
// subfinder attributes the name to.
type SubfinderConfig struct {
	Domain    string   `json:"domain"`
	Threads   int      `json:"threads,omitempty"`        // subfinder -t
	Timeout   int      `json:"timeoutSeconds,omitempty"` // subfinder -timeout: per-source timeout, seconds
	RateLimit int      `json:"rateLimit,omitempty"`      // subfinder -rate-limit: max requests/sec across all sources
	ExtraArgs []string `json:"extraArgs,omitempty"`
}

type SubfinderAdapter struct{}

func (a *SubfinderAdapter) Name() string { return "subfinder" }

// subfinderResult mirrors one -json line: {"host":"www.example.com","input":"example.com"}.
type subfinderResult struct {
	Host string `json:"host"`
}

func (a *SubfinderAdapter) Run(ctx context.Context, config json.RawMessage, meta RunMeta, emit Emit, progress Progress) error {
	var cfg SubfinderConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return &ErrConfig{Adapter: a.Name(), Err: err}
	}
	if cfg.Domain == "" {
		return &ErrConfig{Adapter: a.Name(), Err: fmt.Errorf("domain is required")}
	}

	args := []string{"-d", cfg.Domain, "-json", "-silent"}
	if cfg.Threads > 0 {
		args = append(args, "-t", strconv.Itoa(cfg.Threads))
	}
	if cfg.Timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(cfg.Timeout))
	}
	if cfg.RateLimit > 0 {
		args = append(args, "-rate-limit", strconv.Itoa(cfg.RateLimit))
	}
	args = append(args, cfg.ExtraArgs...)

	cmd := exec.CommandContext(ctx, "subfinder", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("subfinder: stdout pipe: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("subfinder: start: %w (is subfinder installed and on PATH?)", err)
	}

	if progress != nil {
		// How many subdomains passive sources will turn up isn't knowable
		// upfront -- indeterminate, same as feroxbuster/nuclei.
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
		var res subfinderResult
		_ = json.Unmarshal([]byte(line), &res)
		if res.Host == "" {
			continue
		}
		emit(model.Finding{
			ID:           newFindingID(),
			URL:          "https://" + strings.ToLower(res.Host) + "/",
			Method:       "SUBDOMAIN",
			Tags:         []string{"subfinder"},
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
		return fmt.Errorf("subfinder: reading output: %w", scanErr)
	}
	if progress != nil {
		progress(done, 0)
	}
	if waitErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errText := strings.TrimSpace(stderr.String()); errText != "" {
			return fmt.Errorf("subfinder: %w: %s", waitErr, errText)
		}
		return fmt.Errorf("subfinder: %w", waitErr)
	}
	return nil
}
