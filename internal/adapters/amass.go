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
	register(&AmassAdapter{})
}

// defaultAmassMaxDNSQueries/defaultAmassTimeoutMinutes are hardcoded safety
// caps, not just UI-tunable defaults -- amass's own defaults for both are
// unbounded/generous, and running it unconstrained (its normal active mode
// resolves/brute-forces with no built-in concurrency ceiling) has been
// observed to spike DNS/network load hard enough to freeze the whole
// machine it's running on for several seconds. -passive below removes most
// of that load by never touching the target directly at all; these two
// caps bound whatever's left (the OSINT-source lookups' own concurrency,
// and the enumeration's total wall-clock budget) the same way
// maxFuzzRequests bounds ffuf/feroxbuster's job queue.
const (
	defaultAmassMaxDNSQueries  = 20
	defaultAmassTimeoutMinutes = 10
)

// AmassConfig is the node-configurable shape for an amass "enum" run --
// OWASP Amass's own certificate/scraping/OSINT-source subdomain
// enumeration, complementing subfinder's own passive lookups with a
// different (overlapping but not identical) source list. Always run with
// -passive (see the safety-cap comment above) -- unlike feroxbuster's
// Recursive, amass's active mode has no per-Aperture-job resource ceiling
// of its own to opt into, so there's no safe "aggressive" version of this
// tool to offer from the UI. Discovered names are emitted the same
// "https://<host>/" pseudo-URL/Method-"SUBDOMAIN" shape SubfinderAdapter
// and ffuf-subdomain findings already use.
type AmassConfig struct {
	Domain string `json:"domain"`
	// RateLimit maps to amass -max-dns-queries: the closest amass has to a
	// requests/sec cap (queries per second across the whole enumeration).
	// <= 0 falls back to defaultAmassMaxDNSQueries rather than amass's own
	// unbounded default.
	RateLimit int      `json:"rateLimit,omitempty"`
	ExtraArgs []string `json:"extraArgs,omitempty"`
}

type AmassAdapter struct{}

func (a *AmassAdapter) Name() string { return "amass" }

func (a *AmassAdapter) Run(ctx context.Context, config json.RawMessage, meta RunMeta, emit Emit, progress Progress) error {
	var cfg AmassConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return &ErrConfig{Adapter: a.Name(), Err: err}
	}
	if cfg.Domain == "" {
		return &ErrConfig{Adapter: a.Name(), Err: fmt.Errorf("domain is required")}
	}

	maxDNSQueries := cfg.RateLimit
	if maxDNSQueries <= 0 {
		maxDNSQueries = defaultAmassMaxDNSQueries
	}

	// "enum" is amass's subdomain-enumeration subcommand; -silent drops its
	// banner/progress chatter so stdout is exactly one discovered name per
	// line, the same "plain hostname list" shape amass falls back to
	// whenever -json/-o isn't given. ExtraArgs is appended last so an
	// advanced caller can override any of the safety flags above it
	// (amass, like most CLI parsers, takes the last occurrence of a
	// repeated flag) -- e.g. passing a longer "-timeout" or dropping
	// "-passive" isn't possible through the UI but still works via the API.
	args := []string{
		"enum", "-d", cfg.Domain, "-silent", "-passive",
		"-max-dns-queries", strconv.Itoa(maxDNSQueries),
		"-timeout", strconv.Itoa(defaultAmassTimeoutMinutes),
	}
	args = append(args, cfg.ExtraArgs...)

	cmd := exec.CommandContext(ctx, "amass", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("amass: stdout pipe: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("amass: start: %w (is amass installed and on PATH?)", err)
	}

	if progress != nil {
		// Total subdomain count is never knowable upfront -- indeterminate.
		progress(0, 0)
	}

	done := 0
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		host := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if host == "" {
			continue
		}
		emit(model.Finding{
			ID:           newFindingID(),
			URL:          "https://" + host + "/",
			Method:       "SUBDOMAIN",
			Tags:         []string{"amass"},
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
		return fmt.Errorf("amass: reading output: %w", scanErr)
	}
	if progress != nil {
		progress(done, 0)
	}
	if waitErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errText := strings.TrimSpace(stderr.String()); errText != "" {
			return fmt.Errorf("amass: %w: %s", waitErr, errText)
		}
		return fmt.Errorf("amass: %w", waitErr)
	}
	return nil
}
