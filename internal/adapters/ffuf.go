package adapters

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/model"
	"github.com/Indigo6415/Aperture/internal/wordlists"
)

// progressEvery is how many parsed result lines pass between progress
// callbacks, so a fast-running ffuf doesn't flood the hub with one event
// per request.
const progressEvery = 25

func init() {
	register(&FFufAdapter{})
}

// FFufConfig is the node-configurable shape for an ffuf run. The FUZZ
// keyword must appear either in URL (content/subdomain discovery) or in a
// header value (virtual-host discovery, typically the Host header) --
// wherever ffuf itself expects it.
type FFufConfig struct {
	URL           string            `json:"url"`
	Wordlist      string            `json:"wordlist"`
	Extensions    []string          `json:"extensions,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	Method        string            `json:"method,omitempty"`
	Threads       int               `json:"threads,omitempty"`
	MatchCodes    string            `json:"matchCodes,omitempty"` // ffuf -mc value; defaults to "all" so downstream filter nodes see everything
	Timeout       int               `json:"timeoutSeconds,omitempty"`
	RateLimit     int               `json:"rateLimit,omitempty"`     // ffuf -rate: requests/sec across the whole run; 0 = unlimited
	AutoCalibrate bool              `json:"autoCalibrate,omitempty"` // ffuf -ac: filter out responses matching a baseline probed with randomized input -- essential for vhost fuzzing, where the default vhost answers every Host header near-identically
	ExtraArgs     []string          `json:"extraArgs,omitempty"`
}

// fuzzHeader returns the name of the first header whose value contains the
// FUZZ keyword, and false if none does (i.e. FUZZ lives in the URL
// instead).
func (c FFufConfig) fuzzHeader() (string, bool) {
	for k, v := range c.Headers {
		if strings.Contains(v, "FUZZ") {
			return k, true
		}
	}
	return "", false
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

func (a *FFufAdapter) Run(ctx context.Context, config json.RawMessage, meta RunMeta, emit Emit, progress Progress) error {
	var cfg FFufConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return &ErrConfig{Adapter: a.Name(), Err: err}
	}
	fuzzHeader, headerHasFuzz := cfg.fuzzHeader()
	if cfg.URL == "" || (!strings.Contains(cfg.URL, "FUZZ") && !headerHasFuzz) {
		return &ErrConfig{Adapter: a.Name(), Err: fmt.Errorf("FUZZ must appear in url or in a header value")}
	}
	if cfg.Wordlist == "" {
		return &ErrConfig{Adapter: a.Name(), Err: fmt.Errorf("wordlist is required")}
	}

	// When FUZZ is only in a header (virtual-host discovery: URL is the
	// bare IP, Host header carries FUZZ), the raw cfg.URL is useless to
	// show the user -- precompute a function that rebuilds a real-looking
	// URL from cfg.URL's scheme/path with the fuzzed header value as host.
	buildResultURL := func(matched string) string { return strings.Replace(cfg.URL, "FUZZ", matched, 1) }
	if headerHasFuzz {
		if base, err := url.Parse(cfg.URL); err == nil {
			buildResultURL = func(matched string) string {
				host := strings.Replace(cfg.Headers[fuzzHeader], "FUZZ", matched, 1)
				u := *base
				u.Host = host
				return u.String()
			}
		}
	}

	matchCodes := cfg.MatchCodes
	if matchCodes == "" {
		matchCodes = "all"
	}

	// ffuf fans out one request per extension per wordlist line (plus the
	// bare word itself), so that's the total request count a progress bar
	// should compare against. A failure to count is non-fatal -- the run
	// still proceeds, just without a percentage (total 0 == indeterminate).
	total := 0
	if lines, err := wordlists.CountLines(cfg.Wordlist); err == nil {
		multiplier := 1
		if len(cfg.Extensions) > 0 {
			multiplier += len(cfg.Extensions)
		}
		total = lines * multiplier
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
	if cfg.RateLimit > 0 {
		args = append(args, "-rate", strconv.Itoa(cfg.RateLimit))
	}
	if len(cfg.Extensions) > 0 {
		args = append(args, "-e", strings.Join(cfg.Extensions, ","))
	}
	if cfg.AutoCalibrate {
		args = append(args, "-ac")
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

	if progress != nil {
		progress(0, total)
	}

	done := 0
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
			URL:           buildResultURL(m[1]),
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
		done++
		if progress != nil && done%progressEvery == 0 {
			progress(done, total)
		}
	}

	waitErr := cmd.Wait()
	if scanErr := scanner.Err(); scanErr != nil {
		return fmt.Errorf("ffuf: reading output: %w", scanErr)
	}
	if progress != nil {
		progress(done, total)
	}
	if waitErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("ffuf: %w", waitErr)
	}
	return nil
}
