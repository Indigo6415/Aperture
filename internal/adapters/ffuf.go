package adapters

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Indigo6415/Aperture/internal/model"
	"github.com/Indigo6415/Aperture/internal/wordlists"
)

// ffufProgressLine matches ffuf's live stderr progress line, e.g.:
//
//	:: Progress: [1234/5000] :: Job [1/1] :: 87 req/sec :: Duration: [0:00:12] :: Errors: 0 ::
//
// This is ffuf's own count of completed requests, independent of how many
// of them pass its match/filter/autocalibration rules -- unlike counting
// emitted stdout result lines (matches only), it doesn't stall near zero
// when -mc is narrow or -ac is filtering out nearly everything, which is
// exactly how subdomain/vhost enumeration are configured (see
// api.buildToolFlow's ToolFFufSubdomain/ToolFFufVHost branches).
var ffufProgressLine = regexp.MustCompile(`::\s*Progress:\s*\[(\d+)/(\d+)\]`)

// watchFfufProgress reads ffuf's stderr for the progress line above. ffuf
// redraws that line in place with a bare '\r' (no trailing '\n') rather
// than appending a new one each time, so this can't use bufio.ScanLines
// directly -- that would buffer the entire run's worth of redraws as one
// unterminated "line" until stderr closes. splitLinesOrCR treats '\r' as
// a line ending too, so each redraw is scanned as it arrives.
//
// Always drains stderr to completion (even with progress == nil) --
// ffuf's stderr pipe otherwise fills and blocks the subprocess once its
// OS buffer is full, since nothing else is reading it.
func watchFfufProgress(stderr io.Reader, progress Progress) {
	scanner := bufio.NewScanner(stderr)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	scanner.Split(splitLinesOrCR)
	for scanner.Scan() {
		if progress == nil {
			continue
		}
		m := ffufProgressLine.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		done, _ := strconv.Atoi(m[1])
		total, _ := strconv.Atoi(m[2])
		progress(done, total)
	}
}

// splitLinesOrCR is bufio.ScanLines extended to also split on a bare
// '\r' -- ffuf (and most CLI progress bars) redraw their status line with
// '\r' alone, never '\n', so the default split never terminates it.
func splitLinesOrCR(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexAny(data, "\r\n"); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func init() {
	register(&FFufAdapter{})
}

// FFufConfig is the node-configurable shape for an ffuf run. The FUZZ
// keyword must appear either in URL (content/subdomain discovery) or in a
// header value (virtual-host discovery, typically the Host header) --
// wherever ffuf itself expects it.
type FFufConfig struct {
	URL             string            `json:"url"`
	Wordlist        string            `json:"wordlist"`
	Extensions      []string          `json:"extensions,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	Body            string            `json:"body,omitempty"` // ffuf -d: raw POST/PUT body, FUZZ substituted the same as it is in URL/headers
	Method          string            `json:"method,omitempty"`
	Threads         int               `json:"threads,omitempty"`
	MatchCodes      string            `json:"matchCodes,omitempty"`  // ffuf -mc value; defaults to "all" so downstream filter nodes see everything
	FilterCodes     string            `json:"filterCodes,omitempty"` // ffuf -fc: status codes to exclude, applied after -mc
	MatchSize       string            `json:"matchSize,omitempty"`   // ffuf -ms
	FilterSize      string            `json:"filterSize,omitempty"`  // ffuf -fs
	Timeout         int               `json:"timeoutSeconds,omitempty"`
	RateLimit       int               `json:"rateLimit,omitempty"`       // ffuf -rate: requests/sec across the whole run; 0 = unlimited
	Delay           string            `json:"delay,omitempty"`           // ffuf -p: per-request delay in seconds, either a fixed value ("0.5") or a jittered range ("0.1-0.5")
	Proxy           string            `json:"proxy,omitempty"`           // ffuf -x: upstream HTTP(S) proxy URL, e.g. for routing through Burp
	AutoCalibrate   bool              `json:"autoCalibrate,omitempty"`   // ffuf -ac: filter out responses matching a baseline probed with randomized input -- essential for vhost fuzzing, where the default vhost answers every Host header near-identically
	FollowRedirects bool              `json:"followRedirects,omitempty"` // ffuf -r
	ExtraArgs       []string          `json:"extraArgs,omitempty"`
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

	// Refuse a wordlist/extensions combination ffuf couldn't run without
	// exhausting RAM building its job queue (see checkFuzzRequestCount).
	if err := checkFuzzRequestCount(a.Name(), cfg.Wordlist, cfg.Extensions); err != nil {
		return err
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
	if cfg.Body != "" {
		args = append(args, "-d", cfg.Body)
	}
	if cfg.FilterCodes != "" {
		args = append(args, "-fc", cfg.FilterCodes)
	}
	if cfg.MatchSize != "" {
		args = append(args, "-ms", cfg.MatchSize)
	}
	if cfg.FilterSize != "" {
		args = append(args, "-fs", cfg.FilterSize)
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
	if cfg.Delay != "" {
		args = append(args, "-p", cfg.Delay)
	}
	if cfg.Proxy != "" {
		args = append(args, "-x", cfg.Proxy)
	}
	if len(cfg.Extensions) > 0 {
		args = append(args, "-e", strings.Join(cfg.Extensions, ","))
	}
	if cfg.AutoCalibrate {
		args = append(args, "-ac")
	}
	if cfg.FollowRedirects {
		args = append(args, "-r")
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
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("ffuf: stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("ffuf: start: %w (is ffuf installed and on PATH?)", err)
	}

	method := cfg.Method
	if method == "" {
		method = "GET"
	}

	if progress != nil {
		// Seeded with the wordlist-derived estimate so callers see a real
		// total immediately; watchFfufProgress below corrects it (usually
		// within the first second) with ffuf's own exact count.
		progress(0, total)
	}

	var progressWG sync.WaitGroup
	progressWG.Add(1)
	go func() {
		defer progressWG.Done()
		watchFfufProgress(stderr, progress)
	}()

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
	}
	scanErr := scanner.Err()

	// Both pipes must be fully drained before Wait -- otherwise a full
	// stderr buffer (progress redraws are frequent) could deadlock the
	// subprocess against Wait closing the pipes out from under it.
	progressWG.Wait()
	waitErr := cmd.Wait()
	if scanErr != nil {
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
