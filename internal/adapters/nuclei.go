package adapters

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
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
	// Tags restricts the run to templates carrying any of these tags (nuclei
	// -tags). Use it to run only the templates that fit the technologies
	// already fingerprinted on a host (see techfp.NucleiTags), which cuts both
	// noise and request volume.
	Tags []string `json:"tags,omitempty"`
	// ExcludeTags removes templates by tag (nuclei -etags). When left empty,
	// denialof-service and fuzzing templates are excluded: they send traffic
	// built to break a target, which is not what a discovery run should do.
	ExcludeTags []string `json:"excludeTags,omitempty"`
	// Retries and Timeout bound each template request (nuclei -retries and
	// -timeout, in seconds). Zero leaves nuclei's own defaults in place.
	Retries   int      `json:"retries,omitempty"`
	Timeout   int      `json:"timeout,omitempty"`
	ExtraArgs []string `json:"extraArgs,omitempty"`
}

// nucleiDefaultExcludeTags are excluded from every run unless the caller
// supplies its own ExcludeTags.
var nucleiDefaultExcludeTags = []string{"dos", "fuzz"}

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
	// MatcherName says which matcher inside the template fired.
	MatcherName string `json:"matcher-name"`
	// CurlCommand is nuclei's own reproduction command for the match.
	CurlCommand string `json:"curl-command"`
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
	if len(cfg.Tags) > 0 {
		args = append(args, "-tags", strings.Join(cfg.Tags, ","))
	}
	exclude := cfg.ExcludeTags
	if len(exclude) == 0 {
		exclude = nucleiDefaultExcludeTags
	}
	args = append(args, "-etags", strings.Join(exclude, ","))
	if cfg.Retries > 0 {
		args = append(args, "-retries", strconv.Itoa(cfg.Retries))
	}
	if cfg.Timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(cfg.Timeout))
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
			ID:  newFindingID(),
			URL: url,
			// Method is the request method nuclei used, not a placeholder. The
			// Tester replays findings with it, so "VULN" made replays fail.
			Method:      nucleiMethod(res.CurlCommand),
			ContentType: res.Info.Name,
			Tags:        []string{res.Info.Severity, res.TemplateID},
			Template:    res.TemplateID,
			Severity:    res.Info.Severity,
			Matcher:     res.MatcherName,
			Reproduce:   res.CurlCommand,
			// A nuclei template is a verified rule, but templates can misfire,
			// so a match is reported as likely rather than confirmed.
			Confidence:   "likely",
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

// curlMethodPattern pulls the request method out of a curl command line, such
// as the "-X POST" that nuclei writes for non-GET templates.
var curlMethodPattern = regexp.MustCompile(`-X\s+([A-Z]+)`)

// nucleiMethod returns the HTTP method of a nuclei match from its curl command,
// defaulting to GET when the command names none.
func nucleiMethod(curl string) string {
	if m := curlMethodPattern.FindStringSubmatch(curl); m != nil {
		return m[1]
	}
	return "GET"
}
