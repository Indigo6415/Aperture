package adapters

import (
	"bufio"
	"bytes"
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
	register(&HttpxAdapter{})
}

// HttpxConfig is the node-configurable shape for an httpx run: fast bulk
// HTTP(S) probing of a target list, reporting liveness plus whatever
// title/server/tech-stack fingerprint httpx itself detects -- a much
// cheaper alternative to a full feroxbuster/ffuf pass when the question is
// just "which of these hosts are alive, and what are they running."
type HttpxConfig struct {
	Targets   []string          `json:"targets"`
	Headers   map[string]string `json:"headers,omitempty"`
	Threads   int               `json:"threads,omitempty"`
	Timeout   int               `json:"timeoutSeconds,omitempty"`
	RateLimit int               `json:"rateLimit,omitempty"`
	ExtraArgs []string          `json:"extraArgs,omitempty"`
}

type HttpxAdapter struct{}

func (a *HttpxAdapter) Name() string { return "httpx" }

// httpxResult mirrors the subset of httpx's -json line schema Aperture
// cares about. Most of these fields are only ever populated by httpx when
// the matching CLI flag was passed (see the -status-code/-title/etc. flags
// added below) -- httpx's own defaults report almost nothing beyond
// url/input/timestamp, which is why a run without those flags looks like
// it "only returns basic information."
type httpxResult struct {
	URL           string      `json:"url"`
	StatusCode    int         `json:"status_code"`
	ContentLength int         `json:"content_length"`
	ContentType   string      `json:"content_type"`
	Title         string      `json:"title"`
	Webserver     string      `json:"webserver"`
	Tech          []string    `json:"tech"`
	Location      string      `json:"location"`
	IP            string      `json:"host"` // httpx's own naming quirk: "host" is the resolved IP, "input" is the hostname
	CNAME         []string    `json:"cname"`
	CDNName       string      `json:"cdn_name"`
	Favicon       json.Number `json:"favicon"`
	Words         int         `json:"words"`
	Lines         int         `json:"lines"`
}

func (a *HttpxAdapter) Run(ctx context.Context, config json.RawMessage, meta RunMeta, emit Emit, progress Progress) error {
	var cfg HttpxConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return &ErrConfig{Adapter: a.Name(), Err: err}
	}
	if len(cfg.Targets) == 0 {
		return &ErrConfig{Adapter: a.Name(), Err: fmt.Errorf("targets is required")}
	}

	// -l reads targets from a file, one per line -- same reasoning as
	// nuclei's target file (avoids a shell argv length limit).
	targetFile, err := os.CreateTemp("", "aperture-httpx-targets-*.txt")
	if err != nil {
		return fmt.Errorf("httpx: create targets file: %w", err)
	}
	defer os.Remove(targetFile.Name())
	for _, t := range cfg.Targets {
		fmt.Fprintln(targetFile, t)
	}
	if err := targetFile.Close(); err != nil {
		return fmt.Errorf("httpx: write targets file: %w", err)
	}

	// httpx's own defaults report almost nothing beyond url/input/timestamp
	// in -json mode -- every one of these display flags gates a specific
	// field in that JSON, so without them the output really is "basic
	// information" only, no matter how detailed httpx's own README looks.
	// -favicon adds one extra request per target (fetching /favicon.ico);
	// -cdn/-ip/-cname/-asn-style lookups are otherwise free, reusing data
	// httpx already has from the probe/DNS resolution it just did.
	//
	// -follow-redirects matters more than any single display flag above:
	// without it, httpx probes exactly the URL it was given and stops --
	// for a target that 301/302s (bare domain -> www, http -> https, or
	// straight into a CDN/WAF challenge page), that first hop's tiny
	// response is *all* -tech-detect ever gets to look at, so a real stack
	// sitting one redirect away from the front door never gets fingerprinted
	// and only the redirecting edge (e.g. "Cloudflare") shows up. Following
	// redirects lets -tech-detect's wappalyzer-based fingerprinting (the
	// same source Wappalyzer itself draws from) actually see the final
	// rendered page's headers/HTML, which is where CMS/framework/server-
	// version signatures usually live.
	args := []string{
		"-l", targetFile.Name(), "-json", "-silent",
		"-status-code", "-content-length", "-content-type", "-title", "-web-server",
		"-tech-detect", "-location", "-ip", "-cname", "-cdn", "-favicon",
		"-word-count", "-line-count", "-follow-redirects",
	}
	if cfg.Threads > 0 {
		args = append(args, "-threads", strconv.Itoa(cfg.Threads))
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

	cmd := exec.CommandContext(ctx, "httpx", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("httpx: stdout pipe: %w", err)
	}
	// Captured (rather than left to inherit the parent's, or discarded) so
	// a hard failure -- e.g. an unrecognized flag on an older httpx build
	// -- surfaces httpx's own explanation instead of a bare exit status.
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("httpx: start: %w (is httpx installed and on PATH?)", err)
	}

	if progress != nil {
		// httpx probes each target roughly once, so the target count is a
		// reasonable (if not exact, given redirects/retries) total.
		progress(0, len(cfg.Targets))
	}

	done := 0
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Unmarshal errors are deliberately non-fatal here beyond requiring a
		// URL: a single field's type not matching what's declared above
		// (schema drift across httpx versions) makes json.Unmarshal return
		// an error but still populate every field it could, so bailing out
		// on err != nil would silently drop an otherwise-good result over
		// one unrelated field.
		var res httpxResult
		_ = json.Unmarshal([]byte(line), &res)
		if res.URL == "" {
			continue
		}
		headers := map[string]string{}
		if res.Title != "" {
			headers["title"] = res.Title
		}
		if res.Webserver != "" {
			headers["server"] = res.Webserver
		}
		if res.IP != "" {
			headers["ip"] = res.IP
		}
		if len(res.CNAME) > 0 {
			headers["cname"] = strings.Join(res.CNAME, ",")
		}
		if res.Favicon != "" {
			headers["faviconHash"] = res.Favicon.String()
		}
		if len(headers) == 0 {
			headers = nil
		}
		tags := res.Tech
		if res.CDNName != "" {
			tags = append(tags, "cdn:"+res.CDNName)
		}
		emit(model.Finding{
			ID:            newFindingID(),
			URL:           res.URL,
			StatusCode:    res.StatusCode,
			ContentLength: res.ContentLength,
			ContentType:   res.ContentType,
			RedirectLoc:   res.Location,
			Words:         res.Words,
			Lines:         res.Lines,
			Method:        "GET",
			Headers:       headers,
			Tags:          tags,
			SourceTool:    a.Name(),
			SourceNodeID:  meta.NodeID,
			RunID:         meta.RunID,
			Timestamp:     time.Now(),
		})
		done++
		if progress != nil {
			progress(done, len(cfg.Targets))
		}
	}

	waitErr := cmd.Wait()
	if scanErr := scanner.Err(); scanErr != nil {
		return fmt.Errorf("httpx: reading output: %w", scanErr)
	}
	if progress != nil {
		progress(done, len(cfg.Targets))
	}
	if waitErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errText := strings.TrimSpace(stderr.String()); errText != "" {
			return fmt.Errorf("httpx: %w: %s", waitErr, errText)
		}
		return fmt.Errorf("httpx: %w", waitErr)
	}
	return nil
}
