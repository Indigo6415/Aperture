package domainscan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func init() {
	registeredModules = append(registeredModules, retireModuleDef)
}

var retireModuleDef = moduleDef{
	id:   "retire",
	name: "Retire.js (outdated/vulnerable JS libraries)",
	run:  runRetireModule,
}

// retireOutput mirrors the subset of `retire --outputformat json`'s schema
// (retire.js v3+) this package cares about -- see
// https://github.com/RetireJS/retire.js/wiki/Output-formats.
type retireOutput struct {
	Data []struct {
		File    string `json:"file"`
		Results []struct {
			Component       string `json:"component"`
			Version         string `json:"version"`
			Vulnerabilities []struct {
				Severity    string `json:"severity"`
				Below       string `json:"below"`
				AtOrAbove   string `json:"atOrAbove"`
				Identifiers struct {
					Summary string   `json:"summary"`
					CVE     []string `json:"CVE"`
				} `json:"identifiers"`
			} `json:"vulnerabilities"`
		} `json:"results"`
	} `json:"data"`
}

// runRetireModule crawls t's whole domain for JS files (see crawl.go --
// retire.js itself has no notion of a live site, only a local directory),
// writes every distinct script it found to a scratch directory, and runs
// the retire.js CLI against that directory once, translating each flagged
// component/version into one Finding per vulnerability. A component with no
// known vulnerabilities never appears in retire's output at all, so every
// Finding here is already something worth looking at -- there's no
// "checked, clean" case to filter out the way probescan's path checks have.
func runRetireModule(ctx context.Context, t *Target, opts Options) ([]Finding, error) {
	if _, err := exec.LookPath("retire"); err != nil {
		return nil, fmt.Errorf("retire: not found on PATH (npm install -g retire)")
	}

	crawl := sharedCrawl(ctx, t, opts)
	if len(crawl.Scripts) == 0 {
		return []Finding{}, nil
	}

	dir, err := os.MkdirTemp("", "aperture-retire-*")
	if err != nil {
		return nil, fmt.Errorf("retire: create scratch dir: %w", err)
	}
	defer os.RemoveAll(dir)

	// retire identifies a lot of libraries by filename convention
	// (jquery-1.12.4.min.js, etc.) as a fallback when content-based
	// detection doesn't match, so each script keeps its original basename
	// (de-duplicated with an index suffix) rather than being renamed to
	// something generic -- that signal would otherwise be thrown away.
	fileToURL := map[string]string{}
	used := map[string]bool{}
	for _, sf := range crawl.Scripts {
		name := scratchName(used, sf.URL)
		if err := os.WriteFile(filepath.Join(dir, name), sf.Body, 0o600); err != nil {
			continue
		}
		fileToURL[name] = sf.URL
	}

	cmd := exec.CommandContext(ctx, "retire", "--path", dir, "--outputformat", "json", "--nocache")
	// retire's own exit code is non-zero the moment it finds anything at
	// or above --severity (default "none", so any finding at all) -- that's
	// signal, not failure, so stdout is what's trusted here, not Wait's
	// error. A hard failure to even run shows up as empty/invalid stdout,
	// checked below.
	out, _ := cmd.Output()

	var parsed retireOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, fmt.Errorf("retire: unreadable output (is retire installed correctly?): %w", err)
	}

	var findings []Finding
	for _, file := range parsed.Data {
		url := fileToURL[filepath.Base(file.File)]
		if url == "" {
			url = file.File
		}
		for _, res := range file.Results {
			for _, vuln := range res.Vulnerabilities {
				sev := normalizeRetireSeverity(vuln.Severity)
				label := fmt.Sprintf("%s %s: %s", res.Component, res.Version, vuln.Identifiers.Summary)
				var detail strings.Builder
				if vuln.Below != "" {
					detail.WriteString("vulnerable below " + vuln.Below)
					if vuln.AtOrAbove != "" {
						detail.WriteString(" (at or above " + vuln.AtOrAbove + ")")
					}
				}
				if len(vuln.Identifiers.CVE) > 0 {
					if detail.Len() > 0 {
						detail.WriteString(" -- ")
					}
					detail.WriteString(strings.Join(vuln.Identifiers.CVE, ", "))
				}
				findings = append(findings, Finding{
					Label:    label,
					URL:      url,
					Detail:   detail.String(),
					Evidence: res.Component + "@" + res.Version,
					Severity: sev,
				})
			}
		}
	}
	if findings == nil {
		findings = []Finding{}
	}
	return findings, nil
}

// scratchName returns the file name a downloaded script is written under. It
// keeps the script's own base name, because retire also identifies libraries by
// filename. It appends a -N suffix until the name is unused, comparing
// case-insensitively because the scratch directory may sit on a case-insensitive
// filesystem, and it records the chosen name in used.
func scratchName(used map[string]bool, rawURL string) string {
	name := filepath.Base(rawURL)
	if idx := strings.IndexAny(name, "?#"); idx >= 0 {
		name = name[:idx]
	}
	if name == "" || name == "." || name == "/" {
		name = "script.js"
	}
	if !strings.HasSuffix(strings.ToLower(name), ".js") {
		name += ".js"
	}
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	candidate := name
	// Try the bare name first, then base-1.js, base-2.js, and so on, until one is free.
	for n := 1; used[strings.ToLower(candidate)]; n++ {
		candidate = base + "-" + strconv.Itoa(n) + ext
	}
	used[strings.ToLower(candidate)] = true
	return candidate
}

// normalizeRetireSeverity maps retire.js's own severity strings onto
// Aperture's info/low/medium/high/critical scale -- retire uses that same
// set today, but this keeps an unrecognized future value from producing an
// empty/invalid severity instead of just degrading to "medium".
func normalizeRetireSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical", "high", "medium", "low":
		return strings.ToLower(s)
	default:
		return "medium"
	}
}
