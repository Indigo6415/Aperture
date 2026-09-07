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
	register(&NmapAdapter{})
}

// NmapConfig is the node-configurable shape for an nmap run. Port/service
// scanning has no natural fit in model.Finding (which is HTTP-response
// shaped), so an open port is emitted as a Finding whose URL is a
// "<proto>://<host>:<port>/" pseudo-URL, ContentType carries the detected
// service name, Tags carries [state, proto], and -- only when ServiceDetect
// found something -- Headers carries "version". Enough for the frontend's
// dedicated ports table to render without needing a second result type
// threaded through the whole engine/store/hub pipeline.
type NmapConfig struct {
	Target   string `json:"target"`             // host or IP to scan
	Ports    string `json:"ports,omitempty"`    // nmap -p value; empty means nmap's default (top 1000)
	FastScan bool   `json:"fastScan,omitempty"` // nmap -F: scan fewer ports, faster
	// ServiceDetect enables nmap -sV (service/version detection): probing
	// each open port to identify the actual product and version behind it,
	// not just the port-number-based guess a plain scan reports. It's much
	// slower per port, which is why it's opt-in and (see
	// buildServiceProfileFlow in api/handlers_scan.go) only ever pointed at
	// ports a prior plain scan already found open, instead of being the
	// default for every port scan.
	ServiceDetect bool     `json:"serviceDetect,omitempty"`
	Timeout       int      `json:"timeoutSeconds,omitempty"` // per-host timeout, seconds (nmap --host-timeout)
	ExtraArgs     []string `json:"extraArgs,omitempty"`
}

type NmapAdapter struct{}

func (a *NmapAdapter) Name() string { return "nmap" }

func (a *NmapAdapter) Run(ctx context.Context, config json.RawMessage, meta RunMeta, emit Emit, progress Progress) error {
	var cfg NmapConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return &ErrConfig{Adapter: a.Name(), Err: err}
	}
	if cfg.Target == "" {
		return &ErrConfig{Adapter: a.Name(), Err: fmt.Errorf("target is required")}
	}

	// -Pn skips nmap's own host-discovery ping (the target already resolved
	// during recon, so a firewall dropping ICMP shouldn't make nmap think
	// it's down and skip it); --open only reports ports actually open,
	// which is the only state worth surfacing as a Finding; -oG - writes
	// greppable output to stdout for line-by-line parsing as it streams.
	args := []string{"-Pn", "--open", "-oG", "-"}
	if cfg.FastScan {
		args = append(args, "-F")
	}
	if cfg.ServiceDetect {
		args = append(args, "-sV")
	}
	if cfg.Ports != "" {
		args = append(args, "-p", cfg.Ports)
	}
	if cfg.Timeout > 0 {
		args = append(args, "--host-timeout", strconv.Itoa(cfg.Timeout)+"s")
	}
	args = append(args, cfg.ExtraArgs...)
	args = append(args, cfg.Target)

	cmd := exec.CommandContext(ctx, "nmap", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("nmap: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("nmap: start: %w (is nmap installed and on PATH?)", err)
	}

	if progress != nil {
		// Port count depends on nmap's own defaults/-F/-p, none of which are
		// worth re-deriving here just for a percentage -- indeterminate.
		progress(0, 0)
	}

	done := 0
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		host, ports, ok := parseNmapGrepLine(line)
		if !ok {
			continue
		}
		for _, f := range parseNmapPorts(host, ports, meta) {
			emit(f)
			done++
			progress(done, 0)
		}
	}

	waitErr := cmd.Wait()
	if scanErr := scanner.Err(); scanErr != nil {
		return fmt.Errorf("nmap: reading output: %w", scanErr)
	}
	if progress != nil {
		progress(done, 0)
	}
	if waitErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("nmap: %w", waitErr)
	}
	return nil
}

// parseNmapGrepLine extracts the host and the raw "Ports:" field from one
// -oG output line, e.g.:
//
//	Host: 93.184.216.34 ()	Ports: 80/open/tcp//http///, 443/open/tcp//https///
func parseNmapGrepLine(line string) (host, ports string, ok bool) {
	if !strings.HasPrefix(line, "Host: ") {
		return "", "", false
	}
	fields := strings.SplitN(line, "\t", -1)
	if len(fields) < 2 {
		return "", "", false
	}
	hostField := strings.TrimPrefix(fields[0], "Host: ")
	host = strings.TrimSpace(strings.SplitN(hostField, " ", 2)[0])
	for _, f := range fields[1:] {
		if strings.HasPrefix(f, "Ports: ") {
			return host, strings.TrimPrefix(f, "Ports: "), host != ""
		}
	}
	return "", "", false
}

// parseNmapPorts turns a -oG "Ports:" field's comma-separated entries into
// one Finding per open port. Each entry's slash-separated fields are
// port/state/protocol/owner/service/rpc/version/ (that final slash is a
// terminator, not an 8th field -- splitting always yields a trailing empty
// string). version is only ever populated when the run used -sV (see
// NmapConfig.ServiceDetect) -- a plain scan leaves it blank, so the Finding
// below gets a nil Headers map rather than one holding an empty string; when
// it is populated, nmap has already folded any extra info (OS, build,
// hostname, ...) into it, e.g. "Apache httpd 2.4.41 ((Ubuntu))".
func parseNmapPorts(host, ports string, meta RunMeta) []model.Finding {
	var out []model.Finding
	for _, entry := range strings.Split(ports, ", ") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		f := strings.Split(entry, "/")
		if len(f) < 5 || f[1] != "open" {
			continue
		}
		port, protocol, service := f[0], f[2], f[4]
		if service == "" {
			service = "unknown"
		}
		var headers map[string]string
		if len(f) > 6 && f[6] != "" {
			headers = map[string]string{"version": f[6]}
		}
		out = append(out, model.Finding{
			ID:           newFindingID(),
			URL:          fmt.Sprintf("%s://%s:%s/", protocol, host, port),
			ContentType:  service,
			Method:       "PORT",
			Headers:      headers,
			Tags:         []string{"open", protocol},
			SourceTool:   "nmap",
			SourceNodeID: meta.NodeID,
			RunID:        meta.RunID,
			Timestamp:    time.Now(),
		})
	}
	return out
}
