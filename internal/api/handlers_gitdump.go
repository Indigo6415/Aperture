package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/gitdump"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
	"github.com/Indigo6415/Aperture/internal/store"
)

// gitDumpRequest is the request body for POST /api/gitdump/scan. One target
// dumps directly; several are each checked for an exposed .git first, and only
// the exposed ones are dumped.
type gitDumpRequest struct {
	// Targets are URLs or bare hosts, one entry each.
	Targets []string `json:"targets"`
	// RequestsPerSecond is the scan speed the Slow/Normal/Fast/Custom control sends; zero means scanRate's default.
	RequestsPerSecond float64 `json:"requestsPerSecond,omitempty"`
	// CredentialID optionally names a saved case credential merged into Headers -- same shape as every other tool's request.
	CredentialID string            `json:"credentialId,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	// CaseID optionally scopes this run to a case -- see secretScanRequest.CaseID's doc comment.
	CaseID string `json:"caseId,omitempty"`
}

// gitDumpTimeout bounds a whole run across every target. A repository with a
// long history can take many round trips, so this is far more generous than
// the single-request timeouts the other tools use.
const gitDumpTimeout = 30 * time.Minute

// maxGitDumpTargets caps how many targets one request may name, so one POST
// can't queue an unbounded crawl.
const maxGitDumpTargets = 200

// bucketIDPattern is the shape newID produces. Download requests are checked
// against it before any path is built from them.
var bucketIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// gitDumpTarget is one target's entry in the scan result. Result is embedded
// so its fields appear at the top level of the JSON. BucketID is set only
// when the target was exposed and its zip was written.
type gitDumpTarget struct {
	*gitdump.Result
	Input    string `json:"input"`
	BucketID string `json:"bucketId,omitempty"`
	ZipBytes int64  `json:"zipBytes,omitempty"`
	Error    string `json:"error,omitempty"`
}

// gitDumpResult is the full result a finished git dump scan hands back.
type gitDumpResult struct {
	Targets []gitDumpTarget `json:"targets"`
}

// SetGitDumpDir records where dumped buckets are written. Dumps are served for
// download from here, so the server refuses to start a dump until it's set.
func (s *Server) SetGitDumpDir(dir string) { s.gitDumpDir = dir }

// handleGitDump validates a git dump request and queues it as a streamed scan.
// The dump itself runs when the browser subscribes to the scan's WebSocket,
// like every other streamed scanner.
func (s *Server) handleGitDump(w http.ResponseWriter, r *http.Request) {
	var req gitDumpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	rps, err := scanRate(req.RequestsPerSecond)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	targets := cleanTargets(req.Targets)
	if len(targets) == 0 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("at least one target is required"))
		return
	}
	if len(targets) > maxGitDumpTargets {
		writeError(w, http.StatusBadRequest, fmt.Errorf("at most %d targets per run", maxGitDumpTargets))
		return
	}
	// Every target is parsed up front, so a malformed one is reported before the
	// run starts instead of as a failed entry partway through.
	for _, t := range targets {
		if _, err := gitdump.Candidates(t); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	if s.gitDumpDir == "" {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("git dump directory is not configured"))
		return
	}

	// Each target is checked against the case scope before anything is queued.
	// queueScan's own check only sees one string, so it can't cover a list.
	scope, err := s.scopeFor(req.CaseID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := checkTargetsInScope(scope, targets...); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if req.CredentialID != "" {
		cred, err := s.store.GetCredential(req.CredentialID)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusBadRequest, fmt.Errorf("credential %s not found", req.CredentialID))
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		req.Headers = mergedCredentialHeaders(cred, req.Headers)
	}

	s.queueScan(w, streamedScan{
		rps:     rps,
		caseID:  req.CaseID,
		target:  strings.Join(targets, ", "),
		tool:    "gitdump",
		timeout: gitDumpTimeout,
		run: func(ctx context.Context, rep scanprogress.Reporter) (scanOutcome, error) {
			return s.runGitDump(ctx, rep, req.CaseID, targets, req.Headers)
		},
	})
}

// cleanTargets trims each target, drops blanks, and removes repeats while
// keeping the order the operator entered them in.
func cleanTargets(in []string) []string {
	seen := map[string]bool{}
	var out []string
	// Each pass takes one entered target.
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

// runGitDump dumps every target in turn and summarizes the outcome. One target
// failing doesn't stop the rest; only cancellation does.
func (s *Server) runGitDump(ctx context.Context, rep scanprogress.Reporter, caseID string, targets []string, headers map[string]string) (scanOutcome, error) {
	checks := make([]scanprogress.Check, len(targets))
	// Each pass names one target's check, so its progress events have a stable ID.
	for i, t := range targets {
		checks[i] = scanprogress.Check{ID: fmt.Sprintf("target-%d", i), Label: t, Group: "Git exposure"}
	}
	rep.Plan(checks...)

	out := gitDumpResult{Targets: make([]gitDumpTarget, 0, len(targets))}
	exposed, files := 0, 0
	// Each pass dumps one target and records its outcome.
	for i, t := range targets {
		if err := ctx.Err(); err != nil {
			return scanOutcome{}, err
		}
		rep.Start(checks[i].ID)
		entry, err := s.dumpGitTarget(ctx, rep, t, s.applyDomainCookie(caseID, t, headers))
		if err != nil {
			entry.Error = err.Error()
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return scanOutcome{}, ctxErr
		}
		if entry.Exposed {
			exposed++
			files += entry.Files
		}
		findings := 0
		if entry.Exposed {
			findings = 1
		}
		rep.Done(checks[i].ID, findings, err)
		out.Targets = append(out.Targets, entry)
	}

	// Any exposed repository is a high-severity finding, since it's source code
	// and history the operator never meant to publish.
	severity := "info"
	if exposed > 0 {
		severity = "high"
	}
	summary := fmt.Sprintf("git exposed on %d of %d target(s); %d file(s) restored", exposed, len(targets), files)
	return scanOutcome{result: out, severity: severity, summary: summary}, nil
}

// dumpGitTarget dumps one target into a fresh bucket. An unexposed target
// leaves no bucket behind. An exposed one gets a zip, which is what the UI
// downloads. A dump that failed partway still keeps and zips what it got.
func (s *Server) dumpGitTarget(ctx context.Context, rep scanprogress.Reporter, target string, headers map[string]string) (gitDumpTarget, error) {
	bucketID := newID()
	dir := filepath.Join(s.gitDumpDir, bucketID)
	res, err := gitdump.Dump(ctx, target, dir, gitdump.Options{Headers: headers, Progress: rep})
	entry := gitDumpTarget{Result: res, Input: target}
	if !res.Exposed {
		os.RemoveAll(dir)
		return entry, err
	}

	zipPath := filepath.Join(s.gitDumpDir, bucketID+".zip")
	if zerr := gitdump.Zip(dir, res.Host, zipPath); zerr != nil {
		return entry, errors.Join(err, fmt.Errorf("zip bucket: %w", zerr))
	}
	entry.BucketID = bucketID
	if info, statErr := os.Stat(zipPath); statErr == nil {
		entry.ZipBytes = info.Size()
	}
	return entry, err
}

// handleGitDumpDownload serves a finished bucket's zip. The ID is checked
// against bucketIDPattern before a path is built from it.
func (s *Server) handleGitDumpDownload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !bucketIDPattern.MatchString(id) || s.gitDumpDir == "" {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(filepath.Join(s.gitDumpDir, id+".zip"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="gitdump-%s.zip"`, id))
	http.ServeContent(w, r, "", info.ModTime(), f)
}
