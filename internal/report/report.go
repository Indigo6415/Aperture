// Package report bundles one case's targets, identify checks, and job
// findings into a downloadable report -- JSON (a direct data dump), HTML (a
// rendered summary a person can read in a browser), and PDF (the same HTML,
// printed headlessly by whichever Chrome/Chromium binary internal/adapters
// already knows how to find for screenshots). This is what wires
// engine.KindExport's underlying idea -- collecting a run's results and
// writing them out in a chosen format -- to an actual UI action, extended
// to cover a whole case (every job + every identify check) rather than one
// flow's export node.
package report

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"sort"
	"time"

	"github.com/Indigo6415/Aperture/internal/adapters"
	"github.com/Indigo6415/Aperture/internal/model"
	"github.com/Indigo6415/Aperture/internal/recon"
	"github.com/Indigo6415/Aperture/internal/store"
)

// Report is everything gathered about one case, in the shape both the JSON
// and HTML/PDF renderers work from.
type Report struct {
	Case        store.Case                 `json:"case"`
	Targets     []store.Target             `json:"targets"`
	GeneratedAt time.Time                  `json:"generatedAt"`
	Checks      []recon.Check              `json:"checks"`
	Jobs        []store.Job                `json:"jobs"`
	Findings    map[string][]model.Finding `json:"findings"` // keyed by Job.RunID (absent for identify jobs)
}

// Build gathers everything store knows about caseID into a Report.
func Build(st *store.Store, caseID string) (Report, error) {
	c, err := st.GetCase(caseID)
	if err != nil {
		return Report{}, fmt.Errorf("report: get case: %w", err)
	}
	targets, err := st.ListTargets(caseID)
	if err != nil {
		return Report{}, fmt.Errorf("report: list targets: %w", err)
	}
	checks, err := st.ListCaseChecks(caseID)
	if err != nil {
		return Report{}, fmt.Errorf("report: list checks: %w", err)
	}
	jobs, err := st.ListCaseJobs(caseID)
	if err != nil {
		return Report{}, fmt.Errorf("report: list jobs: %w", err)
	}

	findings := make(map[string][]model.Finding, len(jobs))
	for _, job := range jobs {
		if job.RunID == "" {
			continue
		}
		fs, err := st.ListFindings(job.RunID, "table")
		if err != nil {
			return Report{}, fmt.Errorf("report: list findings for job %s: %w", job.ID, err)
		}
		findings[job.RunID] = fs
	}

	return Report{Case: c, Targets: targets, GeneratedAt: time.Now(), Checks: checks, Jobs: jobs, Findings: findings}, nil
}

// RenderJSON marshals the report as indented JSON.
func (r Report) RenderJSON() ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("report: marshal json: %w", err)
	}
	return b, nil
}

// findingCount totals findings across every scanner run, for the HTML
// template's summary line.
func (r Report) findingCount() int {
	n := 0
	for _, fs := range r.Findings {
		n += len(fs)
	}
	return n
}

// checksByTarget groups checks by target, in the case's target creation
// order (falling back to alphabetical for a target with checks but no
// corresponding Targets row, e.g. one from a deleted target), so the HTML
// report reads as one block per target instead of one flat list.
func (r Report) checksByTarget() []targetChecks {
	byTarget := map[string][]recon.Check{}
	for _, c := range r.Checks {
		byTarget[c.Domain] = append(byTarget[c.Domain], c)
	}
	order := make([]string, 0, len(r.Targets))
	seen := map[string]bool{}
	for _, t := range r.Targets {
		if _, ok := byTarget[t.Value]; ok && !seen[t.Value] {
			order = append(order, t.Value)
			seen[t.Value] = true
		}
	}
	var rest []string
	for target := range byTarget {
		if !seen[target] {
			rest = append(rest, target)
		}
	}
	sort.Strings(rest)
	order = append(order, rest...)

	out := make([]targetChecks, 0, len(order))
	for _, target := range order {
		out = append(out, targetChecks{Target: target, Checks: byTarget[target]})
	}
	return out
}

type targetChecks struct {
	Target string
	Checks []recon.Check
}

var reportTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"findingCount": func(r Report) int { return r.findingCount() },
	"targets":      func(r Report) []targetChecks { return r.checksByTarget() },
}).Parse(reportHTML))

// RenderHTML executes the report template into a standalone HTML page (no
// external assets, so it's equally valid saved to disk or printed to PDF).
func (r Report) RenderHTML() ([]byte, error) {
	var buf bytes.Buffer
	if err := reportTemplate.Execute(&buf, r); err != nil {
		return nil, fmt.Errorf("report: render html: %w", err)
	}
	return buf.Bytes(), nil
}

// RenderPDF renders the report to HTML and prints it to PDF via whichever
// headless-Chrome-compatible binary adapters.FindChromeBinary locates.
func (r Report) RenderPDF(ctx context.Context) ([]byte, error) {
	chrome, err := adapters.FindChromeBinary()
	if err != nil {
		return nil, fmt.Errorf("report: pdf export needs a headless-Chrome-compatible browser: %w", err)
	}

	html, err := r.RenderHTML()
	if err != nil {
		return nil, err
	}
	htmlFile, err := os.CreateTemp("", "aperture-report-*.html")
	if err != nil {
		return nil, fmt.Errorf("report: create temp html: %w", err)
	}
	defer os.Remove(htmlFile.Name())
	if _, err := htmlFile.Write(html); err != nil {
		htmlFile.Close()
		return nil, fmt.Errorf("report: write temp html: %w", err)
	}
	if err := htmlFile.Close(); err != nil {
		return nil, fmt.Errorf("report: close temp html: %w", err)
	}

	pdfFile, err := os.CreateTemp("", "aperture-report-*.pdf")
	if err != nil {
		return nil, fmt.Errorf("report: create temp pdf: %w", err)
	}
	pdfPath := pdfFile.Name()
	pdfFile.Close()
	defer os.Remove(pdfPath)

	args := []string{
		"--headless=new",
		"--disable-gpu",
		"--no-sandbox",
		"--print-to-pdf=" + pdfPath,
		"--no-pdf-header-footer",
		"file://" + htmlFile.Name(),
	}
	cmd := exec.CommandContext(ctx, chrome, args...)
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("report: %s: %w", chrome, err)
	}

	pdf, err := os.ReadFile(pdfPath)
	if err != nil {
		return nil, fmt.Errorf("report: read pdf: %w", err)
	}
	return pdf, nil
}
