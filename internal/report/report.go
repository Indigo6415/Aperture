// Package report bundles one scan's recon checks and scanner findings into
// a downloadable report -- JSON (a direct data dump), HTML (a rendered
// summary a person can read in a browser), and PDF (the same HTML, printed
// headlessly by whichever Chrome/Chromium binary internal/adapters already
// knows how to find for screenshots). This is what wires engine.KindExport's
// underlying idea -- collecting a run's results and writing them out in a
// chosen format -- to an actual UI action, extended to cover a whole scan
// (every scanner run + every recon check) rather than one flow's export
// node.
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

// Report is everything gathered about one scan, in the shape both the JSON
// and HTML/PDF renderers work from.
type Report struct {
	Scan        store.Scan                 `json:"scan"`
	GeneratedAt time.Time                  `json:"generatedAt"`
	Checks      []recon.Check              `json:"checks"`
	ScanRuns    []store.ScanRun            `json:"scanRuns"`
	Findings    map[string][]model.Finding `json:"findings"` // keyed by ScanRun.RunID
}

// Build gathers everything store knows about scanID into a Report.
func Build(st *store.Store, scanID string) (Report, error) {
	sc, err := st.GetScan(scanID)
	if err != nil {
		return Report{}, fmt.Errorf("report: get scan: %w", err)
	}
	checks, err := st.ListChecks(scanID)
	if err != nil {
		return Report{}, fmt.Errorf("report: list checks: %w", err)
	}
	runs, err := st.ListScanRuns(scanID)
	if err != nil {
		return Report{}, fmt.Errorf("report: list scan runs: %w", err)
	}

	findings := make(map[string][]model.Finding, len(runs))
	for _, run := range runs {
		fs, err := st.ListFindings(run.RunID, "table")
		if err != nil {
			return Report{}, fmt.Errorf("report: list findings for run %s: %w", run.RunID, err)
		}
		findings[run.RunID] = fs
	}

	return Report{Scan: sc, GeneratedAt: time.Now(), Checks: checks, ScanRuns: runs, Findings: findings}, nil
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

// checksByDomain groups checks by domain, apex first then alphabetically,
// so the HTML report reads as one block per host instead of one flat list
// interleaving apex and subdomain checks.
func (r Report) checksByDomain() []domainChecks {
	byDomain := map[string][]recon.Check{}
	for _, c := range r.Checks {
		byDomain[c.Domain] = append(byDomain[c.Domain], c)
	}
	domains := make([]string, 0, len(byDomain))
	for d := range byDomain {
		domains = append(domains, d)
	}
	sort.Slice(domains, func(i, j int) bool {
		if domains[i] == r.Scan.Domain {
			return true
		}
		if domains[j] == r.Scan.Domain {
			return false
		}
		return domains[i] < domains[j]
	})
	out := make([]domainChecks, 0, len(domains))
	for _, d := range domains {
		out = append(out, domainChecks{Domain: d, Checks: byDomain[d]})
	}
	return out
}

type domainChecks struct {
	Domain string
	Checks []recon.Check
}

var reportTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"findingCount": func(r Report) int { return r.findingCount() },
	"domains":      func(r Report) []domainChecks { return r.checksByDomain() },
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
