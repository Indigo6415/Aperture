package report

// reportHTML is a self-contained (no external assets) HTML page, so it
// renders identically whether opened directly or printed to PDF headlessly.
const reportHTML = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Aperture case report: {{.Case.Name}}</title>
<style>
  body { font-family: -apple-system, Helvetica, Arial, sans-serif; color: #1a1a1a; margin: 2rem; }
  h1 { font-size: 1.4rem; margin-bottom: 0.1rem; }
  h2 { font-size: 1.05rem; margin-top: 2rem; border-bottom: 1px solid #ccc; padding-bottom: 0.2rem; }
  .meta { color: #666; font-size: 0.85rem; margin-bottom: 1.5rem; }
  table { border-collapse: collapse; width: 100%; font-size: 0.8rem; margin-top: 0.5rem; }
  th, td { border: 1px solid #ddd; padding: 4px 8px; text-align: left; word-break: break-all; }
  th { background: #f2f2f2; }
  .status-2 { color: #0a7d2f; } .status-3 { color: #0a5fd9; } .status-4 { color: #b5860b; } .status-5 { color: #c9302c; }
  .domain-block { margin-bottom: 1rem; }
  .badge { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 0.7rem; margin-right: 4px; }
  .badge-error { background: #fdecea; color: #c9302c; }
  .badge-done { background: #eafaf0; color: #0a7d2f; }
</style>
</head>
<body>
  <h1>Case report: {{.Case.Name}}</h1>
  {{if .Case.Description}}<div class="meta">{{.Case.Description}}</div>{{end}}
  <div class="meta">
    Case created {{.Case.CreatedAt.Format "2006-01-02 15:04:05 MST"}} &middot;
    Report generated {{.GeneratedAt.Format "2006-01-02 15:04:05 MST"}} &middot;
    {{len .Targets}} target(s) &middot;
    {{findingCount .}} total finding(s) across {{len .Jobs}} job(s)
  </div>

  <h2>Identify checks</h2>
  {{range targets .}}
  <div class="domain-block">
    <strong>{{.Target}}</strong>
    {{range .Checks}}
      <div><span class="badge {{if eq (print .Status) "error"}}badge-error{{else}}badge-done{{end}}">{{.Kind}}: {{.Status}}</span>
      {{if .Error}}{{.Error}}{{end}}</div>
    {{end}}
  </div>
  {{end}}

  <h2>Jobs</h2>
  <table>
    <thead><tr><th>Tool</th><th>Targets</th><th>Status</th><th>Started</th><th>Findings</th></tr></thead>
    <tbody>
    {{range .Jobs}}
      <tr>
        <td>{{.Tool}}</td>
        <td>{{range $i, $t := .Targets}}{{if $i}}, {{end}}{{$t}}{{end}}</td>
        <td>{{.Status}}</td>
        <td>{{.CreatedAt.Format "2006-01-02 15:04:05"}}</td>
        <td>{{len (index $.Findings .RunID)}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>

  {{range .Jobs}}
  {{$fs := index $.Findings .RunID}}
  {{if $fs}}
  <h2>{{.Tool}} findings</h2>
  <table>
    <thead><tr><th>Status</th><th>URL</th><th>Size</th><th>Words</th><th>Lines</th><th>Tool</th></tr></thead>
    <tbody>
    {{range $fs}}
      <tr>
        <td>{{.StatusCode}}</td>
        <td>{{.URL}}</td>
        <td>{{.ContentLength}}</td>
        <td>{{.Words}}</td>
        <td>{{.Lines}}</td>
        <td>{{.SourceTool}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
  {{end}}
  {{end}}
</body>
</html>
`
