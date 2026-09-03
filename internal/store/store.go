// Package store persists flows, runs, and findings to a local SQLite
// database (pure Go driver, no CGO) so the whole application stays a
// single static executable.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/Indigo6415/Aperture/internal/engine"
	"github.com/Indigo6415/Aperture/internal/model"
	"github.com/Indigo6415/Aperture/internal/recon"
)

type Store struct {
	db *sql.DB
}

// Open opens (creating if necessary) the SQLite database at path and
// applies the schema.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	// SQLite only tolerates one writer at a time; a single connection
	// avoids "database is locked" errors under concurrent goroutines.
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS flows (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	definition TEXT NOT NULL,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
	id TEXT PRIMARY KEY,
	flow_id TEXT NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
	status TEXT NOT NULL,
	error TEXT,
	started_at DATETIME NOT NULL,
	finished_at DATETIME
);
CREATE INDEX IF NOT EXISTS idx_runs_flow_id ON runs(flow_id);

CREATE TABLE IF NOT EXISTS findings (
	id TEXT NOT NULL,
	run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
	node_id TEXT NOT NULL,
	url TEXT NOT NULL,
	status_code INTEGER NOT NULL,
	content_length INTEGER NOT NULL,
	words INTEGER NOT NULL,
	lines INTEGER NOT NULL,
	content_type TEXT,
	redirect_location TEXT,
	method TEXT,
	headers TEXT,
	source_tool TEXT NOT NULL,
	tags TEXT,
	timestamp DATETIME NOT NULL,
	PRIMARY KEY (id, node_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_run_id ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_node_id ON findings(run_id, node_id);

CREATE TABLE IF NOT EXISTS scans (
	id TEXT PRIMARY KEY,
	domain TEXT NOT NULL,
	flow_id TEXT,
	run_id TEXT,
	created_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_checks (
	scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
	domain TEXT NOT NULL,
	kind TEXT NOT NULL,
	status TEXT NOT NULL,
	data TEXT,
	error TEXT,
	started_at DATETIME NOT NULL,
	finished_at DATETIME,
	PRIMARY KEY (scan_id, domain, kind)
);
CREATE INDEX IF NOT EXISTS idx_scan_checks_scan_id ON scan_checks(scan_id);
`
	_, err := s.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	return nil
}

// --- Flows ---

func (s *Store) SaveFlow(f engine.Flow) error {
	def, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("store: marshal flow: %w", err)
	}
	now := time.Now()
	_, err = s.db.Exec(`
		INSERT INTO flows (id, name, definition, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, definition=excluded.definition, updated_at=excluded.updated_at
	`, f.ID, f.Name, string(def), now, now)
	if err != nil {
		return fmt.Errorf("store: save flow: %w", err)
	}
	return nil
}

func (s *Store) GetFlow(id string) (engine.Flow, error) {
	var def string
	err := s.db.QueryRow(`SELECT definition FROM flows WHERE id = ?`, id).Scan(&def)
	if err == sql.ErrNoRows {
		return engine.Flow{}, fmt.Errorf("store: flow %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return engine.Flow{}, fmt.Errorf("store: get flow: %w", err)
	}
	var f engine.Flow
	if err := json.Unmarshal([]byte(def), &f); err != nil {
		return engine.Flow{}, fmt.Errorf("store: decode flow: %w", err)
	}
	return f, nil
}

type FlowSummary struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (s *Store) ListFlows() ([]FlowSummary, error) {
	rows, err := s.db.Query(`SELECT id, name, updated_at FROM flows ORDER BY updated_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: list flows: %w", err)
	}
	defer rows.Close()

	out := []FlowSummary{}
	for rows.Next() {
		var fs FlowSummary
		if err := rows.Scan(&fs.ID, &fs.Name, &fs.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: scan flow: %w", err)
		}
		out = append(out, fs)
	}
	return out, rows.Err()
}

func (s *Store) DeleteFlow(id string) error {
	_, err := s.db.Exec(`DELETE FROM flows WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete flow: %w", err)
	}
	return nil
}

// --- Runs ---

type RunStatus string

const (
	RunPending   RunStatus = "pending"
	RunRunning   RunStatus = "running"
	RunSucceeded RunStatus = "succeeded"
	RunFailed    RunStatus = "failed"
)

type Run struct {
	ID         string     `json:"id"`
	FlowID     string     `json:"flowId"`
	Status     RunStatus  `json:"status"`
	Error      string     `json:"error,omitempty"`
	StartedAt  time.Time  `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
}

func (s *Store) CreateRun(id, flowID string) error {
	_, err := s.db.Exec(`INSERT INTO runs (id, flow_id, status, started_at) VALUES (?, ?, ?, ?)`,
		id, flowID, RunRunning, time.Now())
	if err != nil {
		return fmt.Errorf("store: create run: %w", err)
	}
	return nil
}

func (s *Store) FinishRun(id string, status RunStatus, errMsg string) error {
	_, err := s.db.Exec(`UPDATE runs SET status = ?, error = ?, finished_at = ? WHERE id = ?`,
		status, errMsg, time.Now(), id)
	if err != nil {
		return fmt.Errorf("store: finish run: %w", err)
	}
	return nil
}

func (s *Store) GetRun(id string) (Run, error) {
	var r Run
	var finishedAt sql.NullTime
	var errMsg sql.NullString
	err := s.db.QueryRow(`SELECT id, flow_id, status, error, started_at, finished_at FROM runs WHERE id = ?`, id).
		Scan(&r.ID, &r.FlowID, &r.Status, &errMsg, &r.StartedAt, &finishedAt)
	if err == sql.ErrNoRows {
		return Run{}, fmt.Errorf("store: run %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return Run{}, fmt.Errorf("store: get run: %w", err)
	}
	r.Error = errMsg.String
	if finishedAt.Valid {
		r.FinishedAt = &finishedAt.Time
	}
	return r, nil
}

func (s *Store) ListRuns(flowID string) ([]Run, error) {
	rows, err := s.db.Query(`SELECT id, flow_id, status, error, started_at, finished_at FROM runs WHERE flow_id = ? ORDER BY started_at DESC`, flowID)
	if err != nil {
		return nil, fmt.Errorf("store: list runs: %w", err)
	}
	defer rows.Close()

	out := []Run{}
	for rows.Next() {
		var r Run
		var finishedAt sql.NullTime
		var errMsg sql.NullString
		if err := rows.Scan(&r.ID, &r.FlowID, &r.Status, &errMsg, &r.StartedAt, &finishedAt); err != nil {
			return nil, fmt.Errorf("store: scan run: %w", err)
		}
		r.Error = errMsg.String
		if finishedAt.Valid {
			r.FinishedAt = &finishedAt.Time
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- Findings ---

func (s *Store) SaveFinding(runID, nodeID string, f model.Finding) error {
	headers, err := json.Marshal(f.Headers)
	if err != nil {
		return fmt.Errorf("store: marshal headers: %w", err)
	}
	tags, err := json.Marshal(f.Tags)
	if err != nil {
		return fmt.Errorf("store: marshal tags: %w", err)
	}
	// A finding keeps its ID as it passes through multiple nodes (filter,
	// merge, table, ...), so (id, node_id) is the natural primary key: one
	// row per finding per node it reached. OR IGNORE covers the rare case
	// of the same finding reaching one node twice via a diamond-shaped
	// graph with dedup disabled.
	_, err = s.db.Exec(`
		INSERT OR IGNORE INTO findings (id, run_id, node_id, url, status_code, content_length, words, lines, content_type, redirect_location, method, headers, source_tool, tags, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, f.ID, runID, nodeID, f.URL, f.StatusCode, f.ContentLength, f.Words, f.Lines, f.ContentType, f.RedirectLoc, f.Method, string(headers), f.SourceTool, string(tags), f.Timestamp)
	if err != nil {
		return fmt.Errorf("store: save finding: %w", err)
	}
	return nil
}

// ListFindings returns every finding recorded for a run, optionally
// restricted to one node (pass "" for nodeID to get all of them).
func (s *Store) ListFindings(runID, nodeID string) ([]model.Finding, error) {
	query := `SELECT id, run_id, node_id, url, status_code, content_length, words, lines, content_type, redirect_location, method, headers, source_tool, tags, timestamp FROM findings WHERE run_id = ?`
	args := []any{runID}
	if nodeID != "" {
		query += ` AND node_id = ?`
		args = append(args, nodeID)
	}
	query += ` ORDER BY timestamp ASC`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list findings: %w", err)
	}
	defer rows.Close()

	out := []model.Finding{}
	for rows.Next() {
		var f model.Finding
		var headers, tags sql.NullString
		var contentType, redirectLoc, method sql.NullString
		if err := rows.Scan(&f.ID, &f.RunID, &f.SourceNodeID, &f.URL, &f.StatusCode, &f.ContentLength, &f.Words, &f.Lines, &contentType, &redirectLoc, &method, &headers, &f.SourceTool, &tags, &f.Timestamp); err != nil {
			return nil, fmt.Errorf("store: scan finding: %w", err)
		}
		f.ContentType = contentType.String
		f.RedirectLoc = redirectLoc.String
		f.Method = method.String
		if headers.Valid && headers.String != "" && headers.String != "null" {
			_ = json.Unmarshal([]byte(headers.String), &f.Headers)
		}
		if tags.Valid && tags.String != "" && tags.String != "null" {
			_ = json.Unmarshal([]byte(tags.String), &f.Tags)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// --- Scans ---

// Scan is one "enter a domain" dashboard run: the recon checks plus the
// auto-generated ffuf/feroxbuster flow it kicks off alongside them.
// FlowID/RunID are empty until the HTTP check resolves and the flow can be
// built (see api.handleStartScan), so callers should tolerate either being
// unset for a brief window right after creation.
type Scan struct {
	ID        string    `json:"id"`
	Domain    string    `json:"domain"`
	FlowID    string    `json:"flowId,omitempty"`
	RunID     string    `json:"runId,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

func (s *Store) CreateScan(id, domain string) error {
	_, err := s.db.Exec(`INSERT INTO scans (id, domain, created_at) VALUES (?, ?, ?)`, id, domain, time.Now())
	if err != nil {
		return fmt.Errorf("store: create scan: %w", err)
	}
	return nil
}

// SetScanFlow links the auto-generated flow/run onto a scan once they've
// been created (this happens slightly after CreateScan, once the apex HTTP
// check has determined which scheme to point ffuf/feroxbuster at).
func (s *Store) SetScanFlow(id, flowID, runID string) error {
	_, err := s.db.Exec(`UPDATE scans SET flow_id = ?, run_id = ? WHERE id = ?`, flowID, runID, id)
	if err != nil {
		return fmt.Errorf("store: set scan flow: %w", err)
	}
	return nil
}

func (s *Store) GetScan(id string) (Scan, error) {
	var sc Scan
	var flowID, runID sql.NullString
	err := s.db.QueryRow(`SELECT id, domain, flow_id, run_id, created_at FROM scans WHERE id = ?`, id).
		Scan(&sc.ID, &sc.Domain, &flowID, &runID, &sc.CreatedAt)
	if err == sql.ErrNoRows {
		return Scan{}, fmt.Errorf("store: scan %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return Scan{}, fmt.Errorf("store: get scan: %w", err)
	}
	sc.FlowID = flowID.String
	sc.RunID = runID.String
	return sc, nil
}

func (s *Store) ListScans() ([]Scan, error) {
	rows, err := s.db.Query(`SELECT id, domain, flow_id, run_id, created_at FROM scans ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: list scans: %w", err)
	}
	defer rows.Close()

	out := []Scan{}
	for rows.Next() {
		var sc Scan
		var flowID, runID sql.NullString
		if err := rows.Scan(&sc.ID, &sc.Domain, &flowID, &runID, &sc.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: scan row: %w", err)
		}
		sc.FlowID = flowID.String
		sc.RunID = runID.String
		out = append(out, sc)
	}
	return out, rows.Err()
}

// --- Scan checks ---

func (s *Store) SaveCheck(scanID string, c recon.Check) error {
	data, err := json.Marshal(c.Data)
	if err != nil {
		return fmt.Errorf("store: marshal check data: %w", err)
	}
	_, err = s.db.Exec(`
		INSERT INTO scan_checks (scan_id, domain, kind, status, data, error, started_at, finished_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(scan_id, domain, kind) DO UPDATE SET
			status=excluded.status, data=excluded.data, error=excluded.error, finished_at=excluded.finished_at
	`, scanID, c.Domain, c.Kind, c.Status, string(data), c.Error, c.StartedAt, c.FinishedAt)
	if err != nil {
		return fmt.Errorf("store: save check: %w", err)
	}
	return nil
}

// ListChecks returns every check recorded for a scan, in the order they
// were started, so a client reloading a past scan sees them roughly as
// they originally streamed in.
func (s *Store) ListChecks(scanID string) ([]recon.Check, error) {
	rows, err := s.db.Query(`SELECT domain, kind, status, data, error, started_at, finished_at FROM scan_checks WHERE scan_id = ? ORDER BY started_at ASC`, scanID)
	if err != nil {
		return nil, fmt.Errorf("store: list checks: %w", err)
	}
	defer rows.Close()

	out := []recon.Check{}
	for rows.Next() {
		var c recon.Check
		var data, errMsg sql.NullString
		var finishedAt sql.NullTime
		if err := rows.Scan(&c.Domain, &c.Kind, &c.Status, &data, &errMsg, &c.StartedAt, &finishedAt); err != nil {
			return nil, fmt.Errorf("store: scan check row: %w", err)
		}
		c.Error = errMsg.String
		if finishedAt.Valid {
			c.FinishedAt = finishedAt.Time
		}
		if data.Valid && data.String != "" && data.String != "null" {
			_ = json.Unmarshal([]byte(data.String), &c.Data)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

var ErrNotFound = fmt.Errorf("not found")
