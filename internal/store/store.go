// Package store persists flows, runs, and findings to a local SQLite
// database (pure Go driver, no CGO) so the whole application stays a
// single static executable.
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"

	"github.com/Indigo6415/Aperture/internal/engine"
	"github.com/Indigo6415/Aperture/internal/model"
	"github.com/Indigo6415/Aperture/internal/recon"
)

// randomID generates a random 128-bit hex identifier, for the rare row this
// package creates the ID for itself (only EnsureDefaultUser -- every other
// table's ID is minted by the api package and passed in).
func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

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

-- A Case is a named container the user builds up over time: targets they've
-- added or promoted, and jobs (tool runs) launched against them. Nothing
-- about a case is tied to a single domain -- that's the whole point of the
-- redesign away from the old one-domain-per-scan model.
CREATE TABLE IF NOT EXISTS cases (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	description TEXT,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL
);

-- A target is any host/URL/IP the user has explicitly added to a case,
-- either typed by hand or promoted from a job's results (see
-- api.handlePromoteTargets). UNIQUE(case_id, value) makes promoting an
-- already-known value a harmless no-op via INSERT OR IGNORE rather than a
-- duplicate row.
CREATE TABLE IF NOT EXISTS targets (
	id TEXT PRIMARY KEY,
	case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
	value TEXT NOT NULL,
	kind TEXT,
	source_tool TEXT,
	source_job_id TEXT,
	notes TEXT,
	created_at DATETIME NOT NULL,
	UNIQUE(case_id, value)
);
CREATE INDEX IF NOT EXISTS idx_targets_case_id ON targets(case_id);

-- A job is one user-launched tool run against one or more targets --
-- feroxbuster/ffuf-subdomain/ffuf-vhost jobs drive an engine.Flow (flow_id/
-- run_id set); an identify job runs internal/recon directly and has no flow
-- underneath (flow_id/run_id left empty), see api.runIdentifyJob.
CREATE TABLE IF NOT EXISTS jobs (
	id TEXT PRIMARY KEY,
	case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
	tool TEXT NOT NULL,
	flow_id TEXT,
	run_id TEXT,
	targets TEXT NOT NULL,
	config TEXT,
	status TEXT NOT NULL,
	error TEXT,
	created_at DATETIME NOT NULL,
	finished_at DATETIME
);
CREATE INDEX IF NOT EXISTS idx_jobs_case_id ON jobs(case_id);

CREATE TABLE IF NOT EXISTS case_checks (
	case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
	target TEXT NOT NULL,
	kind TEXT NOT NULL,
	status TEXT NOT NULL,
	data TEXT,
	error TEXT,
	job_id TEXT NOT NULL,
	started_at DATETIME NOT NULL,
	finished_at DATETIME,
	PRIMARY KEY (case_id, target, kind)
);
CREATE INDEX IF NOT EXISTS idx_case_checks_case_id ON case_checks(case_id);

-- One screenshot per case+target, captured opportunistically by an identify
-- job once a target's HTTP check resolves a live URL for it (see
-- api.captureScreenshot). Currently unused: screenshotPreviewEnabled is off.
CREATE TABLE IF NOT EXISTS case_screenshots (
	case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
	target TEXT NOT NULL,
	url TEXT NOT NULL,
	image BLOB NOT NULL,
	captured_at DATETIME NOT NULL,
	PRIMARY KEY (case_id, target)
);

-- App-wide key/value settings (e.g. the DNSDumpster API key) -- deliberately
-- just one flat table since there's currently only ever one operator/one
-- copy of each setting, not per-user config.
CREATE TABLE IF NOT EXISTS settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

-- Caches NVD lookups (see internal/cve) keyed by the fingerprinted
-- product+version, so repeat scans against common software (nginx,
-- WordPress, jQuery, ...) don't re-hit NVD's rate-limited API every time,
-- and old lookups still work offline. fetched_at backs the caller's own TTL
-- check (see cveCacheTTL in api/handlers_scan.go) -- CVEs for a given
-- product/version can still gain new entries over time, so this isn't
-- cached forever.
CREATE TABLE IF NOT EXISTS cve_cache (
	product TEXT NOT NULL,
	version TEXT NOT NULL,
	data TEXT NOT NULL,
	fetched_at DATETIME NOT NULL,
	PRIMARY KEY (product, version)
);

CREATE TABLE IF NOT EXISTS users (
	id TEXT PRIMARY KEY,
	email TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	created_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
	token TEXT PRIMARY KEY,
	user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	created_at DATETIME NOT NULL,
	expires_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
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

// --- Runs ---

type RunStatus string

const (
	RunPending   RunStatus = "pending"
	RunRunning   RunStatus = "running"
	RunSucceeded RunStatus = "succeeded"
	RunFailed    RunStatus = "failed"
	RunCancelled RunStatus = "cancelled"
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

// --- Cases ---

// Case is a named container the user builds up over time: a set of Targets
// plus every Job launched against them. Unlike the old Scan, a Case has no
// single domain of its own.
type Case struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

func (s *Store) CreateCase(id, name, description string) error {
	now := time.Now()
	_, err := s.db.Exec(`INSERT INTO cases (id, name, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		id, name, description, now, now)
	if err != nil {
		return fmt.Errorf("store: create case: %w", err)
	}
	return nil
}

func (s *Store) GetCase(id string) (Case, error) {
	var c Case
	var description sql.NullString
	err := s.db.QueryRow(`SELECT id, name, description, created_at, updated_at FROM cases WHERE id = ?`, id).
		Scan(&c.ID, &c.Name, &description, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return Case{}, fmt.Errorf("store: case %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return Case{}, fmt.Errorf("store: get case: %w", err)
	}
	c.Description = description.String
	return c, nil
}

func (s *Store) ListCases() ([]Case, error) {
	rows, err := s.db.Query(`SELECT id, name, description, created_at, updated_at FROM cases ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: list cases: %w", err)
	}
	defer rows.Close()

	out := []Case{}
	for rows.Next() {
		var c Case
		var description sql.NullString
		if err := rows.Scan(&c.ID, &c.Name, &description, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: case row: %w", err)
		}
		c.Description = description.String
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteCase removes a case and (via ON DELETE CASCADE) every target/job/
// check/screenshot belonging to it. It does not cascade into runs/findings,
// since those are keyed by run_id and jobs.run_id has no FK to enforce it --
// orphaned runs/findings for a deleted case's jobs are harmless dead rows,
// consistent with how flows/runs already outlive whatever created them.
func (s *Store) DeleteCase(id string) error {
	_, err := s.db.Exec(`DELETE FROM cases WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete case: %w", err)
	}
	return nil
}

// --- Targets ---

type Target struct {
	ID          string    `json:"id"`
	CaseID      string    `json:"caseId"`
	Value       string    `json:"value"`
	Kind        string    `json:"kind,omitempty"`
	SourceTool  string    `json:"sourceTool,omitempty"`
	SourceJobID string    `json:"sourceJobId,omitempty"`
	Notes       string    `json:"notes,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
}

// AddTarget records a target, or does nothing if this case already has one
// with the same value -- INSERT OR IGNORE on the (case_id, value) unique
// constraint is what makes re-promoting an already-known value harmless
// rather than an error the caller has to special-case.
func (s *Store) AddTarget(t Target) error {
	_, err := s.db.Exec(`
		INSERT OR IGNORE INTO targets (id, case_id, value, kind, source_tool, source_job_id, notes, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, t.ID, t.CaseID, t.Value, t.Kind, t.SourceTool, t.SourceJobID, t.Notes, time.Now())
	if err != nil {
		return fmt.Errorf("store: add target: %w", err)
	}
	return nil
}

func (s *Store) ListTargets(caseID string) ([]Target, error) {
	rows, err := s.db.Query(`
		SELECT id, case_id, value, kind, source_tool, source_job_id, notes, created_at
		FROM targets WHERE case_id = ? ORDER BY created_at ASC
	`, caseID)
	if err != nil {
		return nil, fmt.Errorf("store: list targets: %w", err)
	}
	defer rows.Close()

	out := []Target{}
	for rows.Next() {
		var t Target
		var kind, sourceTool, sourceJobID, notes sql.NullString
		if err := rows.Scan(&t.ID, &t.CaseID, &t.Value, &kind, &sourceTool, &sourceJobID, &notes, &t.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: target row: %w", err)
		}
		t.Kind = kind.String
		t.SourceTool = sourceTool.String
		t.SourceJobID = sourceJobID.String
		t.Notes = notes.String
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetTargetByValue looks up one target by its case + exact value, used by
// promotion to report back the (possibly pre-existing) target a value
// resolved to.
func (s *Store) GetTargetByValue(caseID, value string) (Target, error) {
	var t Target
	var kind, sourceTool, sourceJobID, notes sql.NullString
	err := s.db.QueryRow(`
		SELECT id, case_id, value, kind, source_tool, source_job_id, notes, created_at
		FROM targets WHERE case_id = ? AND value = ?
	`, caseID, value).Scan(&t.ID, &t.CaseID, &t.Value, &kind, &sourceTool, &sourceJobID, &notes, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return Target{}, fmt.Errorf("store: target %s/%s: %w", caseID, value, ErrNotFound)
	}
	if err != nil {
		return Target{}, fmt.Errorf("store: get target by value: %w", err)
	}
	t.Kind = kind.String
	t.SourceTool = sourceTool.String
	t.SourceJobID = sourceJobID.String
	t.Notes = notes.String
	return t, nil
}

func (s *Store) DeleteTarget(id string) error {
	_, err := s.db.Exec(`DELETE FROM targets WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete target: %w", err)
	}
	return nil
}

// --- Jobs ---

// Job is one user-launched tool run against one or more targets. flow_id/
// run_id are empty for an identify job, which has no engine.Flow underneath
// -- see api.runIdentifyJob.
type Job struct {
	ID         string     `json:"id"`
	CaseID     string     `json:"caseId"`
	Tool       string     `json:"tool"`
	FlowID     string     `json:"flowId,omitempty"`
	RunID      string     `json:"runId,omitempty"`
	Targets    []string   `json:"targets"`
	Config     string     `json:"config,omitempty"` // raw JSON, opaque to store
	Status     RunStatus  `json:"status"`
	Error      string     `json:"error,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
}

func (s *Store) CreateJob(j Job) error {
	targetsJSON, err := json.Marshal(j.Targets)
	if err != nil {
		return fmt.Errorf("store: marshal job targets: %w", err)
	}
	_, err = s.db.Exec(`
		INSERT INTO jobs (id, case_id, tool, flow_id, run_id, targets, config, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, j.ID, j.CaseID, j.Tool, j.FlowID, j.RunID, string(targetsJSON), j.Config, j.Status, time.Now())
	if err != nil {
		return fmt.Errorf("store: create job: %w", err)
	}
	return nil
}

// FinishJob records a job's terminal status directly on the jobs row --
// authoritative for identify jobs (which have no runs row to join against);
// for engine-backed jobs this mirrors what executeToolJob already wrote to
// the runs table via FinishRun, kept in sync so ListCaseJobs' status column
// is correct even before its LEFT JOIN would otherwise resolve it.
func (s *Store) FinishJob(id string, status RunStatus, errMsg string) error {
	_, err := s.db.Exec(`UPDATE jobs SET status = ?, error = ?, finished_at = ? WHERE id = ?`,
		status, errMsg, time.Now(), id)
	if err != nil {
		return fmt.Errorf("store: finish job: %w", err)
	}
	return nil
}

func (s *Store) GetJob(id string) (Job, error) {
	var j Job
	var flowID, runID, config, errMsg, targets sql.NullString
	var finishedAt sql.NullTime
	err := s.db.QueryRow(`
		SELECT id, case_id, tool, flow_id, run_id, targets, config, status, error, created_at, finished_at
		FROM jobs WHERE id = ?
	`, id).Scan(&j.ID, &j.CaseID, &j.Tool, &flowID, &runID, &targets, &config, &j.Status, &errMsg, &j.CreatedAt, &finishedAt)
	if err == sql.ErrNoRows {
		return Job{}, fmt.Errorf("store: job %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return Job{}, fmt.Errorf("store: get job: %w", err)
	}
	j.FlowID = flowID.String
	j.RunID = runID.String
	j.Config = config.String
	j.Error = errMsg.String
	if targets.Valid && targets.String != "" && targets.String != "null" {
		_ = json.Unmarshal([]byte(targets.String), &j.Targets)
	}
	if finishedAt.Valid {
		j.FinishedAt = &finishedAt.Time
	}
	return j, nil
}

// ListCaseJobs returns every job belonging to a case, in the order they
// were started. For engine-backed jobs (flow_id/run_id set) the live status
// comes from a LEFT JOIN onto runs, since that's updated the moment the
// engine finishes rather than waiting for FinishJob; identify jobs (no
// run_id) fall back to the jobs table's own status column.
func (s *Store) ListCaseJobs(caseID string) ([]Job, error) {
	// Status/error are merged via COALESCE (TEXT columns, so no decltype to
	// lose) but finished_at is selected from both sides separately and
	// merged in Go instead -- COALESCE on two DATETIME columns loses the
	// column's declared type, so the sqlite driver hands back a raw string
	// instead of converting it to time.Time, which sql.NullTime can't Scan.
	rows, err := s.db.Query(`
		SELECT j.id, j.case_id, j.tool, j.flow_id, j.run_id, j.targets, j.config,
			COALESCE(r.status, j.status), COALESCE(r.error, j.error), j.created_at,
			r.finished_at, j.finished_at
		FROM jobs j
		LEFT JOIN runs r ON r.id = j.run_id
		WHERE j.case_id = ?
		ORDER BY j.created_at ASC
	`, caseID)
	if err != nil {
		return nil, fmt.Errorf("store: list case jobs: %w", err)
	}
	defer rows.Close()

	out := []Job{}
	for rows.Next() {
		var j Job
		var flowID, runID, config, errMsg, targets sql.NullString
		var runFinishedAt, jobFinishedAt sql.NullTime
		if err := rows.Scan(&j.ID, &j.CaseID, &j.Tool, &flowID, &runID, &targets, &config, &j.Status, &errMsg, &j.CreatedAt, &runFinishedAt, &jobFinishedAt); err != nil {
			return nil, fmt.Errorf("store: job row: %w", err)
		}
		j.FlowID = flowID.String
		j.RunID = runID.String
		j.Config = config.String
		j.Error = errMsg.String
		if targets.Valid && targets.String != "" && targets.String != "null" {
			_ = json.Unmarshal([]byte(targets.String), &j.Targets)
		}
		if runFinishedAt.Valid {
			j.FinishedAt = &runFinishedAt.Time
		} else if jobFinishedAt.Valid {
			j.FinishedAt = &jobFinishedAt.Time
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// ToolRunning reports whether a case already has a job of tool currently
// running -- callers use this to refuse starting a duplicate, overlapping
// run of the same tool rather than piling up redundant subprocesses.
func (s *Store) ToolRunning(caseID, tool string) (bool, error) {
	var running bool
	err := s.db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM jobs j LEFT JOIN runs r ON r.id = j.run_id
			WHERE j.case_id = ? AND j.tool = ? AND COALESCE(r.status, j.status) = 'running'
		)
	`, caseID, tool).Scan(&running)
	if err != nil {
		return false, fmt.Errorf("store: tool running: %w", err)
	}
	return running, nil
}

// TargetRunning reports whether target is currently covered by a running
// job of tool for this case -- used for a per-target restart instead of
// ToolRunning's whole-tool check, so restarting one target doesn't get
// blocked by (or itself block) a different target's job of the same tool.
func (s *Store) TargetRunning(caseID, tool, target string) (bool, error) {
	rows, err := s.db.Query(`
		SELECT j.targets FROM jobs j LEFT JOIN runs r ON r.id = j.run_id
		WHERE j.case_id = ? AND j.tool = ? AND COALESCE(r.status, j.status) = 'running'
	`, caseID, tool)
	if err != nil {
		return false, fmt.Errorf("store: target running: %w", err)
	}
	defer rows.Close()

	needle := strings.ToLower(target)
	for rows.Next() {
		var targets sql.NullString
		if err := rows.Scan(&targets); err != nil {
			return false, fmt.Errorf("store: target running row: %w", err)
		}
		if !targets.Valid || targets.String == "" || targets.String == "null" {
			continue
		}
		var list []string
		if err := json.Unmarshal([]byte(targets.String), &list); err != nil {
			continue
		}
		for _, t := range list {
			if strings.ToLower(t) == needle {
				return true, rows.Err()
			}
		}
	}
	return false, rows.Err()
}

// --- Case aggregates (for the case list) ---

func (s *Store) CaseTargetCount(caseID string) (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM targets WHERE case_id = ?`, caseID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("store: case target count: %w", err)
	}
	return count, nil
}

func (s *Store) CaseJobCount(caseID string) (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM jobs WHERE case_id = ?`, caseID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("store: case job count: %w", err)
	}
	return count, nil
}

// CaseFindingCount counts findings reaching the terminal table sink
// ("table") across every job belonging to a case.
func (s *Store) CaseFindingCount(caseID string) (int, error) {
	var count int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM findings f
		JOIN jobs j ON j.run_id = f.run_id
		WHERE j.case_id = ? AND f.node_id = 'table'
	`, caseID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("store: case finding count: %w", err)
	}
	return count, nil
}

// CaseRunning reports whether any job for a case is still in progress, so
// the case list can show a "running..." vs "idle" pill.
func (s *Store) CaseRunning(caseID string) (bool, error) {
	var running bool
	err := s.db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM jobs j LEFT JOIN runs r ON r.id = j.run_id
			WHERE j.case_id = ? AND COALESCE(r.status, j.status) = 'running'
		)
	`, caseID).Scan(&running)
	if err != nil {
		return false, fmt.Errorf("store: case running: %w", err)
	}
	return running, nil
}

// --- Case checks (identify job results) ---

func (s *Store) SaveCaseCheck(caseID, jobID string, c recon.Check) error {
	data, err := json.Marshal(c.Data)
	if err != nil {
		return fmt.Errorf("store: marshal check data: %w", err)
	}
	_, err = s.db.Exec(`
		INSERT INTO case_checks (case_id, target, kind, status, data, error, job_id, started_at, finished_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(case_id, target, kind) DO UPDATE SET
			status=excluded.status, data=excluded.data, error=excluded.error, job_id=excluded.job_id, finished_at=excluded.finished_at
	`, caseID, c.Domain, c.Kind, c.Status, string(data), c.Error, jobID, c.StartedAt, c.FinishedAt)
	if err != nil {
		return fmt.Errorf("store: save case check: %w", err)
	}
	return nil
}

// ListCaseChecks returns every identify check recorded for a case, in the
// order they were started, so a client reloading a case sees them roughly
// as they originally streamed in.
func (s *Store) ListCaseChecks(caseID string) ([]recon.Check, error) {
	rows, err := s.db.Query(`SELECT target, kind, status, data, error, started_at, finished_at FROM case_checks WHERE case_id = ? ORDER BY started_at ASC`, caseID)
	if err != nil {
		return nil, fmt.Errorf("store: list case checks: %w", err)
	}
	defer rows.Close()

	out := []recon.Check{}
	for rows.Next() {
		var c recon.Check
		var data, errMsg sql.NullString
		var finishedAt sql.NullTime
		if err := rows.Scan(&c.Domain, &c.Kind, &c.Status, &data, &errMsg, &c.StartedAt, &finishedAt); err != nil {
			return nil, fmt.Errorf("store: case check row: %w", err)
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

// --- Case screenshots ---

// ScreenshotMeta is a screenshot's metadata without its image bytes, for
// listing what's available without pulling every PNG over the wire.
type ScreenshotMeta struct {
	Target     string    `json:"target"`
	URL        string    `json:"url"`
	CapturedAt time.Time `json:"capturedAt"`
}

// SaveCaseScreenshot upserts the captured PNG for one case+target -- a
// re-capture (e.g. a re-run identify job) replaces the previous image
// rather than accumulating history, since only the latest view of a target
// is useful.
func (s *Store) SaveCaseScreenshot(caseID, target, url string, image []byte) error {
	_, err := s.db.Exec(`
		INSERT INTO case_screenshots (case_id, target, url, image, captured_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(case_id, target) DO UPDATE SET url=excluded.url, image=excluded.image, captured_at=excluded.captured_at
	`, caseID, target, url, image, time.Now())
	if err != nil {
		return fmt.Errorf("store: save case screenshot: %w", err)
	}
	return nil
}

// ListCaseScreenshots returns metadata for every screenshot captured so far
// for a case, so the UI knows which targets have a thumbnail to fetch.
func (s *Store) ListCaseScreenshots(caseID string) ([]ScreenshotMeta, error) {
	rows, err := s.db.Query(`SELECT target, url, captured_at FROM case_screenshots WHERE case_id = ? ORDER BY target ASC`, caseID)
	if err != nil {
		return nil, fmt.Errorf("store: list case screenshots: %w", err)
	}
	defer rows.Close()

	out := []ScreenshotMeta{}
	for rows.Next() {
		var m ScreenshotMeta
		if err := rows.Scan(&m.Target, &m.URL, &m.CapturedAt); err != nil {
			return nil, fmt.Errorf("store: case screenshot row: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// GetCaseScreenshot returns one target's captured PNG bytes.
func (s *Store) GetCaseScreenshot(caseID, target string) ([]byte, error) {
	var image []byte
	err := s.db.QueryRow(`SELECT image FROM case_screenshots WHERE case_id = ? AND target = ?`, caseID, target).Scan(&image)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("store: case screenshot %s/%s: %w", caseID, target, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("store: get case screenshot: %w", err)
	}
	return image, nil
}

// HasCaseScreenshot reports whether a screenshot already exists for
// caseID + target, so the capture pipeline can skip a target it's already
// shot instead of re-launching a browser for it on every check that fires.
func (s *Store) HasCaseScreenshot(caseID, target string) (bool, error) {
	var exists bool
	err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM case_screenshots WHERE case_id = ? AND target = ?)`, caseID, target).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("store: has case screenshot: %w", err)
	}
	return exists, nil
}

// --- Settings ---

// SetSetting upserts one app-wide setting (e.g. "dnsdumpster_api_key").
// Passing an empty value clears it in the sense that GetSetting will still
// return it (ok=true, value=""), so callers that treat "" as "not
// configured" work the same either way.
func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`
		INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value
	`, key, value)
	if err != nil {
		return fmt.Errorf("store: set setting: %w", err)
	}
	return nil
}

// GetSetting returns a setting's value and whether it's been set at all.
func (s *Store) GetSetting(key string) (value string, ok bool, err error) {
	err = s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("store: get setting: %w", err)
	}
	return value, true, nil
}

// --- CVE cache ---

// GetCVECache returns a cached NVD lookup's raw JSON and when it was
// fetched, and whether one exists at all. Callers decide whether fetchedAt
// is still fresh enough to use (see cveCacheTTL in api/handlers_scan.go)
// rather than this layer enforcing any particular TTL.
func (s *Store) GetCVECache(product, version string) (data string, fetchedAt time.Time, ok bool, err error) {
	err = s.db.QueryRow(`SELECT data, fetched_at FROM cve_cache WHERE product = ? AND version = ?`, product, version).Scan(&data, &fetchedAt)
	if err == sql.ErrNoRows {
		return "", time.Time{}, false, nil
	}
	if err != nil {
		return "", time.Time{}, false, fmt.Errorf("store: get cve cache: %w", err)
	}
	return data, fetchedAt, true, nil
}

// SetCVECache upserts one product+version's raw NVD lookup result.
func (s *Store) SetCVECache(product, version, data string) error {
	_, err := s.db.Exec(`
		INSERT INTO cve_cache (product, version, data, fetched_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(product, version) DO UPDATE SET data=excluded.data, fetched_at=excluded.fetched_at
	`, product, version, data, time.Now())
	if err != nil {
		return fmt.Errorf("store: set cve cache: %w", err)
	}
	return nil
}

// --- Users & sessions ---

// User is one login account. PasswordHash is never serialized out through
// the API -- callers that need it (VerifyPassword) get it internally only.
type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"createdAt"`
}

// CreateUserWithPassword hashes password with bcrypt and inserts a new
// user -- the only place a plaintext password is ever handled on its way
// into storage.
func (s *Store) CreateUserWithPassword(id, email, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("store: hash password: %w", err)
	}
	_, err = s.db.Exec(`INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)`,
		id, strings.ToLower(email), string(hash), time.Now())
	if err != nil {
		return fmt.Errorf("store: create user: %w", err)
	}
	return nil
}

// UserCount reports how many accounts exist, so the caller can decide
// whether to seed a default one on first run.
func (s *Store) UserCount() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: user count: %w", err)
	}
	return n, nil
}

// EnsureDefaultUser seeds one login (email/password) iff no users exist yet
// -- called once at startup so a fresh install always has something to log
// in with, without ever overwriting or recreating an account someone has
// since changed, renamed, or deleted.
func (s *Store) EnsureDefaultUser(email, password string) error {
	n, err := s.UserCount()
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	return s.CreateUserWithPassword(randomID(), email, password)
}

// VerifyPassword looks up email and checks password against its stored
// bcrypt hash. ok is false for both "no such user" and "wrong password" --
// callers must not distinguish the two in any user-facing response, since
// doing so would let an attacker enumerate valid emails.
func (s *Store) VerifyPassword(email, password string) (User, bool, error) {
	var u User
	var hash string
	err := s.db.QueryRow(`SELECT id, email, password_hash, created_at FROM users WHERE email = ?`, strings.ToLower(email)).
		Scan(&u.ID, &u.Email, &hash, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, fmt.Errorf("store: verify password: %w", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return User{}, false, nil
	}
	return u, true, nil
}

// CreateSession records a new login session token for userID, valid until
// expiresAt.
func (s *Store) CreateSession(token, userID string, expiresAt time.Time) error {
	_, err := s.db.Exec(`INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		token, userID, time.Now(), expiresAt)
	if err != nil {
		return fmt.Errorf("store: create session: %w", err)
	}
	return nil
}

// GetSessionUser resolves a session token to its user, treating an expired
// session the same as a nonexistent one (ErrNotFound) -- it also deletes
// the row in that case so expired sessions don't pile up indefinitely.
func (s *Store) GetSessionUser(token string) (User, error) {
	var u User
	var expiresAt time.Time
	err := s.db.QueryRow(`
		SELECT u.id, u.email, u.created_at, s.expires_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token = ?
	`, token).Scan(&u.ID, &u.Email, &u.CreatedAt, &expiresAt)
	if err == sql.ErrNoRows {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("store: get session: %w", err)
	}
	if time.Now().After(expiresAt) {
		_ = s.DeleteSession(token)
		return User{}, ErrNotFound
	}
	return u, nil
}

// DeleteSession removes a session token (logout, or a lazily-noticed
// expiry in GetSessionUser).
func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token = ?`, token)
	if err != nil {
		return fmt.Errorf("store: delete session: %w", err)
	}
	return nil
}

var ErrNotFound = fmt.Errorf("not found")
