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

CREATE TABLE IF NOT EXISTS scans (
	id TEXT PRIMARY KEY,
	domain TEXT NOT NULL,
	scheme TEXT,
	created_at DATETIME NOT NULL
);

-- One scan fans out into several independently-run scanners (content
-- discovery, subdomain bruteforce, vhost bruteforce); content discovery in
-- particular can accumulate more than one run as the user rescans a
-- filtered subdomain selection, so this is a scan -> many-runs table rather
-- than columns on scans itself.
CREATE TABLE IF NOT EXISTS scan_runs (
	scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
	kind TEXT NOT NULL,
	flow_id TEXT NOT NULL,
	run_id TEXT NOT NULL,
	targets TEXT,
	created_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_runs_scan_id ON scan_runs(scan_id);

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

-- One screenshot per scan+hostname, captured opportunistically once a host's
-- HTTP recon check resolves a live URL for it (see api.captureScreenshot).
CREATE TABLE IF NOT EXISTS screenshots (
	scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
	hostname TEXT NOT NULL,
	url TEXT NOT NULL,
	image BLOB NOT NULL,
	captured_at DATETIME NOT NULL,
	PRIMARY KEY (scan_id, hostname)
);

-- App-wide key/value settings (e.g. the DNSDumpster API key) -- deliberately
-- just one flat table since there's currently only ever one operator/one
-- copy of each setting, not per-user config.
CREATE TABLE IF NOT EXISTS settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
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
	// Columns added after the tables above first shipped; ALTER TABLE ADD
	// COLUMN is the only way to bring an existing on-disk database forward
	// since CREATE TABLE IF NOT EXISTS never alters an existing table. The
	// "duplicate column" error is SQLite's way of saying "already migrated",
	// which is expected and fine on every run after the first.
	alters := []string{
		`ALTER TABLE scans ADD COLUMN scheme TEXT`,
		`ALTER TABLE scans ADD COLUMN options TEXT`,
		`ALTER TABLE scan_runs ADD COLUMN targets TEXT`,
	}
	for _, stmt := range alters {
		if _, err := s.db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("store: migrate: %s: %w", stmt, err)
		}
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

// --- Scans ---

// Scan is one "enter a domain" dashboard run: the recon checks plus every
// scanner (content discovery, subdomain bruteforce, vhost bruteforce) it
// kicks off alongside them -- see ScanRun for those. Scheme is empty until
// the apex HTTP check resolves it (see api.runScan), so callers should
// tolerate it being unset for a brief window right after creation.
type Scan struct {
	ID        string    `json:"id"`
	Domain    string    `json:"domain"`
	Scheme    string    `json:"scheme,omitempty"`
	Options   string    `json:"options,omitempty"` // raw JSON (engine.ScanOptions); opaque to store
	CreatedAt time.Time `json:"createdAt"`
}

// CreateScan records a new scan. options is the raw JSON-encoded per-scan
// tuning (thread count/timeout/wordlist/rate limit preset) every scanner
// flow this scan builds should read back via GetScan -- pass "" to fall
// back to the engine-wide defaults.
func (s *Store) CreateScan(id, domain, options string) error {
	_, err := s.db.Exec(`INSERT INTO scans (id, domain, options, created_at) VALUES (?, ?, ?, ?)`, id, domain, options, time.Now())
	if err != nil {
		return fmt.Errorf("store: create scan: %w", err)
	}
	return nil
}

// SetScanScheme records which scheme (http/https) the apex domain answered
// on, once the apex HTTP check resolves it -- every scanner built for this
// scan afterwards (including a later "scan selected subdomains" content
// discovery run) reuses it instead of re-probing.
func (s *Store) SetScanScheme(id, scheme string) error {
	_, err := s.db.Exec(`UPDATE scans SET scheme = ? WHERE id = ?`, scheme, id)
	if err != nil {
		return fmt.Errorf("store: set scan scheme: %w", err)
	}
	return nil
}

func (s *Store) GetScan(id string) (Scan, error) {
	var sc Scan
	var scheme, options sql.NullString
	err := s.db.QueryRow(`SELECT id, domain, scheme, options, created_at FROM scans WHERE id = ?`, id).
		Scan(&sc.ID, &sc.Domain, &scheme, &options, &sc.CreatedAt)
	if err == sql.ErrNoRows {
		return Scan{}, fmt.Errorf("store: scan %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return Scan{}, fmt.Errorf("store: get scan: %w", err)
	}
	sc.Scheme = scheme.String
	sc.Options = options.String
	return sc, nil
}

func (s *Store) ListScans() ([]Scan, error) {
	rows, err := s.db.Query(`SELECT id, domain, scheme, options, created_at FROM scans ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: list scans: %w", err)
	}
	defer rows.Close()

	out := []Scan{}
	for rows.Next() {
		var sc Scan
		var scheme, options sql.NullString
		if err := rows.Scan(&sc.ID, &sc.Domain, &scheme, &options, &sc.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: scan row: %w", err)
		}
		sc.Scheme = scheme.String
		sc.Options = options.String
		out = append(out, sc)
	}
	return out, rows.Err()
}

// --- Scan runs ---

// ScanKind identifies which of a scan's independent scanners a ScanRun
// belongs to.
type ScanKind string

const (
	ScanKindContentDiscovery    ScanKind = "content-discovery"
	ScanKindSubdomainBruteforce ScanKind = "subdomain-bruteforce"
	ScanKindVHostBruteforce     ScanKind = "vhost-bruteforce"
	ScanKindPortScan            ScanKind = "port-scan"
	ScanKindVulnScan            ScanKind = "vuln-scan"
	ScanKindServiceProfile      ScanKind = "service-profile"
)

// ScanRun is one scanner run belonging to a scan. A scan can own several --
// content discovery in particular accumulates one per "scan selected
// subdomains" click, in addition to its initial apex-only run.
type ScanRun struct {
	Kind      ScanKind  `json:"kind"`
	FlowID    string    `json:"flowId"`
	RunID     string    `json:"runId"`
	Status    RunStatus `json:"status"`
	Targets   []string  `json:"targets,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// CreateScanRun records a new scanner run. targets is the set of hostnames
// this run covers (e.g. the content-discovery targets it was built
// against) -- used by CoveredTargets to figure out what's already been (or
// is being) scanned so a later "scan selected"/restart doesn't redundantly
// re-scan the same hosts. Pass nil for scanners with no per-target concept
// (subdomain/vhost bruteforce).
func (s *Store) CreateScanRun(scanID string, kind ScanKind, flowID, runID string, targets []string) error {
	targetsJSON, err := json.Marshal(targets)
	if err != nil {
		return fmt.Errorf("store: marshal scan run targets: %w", err)
	}
	_, err = s.db.Exec(`INSERT INTO scan_runs (scan_id, kind, flow_id, run_id, targets, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		scanID, kind, flowID, runID, string(targetsJSON), time.Now())
	if err != nil {
		return fmt.Errorf("store: create scan run: %w", err)
	}
	return nil
}

// ListScanRuns returns every scanner run for a scan, joined with its
// current run status, in the order they were started -- so a client
// reloading a past scan can reconstruct which scanners exist and reopen a
// watch on any still running.
func (s *Store) ListScanRuns(scanID string) ([]ScanRun, error) {
	rows, err := s.db.Query(`
		SELECT sr.kind, sr.flow_id, sr.run_id, r.status, sr.targets, sr.created_at
		FROM scan_runs sr
		JOIN runs r ON r.id = sr.run_id
		WHERE sr.scan_id = ?
		ORDER BY sr.created_at ASC
	`, scanID)
	if err != nil {
		return nil, fmt.Errorf("store: list scan runs: %w", err)
	}
	defer rows.Close()

	out := []ScanRun{}
	for rows.Next() {
		var r ScanRun
		var targets sql.NullString
		if err := rows.Scan(&r.Kind, &r.FlowID, &r.RunID, &r.Status, &targets, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: scan run row: %w", err)
		}
		if targets.Valid && targets.String != "" && targets.String != "null" {
			_ = json.Unmarshal([]byte(targets.String), &r.Targets)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ScanRunRef identifies which scan + scanner kind a run_id belongs to --
// looked up when a run finishes and the caller (executeRun) needs to decide
// whether finishing it should trigger another scanner (e.g. a
// content-discovery run completing kicks off a vuln-scan against its hits).
type ScanRunRef struct {
	ScanID string
	Kind   ScanKind
}

// GetScanRunByRunID looks up which scan + scanner kind a run_id belongs to.
func (s *Store) GetScanRunByRunID(runID string) (ScanRunRef, error) {
	var ref ScanRunRef
	err := s.db.QueryRow(`SELECT scan_id, kind FROM scan_runs WHERE run_id = ?`, runID).Scan(&ref.ScanID, &ref.Kind)
	if err == sql.ErrNoRows {
		return ScanRunRef{}, fmt.Errorf("store: scan run for run %s: %w", runID, ErrNotFound)
	}
	if err != nil {
		return ScanRunRef{}, fmt.Errorf("store: get scan run by run id: %w", err)
	}
	return ref, nil
}

// KindRunning reports whether a scan already has a scanner run of kind
// currently running -- callers use this to refuse starting a duplicate,
// overlapping run of the same kind rather than piling up redundant
// subprocesses while one is already in flight.
func (s *Store) KindRunning(scanID string, kind ScanKind) (bool, error) {
	var running bool
	err := s.db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM scan_runs sr JOIN runs r ON r.id = sr.run_id
			WHERE sr.scan_id = ? AND sr.kind = ? AND r.status = 'running'
		)
	`, scanID, kind).Scan(&running)
	if err != nil {
		return false, fmt.Errorf("store: kind running: %w", err)
	}
	return running, nil
}

// CoveredTargets returns the set of hostnames already claimed by a
// running-or-succeeded scan_runs row of kind for this scan -- a failed or
// cancelled run's targets are deliberately excluded so they remain eligible
// for a retry. Hostnames are lowercased since that's how recon.NormalizeDomain
// and the frontend's hostname extraction both produce them.
func (s *Store) CoveredTargets(scanID string, kind ScanKind) (map[string]bool, error) {
	rows, err := s.db.Query(`
		SELECT sr.targets FROM scan_runs sr JOIN runs r ON r.id = sr.run_id
		WHERE sr.scan_id = ? AND sr.kind = ? AND r.status IN ('running', 'succeeded')
	`, scanID, kind)
	if err != nil {
		return nil, fmt.Errorf("store: covered targets: %w", err)
	}
	defer rows.Close()

	covered := map[string]bool{}
	for rows.Next() {
		var targets sql.NullString
		if err := rows.Scan(&targets); err != nil {
			return nil, fmt.Errorf("store: covered targets row: %w", err)
		}
		if !targets.Valid || targets.String == "" || targets.String == "null" {
			continue
		}
		var list []string
		if err := json.Unmarshal([]byte(targets.String), &list); err != nil {
			continue
		}
		for _, t := range list {
			covered[strings.ToLower(t)] = true
		}
	}
	return covered, rows.Err()
}

// --- Scan aggregates (for the dashboard) ---

// SubdomainCount returns how many subdomains crt.sh found for a scan's
// apex domain, and whether that check has completed yet.
func (s *Store) SubdomainCount(scanID, domain string) (count int, done bool, err error) {
	var status string
	var data sql.NullString
	err = s.db.QueryRow(`SELECT status, data FROM scan_checks WHERE scan_id = ? AND domain = ? AND kind = 'subdomains'`, scanID, domain).
		Scan(&status, &data)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("store: subdomain count: %w", err)
	}
	if status != string(recon.StatusDone) || !data.Valid {
		return 0, false, nil
	}
	var parsed struct {
		Count int `json:"count"`
	}
	if jsonErr := json.Unmarshal([]byte(data.String), &parsed); jsonErr != nil {
		return 0, false, nil
	}
	return parsed.Count, true, nil
}

// ApexHTTP returns the apex domain's HTTP status code and page title, if
// that check has completed.
func (s *Store) ApexHTTP(scanID, domain string) (statusCode int, title string, ok bool, err error) {
	var status string
	var data sql.NullString
	err = s.db.QueryRow(`SELECT status, data FROM scan_checks WHERE scan_id = ? AND domain = ? AND kind = 'http'`, scanID, domain).
		Scan(&status, &data)
	if err == sql.ErrNoRows {
		return 0, "", false, nil
	}
	if err != nil {
		return 0, "", false, fmt.Errorf("store: apex http: %w", err)
	}
	if status != string(recon.StatusDone) || !data.Valid {
		return 0, "", false, nil
	}
	var parsed struct {
		StatusCode int    `json:"statusCode"`
		Title      string `json:"title"`
	}
	if jsonErr := json.Unmarshal([]byte(data.String), &parsed); jsonErr != nil {
		return 0, "", false, nil
	}
	return parsed.StatusCode, parsed.Title, true, nil
}

// ApexCloudflare reports whether the apex domain's HTTP check detected
// Cloudflare fronting it (see recon.isCloudflare) -- false (not just
// "unknown") if that check hasn't completed yet, since the dashboard only
// ever wants a definite yes/no badge.
func (s *Store) ApexCloudflare(scanID, domain string) (bool, error) {
	var status string
	var data sql.NullString
	err := s.db.QueryRow(`SELECT status, data FROM scan_checks WHERE scan_id = ? AND domain = ? AND kind = 'http'`, scanID, domain).
		Scan(&status, &data)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: apex cloudflare: %w", err)
	}
	if status != string(recon.StatusDone) || !data.Valid {
		return false, nil
	}
	var parsed struct {
		Cloudflare bool `json:"cloudflare"`
	}
	if jsonErr := json.Unmarshal([]byte(data.String), &parsed); jsonErr != nil {
		return false, nil
	}
	return parsed.Cloudflare, nil
}

// ContentDiscoveryFindingCount counts findings reaching the terminal table
// sink ("table") across every content-discovery run belonging to a scan.
func (s *Store) ContentDiscoveryFindingCount(scanID string) (int, error) {
	var count int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM findings f
		JOIN scan_runs sr ON sr.run_id = f.run_id
		WHERE sr.scan_id = ? AND sr.kind = ? AND f.node_id = 'table'
	`, scanID, ScanKindContentDiscovery).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("store: content discovery finding count: %w", err)
	}
	return count, nil
}

// ScanRunning reports whether any apex/subdomain check or scanner run for a
// scan is still in progress, so the dashboard can show a "scanning..." vs
// "done" pill.
func (s *Store) ScanRunning(scanID string) (bool, error) {
	var running bool
	err := s.db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM scan_checks WHERE scan_id = ? AND status = 'running'
			UNION
			SELECT 1 FROM scan_runs sr JOIN runs r ON r.id = sr.run_id WHERE sr.scan_id = ? AND r.status = 'running'
		)
	`, scanID, scanID).Scan(&running)
	if err != nil {
		return false, fmt.Errorf("store: scan running: %w", err)
	}
	return running, nil
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

// --- Screenshots ---

// ScreenshotMeta is a screenshot's metadata without its image bytes, for
// listing what's available without pulling every PNG over the wire.
type ScreenshotMeta struct {
	Hostname   string    `json:"hostname"`
	URL        string    `json:"url"`
	CapturedAt time.Time `json:"capturedAt"`
}

// SaveScreenshot upserts the captured PNG for one scan+hostname -- a
// re-capture (e.g. a scan restart) replaces the previous image rather than
// accumulating history, since only the latest view of a host is useful.
func (s *Store) SaveScreenshot(scanID, hostname, url string, image []byte) error {
	_, err := s.db.Exec(`
		INSERT INTO screenshots (scan_id, hostname, url, image, captured_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(scan_id, hostname) DO UPDATE SET url=excluded.url, image=excluded.image, captured_at=excluded.captured_at
	`, scanID, hostname, url, image, time.Now())
	if err != nil {
		return fmt.Errorf("store: save screenshot: %w", err)
	}
	return nil
}

// ListScreenshots returns metadata for every screenshot captured so far for
// a scan, so the UI knows which hostnames have a thumbnail to fetch.
func (s *Store) ListScreenshots(scanID string) ([]ScreenshotMeta, error) {
	rows, err := s.db.Query(`SELECT hostname, url, captured_at FROM screenshots WHERE scan_id = ? ORDER BY hostname ASC`, scanID)
	if err != nil {
		return nil, fmt.Errorf("store: list screenshots: %w", err)
	}
	defer rows.Close()

	out := []ScreenshotMeta{}
	for rows.Next() {
		var m ScreenshotMeta
		if err := rows.Scan(&m.Hostname, &m.URL, &m.CapturedAt); err != nil {
			return nil, fmt.Errorf("store: screenshot row: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// GetScreenshot returns one hostname's captured PNG bytes.
func (s *Store) GetScreenshot(scanID, hostname string) ([]byte, error) {
	var image []byte
	err := s.db.QueryRow(`SELECT image FROM screenshots WHERE scan_id = ? AND hostname = ?`, scanID, hostname).Scan(&image)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("store: screenshot %s/%s: %w", scanID, hostname, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("store: get screenshot: %w", err)
	}
	return image, nil
}

// HasScreenshot reports whether a screenshot already exists for scanID +
// hostname, so the capture pipeline can skip a host it's already shot
// instead of re-launching a browser for it on every recon check that fires
// (e.g. a restarted scan re-observing the same live host).
func (s *Store) HasScreenshot(scanID, hostname string) (bool, error) {
	var exists bool
	err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM screenshots WHERE scan_id = ? AND hostname = ?)`, scanID, hostname).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("store: has screenshot: %w", err)
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
