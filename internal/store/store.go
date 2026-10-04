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
	"regexp"
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
	// db is the single writer connection: SQLite allows one writer at a time,
	// so writes are serialized through it.
	db *sql.DB
	// rdb serves read-only queries from a small pool. With WAL journaling,
	// readers run alongside the writer, so a long report or list query no
	// longer blocks scanners writing results.
	rdb *sql.DB
	// requests queues request-log rows for the single background writer
	// (see requests.go). requestsStop asks it to finish, and requestsDone
	// closes once it has.
	requests     chan RequestRecord
	requestsStop chan struct{}
	requestsDone chan struct{}
}

// Open opens (creating if necessary) the SQLite database at path and
// applies the schema.
func Open(path string) (*Store, error) {
	// Both pools share one DSN so every connection gets the same settings.
	// busy_timeout is per connection, and journal_mode=WAL lets readers
	// proceed during a write. The driver applies _pragma to each new connection.
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	// SQLite only tolerates one writer at a time; a single connection
	// avoids "database is locked" errors under concurrent goroutines.
	db.SetMaxOpenConns(1)

	rdb, err := sql.Open("sqlite", dsn)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("store: open read pool %s: %w", path, err)
	}
	rdb.SetMaxOpenConns(readPoolSize)

	s := &Store{db: db, rdb: rdb}
	if err := s.migrate(); err != nil {
		db.Close()
		rdb.Close()
		return nil, err
	}
	s.startRequestWriter()
	return s, nil
}

// readPoolSize caps concurrent read-only connections. Small on purpose: this
// is a single-operator local tool, and WAL readers only need enough to avoid
// queueing behind each other on ordinary page loads.
const readPoolSize = 4

// Close drains any queued request-log rows, then closes both pools.
func (s *Store) Close() error {
	s.stopRequestWriter()
	s.rdb.Close()
	return s.db.Close()
}

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
	triage_status TEXT NOT NULL DEFAULT 'new',
	triage_note TEXT,
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

-- A target list is a named, user-created collection of targets within a
-- case -- domains, directories, files, login-form URLs, or whatever else
-- the user wants to group separately (like a Spotify playlist). Every
-- target belongs to exactly one list; kind is a UI hint (icon/placeholder)
-- only, same as targets.kind was before this table existed.
-- Scope rules for a case: the hosts a scan launched under this case may touch
-- (see netgov.Scope). A case with no rows is unrestricted. pattern is kept as
-- the operator typed it, normalized only by netgov.NewScope when it is used.
CREATE TABLE IF NOT EXISTS case_scope (
	case_id TEXT NOT NULL,
	pattern TEXT NOT NULL,
	PRIMARY KEY (case_id, pattern)
);

CREATE TABLE IF NOT EXISTS target_lists (
	id TEXT PRIMARY KEY,
	case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
	name TEXT NOT NULL,
	kind TEXT NOT NULL DEFAULT 'other',
	created_at DATETIME NOT NULL,
	UNIQUE(case_id, name)
);
CREATE INDEX IF NOT EXISTS idx_target_lists_case_id ON target_lists(case_id);

-- A target is any host/URL/IP/directory/file the user has explicitly added
-- to a case, either typed by hand or promoted from a job's results (see
-- api.handlePromoteTargets), filed under exactly one target_lists row.
-- UNIQUE(case_id, value) makes promoting an already-known value a harmless
-- no-op via INSERT OR IGNORE rather than a duplicate row -- as a
-- consequence a value already saved under one list can't also be saved
-- under a second list within the same case, which is an acceptable
-- limitation for what this is (a pentesting scratchpad, not a tagging
-- system).
CREATE TABLE IF NOT EXISTS targets (
	id TEXT PRIMARY KEY,
	case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
	list_id TEXT REFERENCES target_lists(id) ON DELETE CASCADE,
	value TEXT NOT NULL,
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

-- A saved auth bundle (headers/cookie) a user can apply to JWT
-- Scanner/Probe/Secret Scanner instead of re-pasting the same
-- Authorization header or session cookie into each tool every time. Scoped
-- to a case (an engagement's credentials rarely make sense reused in
-- another one) -- unlike settings' app-wide API keys, values here ARE
-- returned in full on every read: this is a single-operator local tool and
-- the whole point is reusing what's stored, not hiding it from its owner.
--
-- username/password/login_url (+ username_field/password_field/
-- token_field) are optional: when set, this row is a "test credential" --
-- a valid login the operator has authorization to use -- and
-- POST /api/credentials/{id}/session (see handleCreateCredentialSession)
-- performs that login and writes the resulting Set-Cookie/bearer token
-- back into headers/cookie above, so every scanner that already applies
-- this credential via mergedCredentialHeaders picks up the live session
-- with no changes of its own. session_created_at records when that last
-- succeeded, purely for display.
CREATE TABLE IF NOT EXISTS credentials (
	id TEXT PRIMARY KEY,
	case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
	name TEXT NOT NULL,
	headers TEXT,
	cookie TEXT,
	notes TEXT,
	username TEXT,
	password TEXT,
	login_url TEXT,
	login_method TEXT,
	username_field TEXT,
	password_field TEXT,
	token_field TEXT,
	session_created_at DATETIME,
	created_at DATETIME NOT NULL,
	UNIQUE(case_id, name)
);
CREATE INDEX IF NOT EXISTS idx_credentials_case_id ON credentials(case_id);

-- A per-domain Cookie header applied automatically to every request a case
-- makes against that domain, so an authenticated session doesn't have to be
-- picked via a Credential on every single tool call -- unlike credentials
-- (explicit, chosen per request), this is implicit and always-on for its
-- domain. One row per (case, domain); domain is stored lowercased.
CREATE TABLE IF NOT EXISTS domain_cookies (
	case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
	domain TEXT NOT NULL,
	cookie TEXT NOT NULL,
	updated_at DATETIME NOT NULL,
	PRIMARY KEY (case_id, domain)
);
CREATE INDEX IF NOT EXISTS idx_domain_cookies_case_id ON domain_cookies(case_id);

-- A named, reusable bundle of job-launch options (preset/threads/timeout/
-- rate/wordlist/scheme/hostSuffix/recursive, plus ffuf-custom's own
-- fields) for one tool, so a launcher's tuning doesn't have to be rebuilt
-- by hand on every job. Global rather than case-scoped -- the intensity/
-- wordlist choices this saves are reusable across every case, unlike
-- targets or credentials.
CREATE TABLE IF NOT EXISTS job_templates (
	id TEXT PRIMARY KEY,
	tool TEXT NOT NULL,
	name TEXT NOT NULL,
	options TEXT NOT NULL,
	created_at DATETIME NOT NULL,
	UNIQUE(tool, name)
);

-- One row per Probe/JWT/Secret Scanner run launched with a case selected --
-- unlike case_checks (one row per case+target+kind, overwritten on re-run),
-- this keeps every run so a case's scan history is never silently
-- replaced. data is the tool's raw JSON response, kept opaque here (like
-- jobs.config) so the store package never needs to know probescan/jwtscan/
-- secretscan's response shapes.
CREATE TABLE IF NOT EXISTS case_scans (
	id TEXT PRIMARY KEY,
	case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
	target TEXT NOT NULL,
	tool TEXT NOT NULL, -- 'probe' | 'jwt' | 'secrets' | 'breach' | 'breach-crawl' | 'domainscan' | 'bypass403' | 'pwreset' | 'graphqlenum'
	severity TEXT NOT NULL, -- worst finding severity, on the same info/low/medium/high/critical scale as probescan
	summary TEXT NOT NULL,
	data TEXT NOT NULL,
	created_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_case_scans_case_id ON case_scans(case_id);

-- requests is the HTTP request log: one row per request a native scanner put
-- on the wire (see netgov.Exchange). It is written by the background writer
-- in requests.go, never inline with a request, and is what the "Inspect
-- requests" view lists. request_raw and response_raw hold the full rendered
-- exchange (body capped), so the list query selects only the small columns
-- and detail is fetched one row at a time.
-- run_id is either a job's run (runs.id) or a direct scan's id, which is also
-- its case_scans.id. There is deliberately no foreign key: a direct scan has no
-- runs row, and DeleteCase clears these rows itself.
CREATE TABLE IF NOT EXISTS requests (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	run_id TEXT NOT NULL,
	node_id TEXT NOT NULL,
	method TEXT NOT NULL,
	url TEXT NOT NULL,
	host TEXT NOT NULL,
	status_code INTEGER NOT NULL,
	size INTEGER NOT NULL,
	ttfb_ms INTEGER NOT NULL,
	error TEXT NOT NULL DEFAULT '',
	request_raw TEXT NOT NULL,
	response_raw TEXT NOT NULL,
	timestamp DATETIME NOT NULL,
	-- ref names this exchange; from_ref names the exchange whose 3xx redirected
	-- here. Both are empty for rows written before redirect linking existed.
	ref TEXT NOT NULL DEFAULT '',
	from_ref TEXT NOT NULL DEFAULT '',
	location TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_requests_node ON requests(run_id, node_id);

-- request_hits records the requests a scan reported as findings: one row per
-- (method, URL) a finding captured as its request, per node. The request log
-- marks a logged exchange as a hit when its method and URL appear here, so only
-- requests that actually produced a finding are highlighted. Written when a
-- finding is saved (job nodes) or when a direct scan's result is saved.
CREATE TABLE IF NOT EXISTS request_hits (
	run_id TEXT NOT NULL,
	node_id TEXT NOT NULL,
	method TEXT NOT NULL,
	url TEXT NOT NULL,
	PRIMARY KEY (run_id, node_id, method, url)
);
`
	_, err := s.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	// requests predates redirect linking, so an existing table needs its two
	// new columns added by hand, once (see the requests schema comment above).
	if err := s.ensureColumn("requests", "ref", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("requests", "from_ref", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("requests", "location", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	// findings predates triage_status/triage_note -- CREATE TABLE IF NOT
	// EXISTS above only applies that shape to a brand new database, so an
	// existing one needs these two columns added by hand, once.
	if err := s.ensureColumn("findings", "triage_status", "TEXT NOT NULL DEFAULT 'new'"); err != nil {
		return err
	}
	if err := s.ensureColumn("findings", "triage_note", "TEXT"); err != nil {
		return err
	}
	// targets predates target_lists -- give every pre-existing target a
	// home list so it doesn't vanish from the Targets tab once lists become
	// mandatory there. The index has to wait until the column actually
	// exists -- CREATE INDEX isn't guarded by IF NOT EXISTS the way ADD
	// COLUMN would need to be, so it can't live in the schema string above
	// (that runs unconditionally, before ensureColumn has a chance to add
	// list_id to a pre-existing targets table).
	// Template-level detail and confidence. Added after the first release, so
	// existing databases get them through ensureColumn.
	for _, col := range []string{"template", "severity", "matcher", "reproduce", "confidence"} {
		if err := s.ensureColumn("findings", col, "TEXT"); err != nil {
			return err
		}
	}
	if err := s.ensureColumn("targets", "list_id", "TEXT REFERENCES target_lists(id) ON DELETE CASCADE"); err != nil {
		return err
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_targets_list_id ON targets(list_id)`); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	if err := s.backfillTargetLists(); err != nil {
		return err
	}
	// credentials predates the test-credential/session fields -- add them
	// for a pre-existing database the same way list_id was added above.
	for _, col := range []struct{ name, decl string }{
		{"username", "TEXT"},
		{"password", "TEXT"},
		{"login_url", "TEXT"},
		{"login_method", "TEXT"},
		{"username_field", "TEXT"},
		{"password_field", "TEXT"},
		{"token_field", "TEXT"},
		{"session_created_at", "DATETIME"},
	} {
		if err := s.ensureColumn("credentials", col.name, col.decl); err != nil {
			return err
		}
	}
	return nil
}

// backfillTargetLists gives every target left over from before target_lists
// existed a home: one new "Domains" list per case (matching the
// domains-only behavior every target had before this feature), so nothing
// already saved silently disappears from the Targets tab. A no-op once
// every target already has a list_id.
func (s *Store) backfillTargetLists() error {
	rows, err := s.rdb.Query(`SELECT DISTINCT case_id FROM targets WHERE list_id IS NULL OR list_id = ''`)
	if err != nil {
		return fmt.Errorf("store: backfill target lists: %w", err)
	}
	var caseIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return fmt.Errorf("store: backfill target lists: %w", err)
		}
		caseIDs = append(caseIDs, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()

	for _, caseID := range caseIDs {
		listID, err := s.getOrCreateTargetList(caseID, "Domains", "domain")
		if err != nil {
			return fmt.Errorf("store: backfill target lists: %w", err)
		}
		if _, err := s.db.Exec(`UPDATE targets SET list_id = ? WHERE case_id = ? AND (list_id IS NULL OR list_id = '')`, listID, caseID); err != nil {
			return fmt.Errorf("store: backfill target lists: %w", err)
		}
	}
	return nil
}

// identPattern matches a plain SQL identifier: letters, digits, underscore.
var identPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// validIdentifier reports whether name is safe to splice into SQL as a table
// or column name.
func validIdentifier(name string) bool {
	return identPattern.MatchString(name)
}

// ensureColumn adds column to table (via ALTER TABLE ... ADD COLUMN decl) if
// it isn't already present -- SQLite has no "ADD COLUMN IF NOT EXISTS", and
// re-running the bare ALTER on every startup would fail once the column
// already exists.
func (s *Store) ensureColumn(table, column, decl string) error {
	// table is spliced into a PRAGMA (no bind parameters there), so refuse
	// anything that isn't a plain identifier. Callers are internal, but this
	// keeps the interpolation safe if one ever passes user input.
	if !validIdentifier(table) || !validIdentifier(column) {
		return fmt.Errorf("store: refusing non-identifier table %q or column %q", table, column)
	}
	rows, err := s.rdb.Query(fmt.Sprintf(`PRAGMA table_info(%s)`, table))
	if err != nil {
		return fmt.Errorf("store: inspect %s: %w", table, err)
	}
	defer rows.Close()

	var name string
	var cid, notNull, pk int
	var dfltValue sql.NullString
	var colType string
	for rows.Next() {
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
			return fmt.Errorf("store: inspect %s: %w", table, err)
		}
		if name == column {
			return rows.Err()
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if _, err := s.db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, table, column, decl)); err != nil {
		return fmt.Errorf("store: add column %s.%s: %w", table, column, err)
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
	err := s.rdb.QueryRow(`SELECT definition FROM flows WHERE id = ?`, id).Scan(&def)
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
	err := s.rdb.QueryRow(`SELECT id, flow_id, status, error, started_at, finished_at FROM runs WHERE id = ?`, id).
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
	// graph with dedup disabled. triage_status is left at its schema default
	// ('new') here -- only UpdateFindingTriage ever sets it to anything else.
	_, err = s.db.Exec(`
		INSERT OR IGNORE INTO findings (id, run_id, node_id, url, status_code, content_length, words, lines, content_type, redirect_location, method, headers, source_tool, tags, timestamp, template, severity, matcher, reproduce, confidence)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, f.ID, runID, nodeID, f.URL, f.StatusCode, f.ContentLength, f.Words, f.Lines, f.ContentType, f.RedirectLoc, f.Method, string(headers), f.SourceTool, string(tags), f.Timestamp, f.Template, f.Severity, f.Matcher, f.Reproduce, f.Confidence)
	if err != nil {
		return fmt.Errorf("store: save finding: %w", err)
	}
	return nil
}

// ListFindings returns every finding recorded for a run, optionally
// restricted to one node (pass "" for nodeID to get all of them).
func (s *Store) ListFindings(runID, nodeID string) ([]model.Finding, error) {
	query := `SELECT id, run_id, node_id, url, status_code, content_length, words, lines, content_type, redirect_location, method, headers, source_tool, tags, timestamp, triage_status, triage_note, template, severity, matcher, reproduce, confidence FROM findings WHERE run_id = ?`
	args := []any{runID}
	if nodeID != "" {
		query += ` AND node_id = ?`
		args = append(args, nodeID)
	}
	query += ` ORDER BY timestamp ASC`

	rows, err := s.rdb.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list findings: %w", err)
	}
	defer rows.Close()

	out := []model.Finding{}
	for rows.Next() {
		var f model.Finding
		var headers, tags sql.NullString
		var contentType, redirectLoc, method, triageNote, template, severity, matcher, reproduce, confidence sql.NullString
		if err := rows.Scan(&f.ID, &f.RunID, &f.SourceNodeID, &f.URL, &f.StatusCode, &f.ContentLength, &f.Words, &f.Lines, &contentType, &redirectLoc, &method, &headers, &f.SourceTool, &tags, &f.Timestamp, &f.TriageStatus, &triageNote, &template, &severity, &matcher, &reproduce, &confidence); err != nil {
			return nil, fmt.Errorf("store: scan finding: %w", err)
		}
		f.ContentType = contentType.String
		f.RedirectLoc = redirectLoc.String
		f.Method = method.String
		f.TriageNote = triageNote.String
		f.Template, f.Severity, f.Matcher, f.Reproduce, f.Confidence = template.String, severity.String, matcher.String, reproduce.String, confidence.String
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

// UpdateFindingTriage sets a finding's operator-assigned triage status/note,
// identified by its ID alone (not id+node_id, findings' actual primary key)
// -- every row sharing that ID is the same logical finding as it passed
// through the flow's later nodes (see SaveFinding's doc comment), and a
// triage decision applies to all of them at once so it reads the same
// regardless of which node's copy a caller happens to have fetched.
func (s *Store) UpdateFindingTriage(id string, status model.TriageStatus, note string) error {
	res, err := s.db.Exec(`UPDATE findings SET triage_status = ?, triage_note = ? WHERE id = ?`, string(status), note, id)
	if err != nil {
		return fmt.Errorf("store: update finding triage: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrNotFound
	}
	return nil
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
	err := s.rdb.QueryRow(`SELECT id, name, description, created_at, updated_at FROM cases WHERE id = ?`, id).
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
	rows, err := s.rdb.Query(`SELECT id, name, description, created_at, updated_at FROM cases ORDER BY created_at DESC`)
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
// The request log is the exception: it can grow large, so the case's rows
// are removed here, in the same transaction, before the cascade drops the
// case_scans rows that identify the direct scans they belong to.
func (s *Store) DeleteCase(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: delete case: %w", err)
	}
	defer tx.Rollback()

	// case_scope has no foreign-key cascade (foreign keys are not enforced
	// here), so its rows are removed explicitly with the case.
	if _, err := tx.Exec(`DELETE FROM case_scope WHERE case_id = ?`, id); err != nil {
		return fmt.Errorf("store: delete case scope: %w", err)
	}

	if _, err := tx.Exec(`
		DELETE FROM requests
		WHERE run_id IN (SELECT id FROM case_scans WHERE case_id = ?)
		   OR run_id IN (SELECT run_id FROM jobs WHERE case_id = ? AND run_id IS NOT NULL)
	`, id, id); err != nil {
		return fmt.Errorf("store: delete case requests: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM cases WHERE id = ?`, id); err != nil {
		return fmt.Errorf("store: delete case: %w", err)
	}
	return tx.Commit()
}

// --- Target Lists ---

// TargetList is a named, user-created collection of targets within a case
// -- see the CREATE TABLE comment above. Kind is a UI hint only (the
// backend never branches on it), same as Target.Kind used to be before
// this type existed.
type TargetList struct {
	ID        string    `json:"id"`
	CaseID    string    `json:"caseId"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	CreatedAt time.Time `json:"createdAt"`
}

func (s *Store) CreateTargetList(l TargetList) error {
	_, err := s.db.Exec(`
		INSERT INTO target_lists (id, case_id, name, kind, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, l.ID, l.CaseID, l.Name, l.Kind, time.Now())
	if err != nil {
		return fmt.Errorf("store: create target list: %w", err)
	}
	return nil
}

func (s *Store) ListTargetLists(caseID string) ([]TargetList, error) {
	rows, err := s.rdb.Query(`
		SELECT id, case_id, name, kind, created_at FROM target_lists WHERE case_id = ? ORDER BY created_at ASC
	`, caseID)
	if err != nil {
		return nil, fmt.Errorf("store: list target lists: %w", err)
	}
	defer rows.Close()

	out := []TargetList{}
	for rows.Next() {
		var l TargetList
		if err := rows.Scan(&l.ID, &l.CaseID, &l.Name, &l.Kind, &l.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: target list row: %w", err)
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// GetTargetListByID looks up one target list by its own id -- used to
// validate that a listId a request carries actually belongs to the case
// it's being used against, and to report back a freshly created/renamed
// list.
func (s *Store) GetTargetListByID(id string) (TargetList, error) {
	var l TargetList
	err := s.rdb.QueryRow(`SELECT id, case_id, name, kind, created_at FROM target_lists WHERE id = ?`, id).
		Scan(&l.ID, &l.CaseID, &l.Name, &l.Kind, &l.CreatedAt)
	if err == sql.ErrNoRows {
		return TargetList{}, fmt.Errorf("store: target list %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return TargetList{}, fmt.Errorf("store: get target list: %w", err)
	}
	return l, nil
}

// getOrCreateTargetList returns the id of the case's list with this exact
// name, creating it first if it doesn't exist yet -- used by
// backfillTargetLists to find-or-make each case's default "Domains" list.
func (s *Store) getOrCreateTargetList(caseID, name, kind string) (string, error) {
	var id string
	err := s.rdb.QueryRow(`SELECT id FROM target_lists WHERE case_id = ? AND name = ?`, caseID, name).Scan(&id)
	if err == nil {
		return id, nil
	}
	if err != sql.ErrNoRows {
		return "", fmt.Errorf("store: get or create target list: %w", err)
	}
	id = randomID()
	if _, err := s.db.Exec(`
		INSERT INTO target_lists (id, case_id, name, kind, created_at) VALUES (?, ?, ?, ?, ?)
	`, id, caseID, name, kind, time.Now()); err != nil {
		return "", fmt.Errorf("store: get or create target list: %w", err)
	}
	return id, nil
}

func (s *Store) RenameTargetList(id, name string) error {
	res, err := s.db.Exec(`UPDATE target_lists SET name = ? WHERE id = ?`, name, id)
	if err != nil {
		return fmt.Errorf("store: rename target list: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteTargetList removes a list and (via ON DELETE CASCADE) every target
// filed under it.
func (s *Store) DeleteTargetList(id string) error {
	_, err := s.db.Exec(`DELETE FROM target_lists WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete target list: %w", err)
	}
	return nil
}

// --- Targets ---

// Target's ListName/ListKind are filled in by a join against target_lists
// wherever a target is read (List/GetByValue/GetByID) -- they aren't
// columns of the targets table itself, just a convenience so callers (the
// frontend's tab-based target pickers in particular) don't need to cross-
// reference a separate target lists response to know which list/kind a
// target belongs to.
type Target struct {
	ID          string    `json:"id"`
	CaseID      string    `json:"caseId"`
	ListID      string    `json:"listId"`
	ListName    string    `json:"listName"`
	ListKind    string    `json:"listKind"`
	Value       string    `json:"value"`
	SourceTool  string    `json:"sourceTool,omitempty"`
	SourceJobID string    `json:"sourceJobId,omitempty"`
	Notes       string    `json:"notes,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
}

const targetSelectCols = `
	t.id, t.case_id, t.list_id, tl.name, tl.kind, t.value, t.source_tool, t.source_job_id, t.notes, t.created_at
	FROM targets t
	JOIN target_lists tl ON tl.id = t.list_id
`

func scanTarget(row interface{ Scan(...any) error }) (Target, error) {
	var t Target
	var sourceTool, sourceJobID, notes sql.NullString
	err := row.Scan(&t.ID, &t.CaseID, &t.ListID, &t.ListName, &t.ListKind, &t.Value, &sourceTool, &sourceJobID, &notes, &t.CreatedAt)
	t.SourceTool = sourceTool.String
	t.SourceJobID = sourceJobID.String
	t.Notes = notes.String
	return t, err
}

// AddTarget records a target, or does nothing if this case already has one
// with the same value -- INSERT OR IGNORE on the (case_id, value) unique
// constraint is what makes re-promoting an already-known value harmless
// rather than an error the caller has to special-case.
func (s *Store) AddTarget(t Target) error {
	_, err := s.db.Exec(`
		INSERT OR IGNORE INTO targets (id, case_id, list_id, value, source_tool, source_job_id, notes, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, t.ID, t.CaseID, t.ListID, t.Value, t.SourceTool, t.SourceJobID, t.Notes, time.Now())
	if err != nil {
		return fmt.Errorf("store: add target: %w", err)
	}
	return nil
}

func (s *Store) ListTargets(caseID string) ([]Target, error) {
	rows, err := s.rdb.Query(`SELECT `+targetSelectCols+`WHERE t.case_id = ? ORDER BY t.created_at ASC`, caseID)
	if err != nil {
		return nil, fmt.Errorf("store: list targets: %w", err)
	}
	defer rows.Close()

	out := []Target{}
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, fmt.Errorf("store: target row: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetTargetByValue looks up one target by its case + exact value, used by
// promotion to report back the (possibly pre-existing) target a value
// resolved to.
func (s *Store) GetTargetByValue(caseID, value string) (Target, error) {
	t, err := scanTarget(s.rdb.QueryRow(`SELECT `+targetSelectCols+`WHERE t.case_id = ? AND t.value = ?`, caseID, value))
	if err == sql.ErrNoRows {
		return Target{}, fmt.Errorf("store: target %s/%s: %w", caseID, value, ErrNotFound)
	}
	if err != nil {
		return Target{}, fmt.Errorf("store: get target by value: %w", err)
	}
	return t, nil
}

// GetTargetByID looks up one target by its own id -- used by
// handleDeleteTarget (whose route only carries the target id) to tell a
// missing target apart from a successful delete.
func (s *Store) GetTargetByID(id string) (Target, error) {
	t, err := scanTarget(s.rdb.QueryRow(`SELECT `+targetSelectCols+`WHERE t.id = ?`, id))
	if err == sql.ErrNoRows {
		return Target{}, fmt.Errorf("store: target %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return Target{}, fmt.Errorf("store: get target by id: %w", err)
	}
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
	err := s.rdb.QueryRow(`
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
	rows, err := s.rdb.Query(`
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
	err := s.rdb.QueryRow(`
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
	rows, err := s.rdb.Query(`
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
	err := s.rdb.QueryRow(`SELECT COUNT(*) FROM targets WHERE case_id = ?`, caseID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("store: case target count: %w", err)
	}
	return count, nil
}

func (s *Store) CaseJobCount(caseID string) (int, error) {
	var count int
	err := s.rdb.QueryRow(`SELECT COUNT(*) FROM jobs WHERE case_id = ?`, caseID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("store: case job count: %w", err)
	}
	return count, nil
}

// CaseFindingCount counts findings reaching the terminal table sink
// ("table") across every job belonging to a case.
func (s *Store) CaseFindingCount(caseID string) (int, error) {
	var count int
	err := s.rdb.QueryRow(`
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
	err := s.rdb.QueryRow(`
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
	rows, err := s.rdb.Query(`SELECT target, kind, status, data, error, started_at, finished_at FROM case_checks WHERE case_id = ? ORDER BY started_at ASC`, caseID)
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
	rows, err := s.rdb.Query(`SELECT target, url, captured_at FROM case_screenshots WHERE case_id = ? ORDER BY target ASC`, caseID)
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
	err := s.rdb.QueryRow(`SELECT image FROM case_screenshots WHERE case_id = ? AND target = ?`, caseID, target).Scan(&image)
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
	err := s.rdb.QueryRow(`SELECT EXISTS(SELECT 1 FROM case_screenshots WHERE case_id = ? AND target = ?)`, caseID, target).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("store: has case screenshot: %w", err)
	}
	return exists, nil
}

// --- Credentials ---

// Credential is a saved auth bundle for one case -- see the migrate()
// schema comment above credentials for why values are returned in full
// rather than redacted the way settings' app-wide API keys are.
type Credential struct {
	ID      string            `json:"id"`
	CaseID  string            `json:"caseId"`
	Name    string            `json:"name"`
	Headers map[string]string `json:"headers,omitempty"`
	Cookie  string            `json:"cookie,omitempty"`
	Notes   string            `json:"notes,omitempty"`
	// Username/Password/LoginURL mark this as a "test credential" -- see
	// the credentials table's schema comment above -- and are only ever
	// used by handleCreateCredentialSession to perform the login that
	// populates Headers/Cookie; scanners never see them directly.
	Username      string     `json:"username,omitempty"`
	Password      string     `json:"password,omitempty"`
	LoginURL      string     `json:"loginUrl,omitempty"`
	LoginMethod   string     `json:"loginMethod,omitempty"`
	UsernameField string     `json:"usernameField,omitempty"`
	PasswordField string     `json:"passwordField,omitempty"`
	TokenField    string     `json:"tokenField,omitempty"`
	SessionAt     *time.Time `json:"sessionAt,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
}

func (s *Store) SaveCredential(c Credential) error {
	headersJSON, err := json.Marshal(c.Headers)
	if err != nil {
		return fmt.Errorf("store: marshal credential headers: %w", err)
	}
	_, err = s.db.Exec(`
		INSERT INTO credentials (
			id, case_id, name, headers, cookie, notes,
			username, password, login_url, login_method, username_field, password_field, token_field,
			created_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, c.ID, c.CaseID, c.Name, string(headersJSON), c.Cookie, c.Notes,
		c.Username, c.Password, c.LoginURL, c.LoginMethod, c.UsernameField, c.PasswordField, c.TokenField,
		time.Now())
	if err != nil {
		return fmt.Errorf("store: save credential: %w", err)
	}
	return nil
}

// UpdateCredentialSession overwrites a credential's live headers/cookie
// with the result of a fresh login (see handleCreateCredentialSession) and
// stamps session_created_at, so a scanner picking this credential up right
// after gets the new session and the vault can show when it was last
// refreshed.
func (s *Store) UpdateCredentialSession(id string, headers map[string]string, cookie string) error {
	headersJSON, err := json.Marshal(headers)
	if err != nil {
		return fmt.Errorf("store: marshal credential headers: %w", err)
	}
	res, err := s.db.Exec(`
		UPDATE credentials SET headers = ?, cookie = ?, session_created_at = ? WHERE id = ?
	`, string(headersJSON), cookie, time.Now(), id)
	if err != nil {
		return fmt.Errorf("store: update credential session: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("store: credential %s: %w", id, ErrNotFound)
	}
	return nil
}

func (s *Store) ListCredentials(caseID string) ([]Credential, error) {
	rows, err := s.rdb.Query(`
		SELECT id, case_id, name, headers, cookie, notes,
			username, password, login_url, login_method, username_field, password_field, token_field, session_created_at,
			created_at
		FROM credentials WHERE case_id = ? ORDER BY created_at ASC
	`, caseID)
	if err != nil {
		return nil, fmt.Errorf("store: list credentials: %w", err)
	}
	defer rows.Close()

	out := []Credential{}
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) GetCredential(id string) (Credential, error) {
	row := s.rdb.QueryRow(`
		SELECT id, case_id, name, headers, cookie, notes,
			username, password, login_url, login_method, username_field, password_field, token_field, session_created_at,
			created_at
		FROM credentials WHERE id = ?
	`, id)
	c, err := scanCredential(row)
	if err == sql.ErrNoRows {
		return Credential{}, fmt.Errorf("store: credential %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return Credential{}, fmt.Errorf("store: get credential: %w", err)
	}
	return c, nil
}

func (s *Store) DeleteCredential(id string) error {
	_, err := s.db.Exec(`DELETE FROM credentials WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete credential: %w", err)
	}
	return nil
}

// credentialScanner is satisfied by both *sql.Row and *sql.Rows, so
// GetCredential and ListCredentials can share one scan+decode routine.
type credentialScanner interface {
	Scan(dest ...any) error
}

func scanCredential(row credentialScanner) (Credential, error) {
	var c Credential
	var headersJSON, cookie, notes sql.NullString
	var username, password, loginURL, loginMethod, usernameField, passwordField, tokenField sql.NullString
	var sessionAt sql.NullTime
	if err := row.Scan(
		&c.ID, &c.CaseID, &c.Name, &headersJSON, &cookie, &notes,
		&username, &password, &loginURL, &loginMethod, &usernameField, &passwordField, &tokenField, &sessionAt,
		&c.CreatedAt,
	); err != nil {
		return Credential{}, err
	}
	if headersJSON.String != "" {
		if err := json.Unmarshal([]byte(headersJSON.String), &c.Headers); err != nil {
			return Credential{}, fmt.Errorf("store: decode credential headers: %w", err)
		}
	}
	c.Cookie = cookie.String
	c.Notes = notes.String
	c.Username = username.String
	c.Password = password.String
	c.LoginURL = loginURL.String
	c.LoginMethod = loginMethod.String
	c.UsernameField = usernameField.String
	c.PasswordField = passwordField.String
	c.TokenField = tokenField.String
	if sessionAt.Valid {
		c.SessionAt = &sessionAt.Time
	}
	return c, nil
}

// --- Cookie vault (per-domain cookies) ---

// DomainCookie is one case's saved Cookie-header override for one domain --
// see the migrate() schema comment above domain_cookies.
type DomainCookie struct {
	CaseID    string    `json:"caseId"`
	Domain    string    `json:"domain"`
	Cookie    string    `json:"cookie"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (s *Store) ListDomainCookies(caseID string) ([]DomainCookie, error) {
	rows, err := s.rdb.Query(`
		SELECT case_id, domain, cookie, updated_at FROM domain_cookies WHERE case_id = ? ORDER BY domain ASC
	`, caseID)
	if err != nil {
		return nil, fmt.Errorf("store: list domain cookies: %w", err)
	}
	defer rows.Close()

	out := []DomainCookie{}
	for rows.Next() {
		var c DomainCookie
		if err := rows.Scan(&c.CaseID, &c.Domain, &c.Cookie, &c.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: domain cookie row: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SetDomainCookie saves cookie as caseID's override for domain, or deletes
// the row entirely when cookie is blank -- clearing the field in the vault
// UI removes the override rather than persisting an empty one.
func (s *Store) SetDomainCookie(caseID, domain, cookie string) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if cookie == "" {
		_, err := s.db.Exec(`DELETE FROM domain_cookies WHERE case_id = ? AND domain = ?`, caseID, domain)
		if err != nil {
			return fmt.Errorf("store: delete domain cookie: %w", err)
		}
		return nil
	}
	_, err := s.db.Exec(`
		INSERT INTO domain_cookies (case_id, domain, cookie, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(case_id, domain) DO UPDATE SET cookie = excluded.cookie, updated_at = excluded.updated_at
	`, caseID, domain, cookie, time.Now())
	if err != nil {
		return fmt.Errorf("store: set domain cookie: %w", err)
	}
	return nil
}

// CookieForDomain returns caseID's saved cookie override for domain, or ""
// if none is set. Used to auto-apply the vault to an outgoing request (see
// api.applyDomainCookie) -- "not set" is not an error.
func (s *Store) CookieForDomain(caseID, domain string) (string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	var cookie string
	err := s.rdb.QueryRow(`SELECT cookie FROM domain_cookies WHERE case_id = ? AND domain = ?`, caseID, domain).Scan(&cookie)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("store: cookie for domain: %w", err)
	}
	return cookie, nil
}

// --- Job templates ---

// JobTemplate is a named, reusable bundle of job-launch options for one
// tool -- see the migrate() schema comment above job_templates.
type JobTemplate struct {
	ID        string    `json:"id"`
	Tool      string    `json:"tool"`
	Name      string    `json:"name"`
	Options   string    `json:"options"` // raw JSON, opaque to store -- mirrors Job.Config
	CreatedAt time.Time `json:"createdAt"`
}

func (s *Store) SaveJobTemplate(t JobTemplate) error {
	_, err := s.db.Exec(`
		INSERT INTO job_templates (id, tool, name, options, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, t.ID, t.Tool, t.Name, t.Options, time.Now())
	if err != nil {
		return fmt.Errorf("store: save job template: %w", err)
	}
	return nil
}

func (s *Store) ListJobTemplates(tool string) ([]JobTemplate, error) {
	rows, err := s.rdb.Query(`
		SELECT id, tool, name, options, created_at FROM job_templates WHERE tool = ? ORDER BY created_at ASC
	`, tool)
	if err != nil {
		return nil, fmt.Errorf("store: list job templates: %w", err)
	}
	defer rows.Close()

	out := []JobTemplate{}
	for rows.Next() {
		var t JobTemplate
		if err := rows.Scan(&t.ID, &t.Tool, &t.Name, &t.Options, &t.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: job template row: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) DeleteJobTemplate(id string) error {
	_, err := s.db.Exec(`DELETE FROM job_templates WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete job template: %w", err)
	}
	return nil
}

// --- Case scans (persisted Probe/JWT/Secret Scanner runs) ---

// CaseScan is one Probe/JWT/Secret Scanner run launched with a case
// selected -- see the migrate() schema comment above case_scans.
type CaseScan struct {
	ID        string    `json:"id"`
	CaseID    string    `json:"caseId"`
	Target    string    `json:"target"`
	Tool      string    `json:"tool"`
	Severity  string    `json:"severity"`
	Summary   string    `json:"summary"`
	Data      string    `json:"data,omitempty"` // raw JSON, opaque to store -- only sent on GetCaseScan, not the list view
	CreatedAt time.Time `json:"createdAt"`
}

func (s *Store) SaveCaseScan(c CaseScan) error {
	_, err := s.db.Exec(`
		INSERT INTO case_scans (id, case_id, target, tool, severity, summary, data, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, c.ID, c.CaseID, c.Target, c.Tool, c.Severity, c.Summary, c.Data, time.Now())
	if err != nil {
		return fmt.Errorf("store: save case scan: %w", err)
	}
	return nil
}

// ListCaseScans returns every scan recorded for a case, most recent first,
// without each row's raw data payload -- a case can accumulate many scans
// over an engagement, and the list view only ever
// needs target/tool/severity/summary. tool optionally narrows the list to
// one tool (e.g. "probe"), for a tab that only cares about its own history;
// pass "" for every tool.
func (s *Store) ListCaseScans(caseID, tool string) ([]CaseScan, error) {
	var rows *sql.Rows
	var err error
	if tool == "" {
		rows, err = s.rdb.Query(`
			SELECT id, case_id, target, tool, severity, summary, created_at
			FROM case_scans WHERE case_id = ? ORDER BY created_at DESC
		`, caseID)
	} else {
		rows, err = s.rdb.Query(`
			SELECT id, case_id, target, tool, severity, summary, created_at
			FROM case_scans WHERE case_id = ? AND tool = ? ORDER BY created_at DESC
		`, caseID, tool)
	}
	if err != nil {
		return nil, fmt.Errorf("store: list case scans: %w", err)
	}
	defer rows.Close()

	out := []CaseScan{}
	for rows.Next() {
		var c CaseScan
		if err := rows.Scan(&c.ID, &c.CaseID, &c.Target, &c.Tool, &c.Severity, &c.Summary, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: case scan row: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetCaseScan returns one scan's full record, including its raw data
// payload -- used when a case scan's details are opened individually.
func (s *Store) GetCaseScan(id string) (CaseScan, error) {
	var c CaseScan
	err := s.rdb.QueryRow(`
		SELECT id, case_id, target, tool, severity, summary, data, created_at FROM case_scans WHERE id = ?
	`, id).Scan(&c.ID, &c.CaseID, &c.Target, &c.Tool, &c.Severity, &c.Summary, &c.Data, &c.CreatedAt)
	if err == sql.ErrNoRows {
		return CaseScan{}, fmt.Errorf("store: case scan %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return CaseScan{}, fmt.Errorf("store: get case scan: %w", err)
	}
	return c, nil
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
	err = s.rdb.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
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
	err = s.rdb.QueryRow(`SELECT data, fetched_at FROM cve_cache WHERE product = ? AND version = ?`, product, version).Scan(&data, &fetchedAt)
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
	if err := s.rdb.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: user count: %w", err)
	}
	return n, nil
}

// EnsureDefaultUser seeds one login (email/password) iff no users exist yet
// -- called once at startup so a fresh install always has something to log
// in with, without ever overwriting or recreating an account someone has
// since changed, renamed, or deleted.
func (s *Store) EnsureDefaultUser(email, password string) (bool, error) {
	n, err := s.UserCount()
	if err != nil {
		return false, err
	}
	if n > 0 {
		return false, nil
	}
	if err := s.CreateUserWithPassword(randomID(), email, password); err != nil {
		return false, err
	}
	return true, nil
}

// VerifyPassword looks up email and checks password against its stored
// bcrypt hash. ok is false for both "no such user" and "wrong password" --
// callers must not distinguish the two in any user-facing response, since
// doing so would let an attacker enumerate valid emails.
func (s *Store) VerifyPassword(email, password string) (User, bool, error) {
	var u User
	var hash string
	err := s.rdb.QueryRow(`SELECT id, email, password_hash, created_at FROM users WHERE email = ?`, strings.ToLower(email)).
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
	now := time.Now()
	// Expired rows are otherwise only removed when that exact token is presented
	// again, so sweep them here on each new login to keep the table bounded.
	if _, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, now); err != nil {
		return fmt.Errorf("store: prune sessions: %w", err)
	}
	_, err := s.db.Exec(`INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		token, userID, now, expiresAt)
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
	err := s.rdb.QueryRow(`
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

// GetCaseScope returns the scope patterns saved for caseID, in insertion order.
// An empty result means the case is unrestricted.
func (s *Store) GetCaseScope(caseID string) ([]string, error) {
	rows, err := s.rdb.Query(`SELECT pattern FROM case_scope WHERE case_id = ? ORDER BY rowid`, caseID)
	if err != nil {
		return nil, fmt.Errorf("store: get case scope: %w", err)
	}
	defer rows.Close()

	out := []string{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, fmt.Errorf("store: case scope row: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: case scope rows: %w", err)
	}
	return out, nil
}

// SetCaseScope replaces caseID's scope patterns with patterns in a single
// transaction, so a failed write never leaves a half-updated scope behind.
// Blank entries are dropped and duplicates collapse; an empty list clears the
// scope, making the case unrestricted again.
func (s *Store) SetCaseScope(caseID string, patterns []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: set case scope: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM case_scope WHERE case_id = ?`, caseID); err != nil {
		return fmt.Errorf("store: clear case scope: %w", err)
	}
	seen := map[string]bool{}
	for _, raw := range patterns {
		p := strings.TrimSpace(raw)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		if _, err := tx.Exec(`INSERT INTO case_scope (case_id, pattern) VALUES (?, ?)`, caseID, p); err != nil {
			return fmt.Errorf("store: insert case scope: %w", err)
		}
	}
	return tx.Commit()
}
