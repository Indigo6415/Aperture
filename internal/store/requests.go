package store

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

// requestQueueSize is how many request-log rows can wait for the writer
// before RecordRequest starts blocking the request that produced them. Each
// row can hold two bodies of up to 64 KiB, so this bounds the memory the
// queue can pin at roughly 64 MiB even when every row is full.
const requestQueueSize = 512

// requestBatchSize caps how many queued rows are written in one transaction.
const requestBatchSize = 200

// RequestRecord is one HTTP exchange from a node's request log. The list
// view leaves RequestRaw and ResponseRaw empty; GetRequest fills them in.
type RequestRecord struct {
	ID          int64     `json:"id"`
	RunID       string    `json:"-"`
	NodeID      string    `json:"-"`
	Method      string    `json:"method"`
	URL         string    `json:"url"`
	Host        string    `json:"host"`
	StatusCode  int       `json:"statusCode"`
	Size        int64     `json:"size"`
	TTFBMs      int64     `json:"ttfbMs"`
	Error       string    `json:"error,omitempty"`
	RequestRaw  string    `json:"requestRaw,omitempty"`
	ResponseRaw string    `json:"responseRaw,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
	// Ref identifies this exchange within the process; FromRef is the Ref of
	// the exchange whose redirect led to it, empty when it wasn't a redirect.
	Ref     string `json:"ref,omitempty"`
	FromRef string `json:"fromRef,omitempty"`
	// Hit is true when a finding the scan reported captured this request, so
	// the inspector can highlight only the requests that produced results.
	Hit bool `json:"hit"`
	// Location is the Location header of a 3xx response, empty otherwise.
	Location string `json:"location,omitempty"`
	// CallbackCount is how many collaborator hits matched this exchange's
	// Location. The API fills it in when a list is read; it is never stored.
	CallbackCount int `json:"callbackCount,omitempty"`
}

// RequestHit names one request a scan reported as a finding: its method and
// URL, as the finding's captured request has them.
type RequestHit struct {
	Method string
	URL    string
}

// startRequestWriter starts the single goroutine that persists request-log
// rows. Requests are queued rather than written inline because SQLite allows
// one connection here, and synchronous inserts would serialize every scanner
// goroutine behind the database.
func (s *Store) startRequestWriter() {
	s.requests = make(chan RequestRecord, requestQueueSize)
	s.requestsStop = make(chan struct{})
	s.requestsDone = make(chan struct{})
	go s.writeRequests()
}

// stopRequestWriter asks the writer to flush what is queued and waits for it
// to finish. It does not close the queue channel, so a request still in
// flight during shutdown cannot panic by sending on a closed channel.
func (s *Store) stopRequestWriter() {
	if s.requestsStop == nil {
		return
	}
	close(s.requestsStop)
	<-s.requestsDone
}

// RecordRequest queues one exchange for the request log. The row's run ID may
// name a job run or a direct scan. It returns without writing if the store is
// already shutting down, since the row could no longer be flushed.
func (s *Store) RecordRequest(rec RequestRecord) {
	select {
	case s.requests <- rec:
	case <-s.requestsStop:
	}
}

// writeRequests is the writer loop. It runs until stopRequestWriter, then
// writes whatever is still queued before returning.
func (s *Store) writeRequests() {
	defer close(s.requestsDone)
	for {
		select {
		case rec := <-s.requests:
			s.insertRequests(s.gather(rec))
		case <-s.requestsStop:
			// Shutdown: flush everything already queued, then stop. Records that
			// arrive after this point are dropped by RecordRequest.
			for {
				select {
				case rec := <-s.requests:
					s.insertRequests(s.gather(rec))
				default:
					return
				}
			}
		}
	}
}

// gather returns first plus up to requestBatchSize-1 more rows that are
// already waiting, so a burst of requests lands in a single transaction
// rather than one commit per request.
func (s *Store) gather(first RequestRecord) []RequestRecord {
	batch := []RequestRecord{first}
	for len(batch) < requestBatchSize {
		select {
		case rec := <-s.requests:
			batch = append(batch, rec)
		default:
			return batch
		}
	}
	return batch
}

// insertRequests writes a batch in one transaction. A failed batch is logged
// and dropped: the request log is diagnostic, and losing rows must never
// stop or fail the scan that produced them.
func (s *Store) insertRequests(batch []RequestRecord) {
	tx, err := s.db.Begin()
	if err != nil {
		log.Printf("store: request log: begin: %v", err)
		return
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO requests (run_id, node_id, method, url, host, status_code, size, ttfb_ms, error, request_raw, response_raw, timestamp, ref, from_ref, location)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		log.Printf("store: request log: prepare: %v", err)
		return
	}
	defer stmt.Close()

	for _, rec := range batch {
		_, err := stmt.Exec(rec.RunID, rec.NodeID, rec.Method, rec.URL, rec.Host, rec.StatusCode, rec.Size, rec.TTFBMs, rec.Error, rec.RequestRaw, rec.ResponseRaw, rec.Timestamp, rec.Ref, rec.FromRef, rec.Location)
		if err != nil {
			log.Printf("store: request log: insert: %v", err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		log.Printf("store: request log: commit: %v", err)
	}
}

// ListRequests returns one node's request log in the order the requests were
// made. Raw bodies are left out to keep the list light; fetch a single row
// with GetRequest to see them.
func (s *Store) ListRequests(runID, nodeID string) ([]RequestRecord, error) {
	return s.listRequests(runID, nodeID, "")
}

// SearchRequests is ListRequests limited to rows that contain query somewhere
// in their method, URL, status code, request, or response. Matching is
// case-insensitive for ASCII and is a plain substring match, not a pattern.
func (s *Store) SearchRequests(runID, nodeID, query string) ([]RequestRecord, error) {
	return s.listRequests(runID, nodeID, query)
}

// listRequests does the work for ListRequests and SearchRequests. An empty
// query matches every row. The search reads the raw bodies in SQL so the server
// can filter without sending every body to the browser.
func (s *Store) listRequests(runID, nodeID, query string) ([]RequestRecord, error) {
	// The hit flag is an EXISTS against request_hits, so the list says which rows
	// a finding came from without a second round trip.
	args := []any{runID, nodeID}
	where := "run_id = ? AND node_id = ?"
	if query != "" {
		// instr rather than LIKE, so the query's % and _ are plain characters.
		where += ` AND (instr(lower(method), lower(?)) > 0
			OR instr(lower(url), lower(?)) > 0
			OR instr(CAST(status_code AS TEXT), ?) > 0
			OR instr(lower(request_raw), lower(?)) > 0
			OR instr(lower(response_raw), lower(?)) > 0)`
		args = append(args, query, query, query, query, query)
	}
	rows, err := s.db.Query(`
		SELECT id, method, url, host, status_code, size, ttfb_ms, error, timestamp, ref, from_ref, location,
			EXISTS (SELECT 1 FROM request_hits h
				WHERE h.run_id = requests.run_id AND h.node_id = requests.node_id
				AND h.method = requests.method AND h.url = requests.url) AS hit
		FROM requests WHERE `+where+` ORDER BY id ASC
	`, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list requests: %w", err)
	}
	defer rows.Close()

	out := []RequestRecord{}
	for rows.Next() {
		var r RequestRecord
		var errText sql.NullString
		var hit int
		if err := rows.Scan(&r.ID, &r.Method, &r.URL, &r.Host, &r.StatusCode, &r.Size, &r.TTFBMs, &errText, &r.Timestamp, &r.Ref, &r.FromRef, &r.Location, &hit); err != nil {
			return nil, fmt.Errorf("store: scan request: %w", err)
		}
		r.Error = errText.String
		r.Hit = hit != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// RecordHits marks requests in one node's log as hits. Each hit's method is
// normalized the way net/http reports it, so a finding that left its method
// empty matches the GET the request actually went out as. Duplicates are
// ignored, so reporting the same request twice is harmless.
func (s *Store) RecordHits(runID, nodeID string, hits []RequestHit) error {
	if len(hits) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: record hits: begin: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO request_hits (run_id, node_id, method, url) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("store: record hits: prepare: %w", err)
	}
	defer stmt.Close()

	for _, h := range hits {
		method := strings.ToUpper(h.Method)
		if method == "" {
			method = "GET"
		}
		if _, err := stmt.Exec(runID, nodeID, method, h.URL); err != nil {
			return fmt.Errorf("store: record hits: insert: %w", err)
		}
	}
	return tx.Commit()
}

// GetRequest returns one logged exchange, including its raw request and
// response. It is scoped to the run and node so an ID from another scan
// cannot be read through this one.
func (s *Store) GetRequest(runID, nodeID string, id int64) (RequestRecord, error) {
	var r RequestRecord
	var errText sql.NullString
	err := s.db.QueryRow(`
		SELECT id, method, url, host, status_code, size, ttfb_ms, error, request_raw, response_raw, timestamp, ref, from_ref, location
		FROM requests WHERE id = ? AND run_id = ? AND node_id = ?
	`, id, runID, nodeID).Scan(&r.ID, &r.Method, &r.URL, &r.Host, &r.StatusCode, &r.Size, &r.TTFBMs, &errText, &r.RequestRaw, &r.ResponseRaw, &r.Timestamp, &r.Ref, &r.FromRef, &r.Location)
	if errors.Is(err, sql.ErrNoRows) {
		return RequestRecord{}, ErrNotFound
	}
	if err != nil {
		return RequestRecord{}, fmt.Errorf("store: get request: %w", err)
	}
	r.Error = errText.String
	return r, nil
}
