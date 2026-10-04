package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/Indigo6415/Aperture/internal/engine"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
	"github.com/Indigo6415/Aperture/internal/store"
)

// newGitDumpTestServer builds a server with a fresh store and a bucket dir
// unless dumpDir is empty, in which case the directory is left unset.
func newGitDumpTestServer(t *testing.T, dumpDir string) *Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "gitdump.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := NewServer(st, engine.New(), nil, t.TempDir())
	if dumpDir != "" {
		srv.SetGitDumpDir(dumpDir)
	}
	return srv
}

// postGitDump sends a JSON body to handleGitDump and returns the response.
func postGitDump(t *testing.T, srv *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/gitdump/scan", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handleGitDump(rec, req)
	return rec
}

// TestGitDumpRequestValidation covers the refusals that must happen before any
// scan is queued: no targets, too many, a malformed target, and an unset dump
// directory.
func TestGitDumpRequestValidation(t *testing.T) {
	srv := newGitDumpTestServer(t, t.TempDir())
	cases := map[string]string{
		"no targets":    `{"targets":[]}`,
		"blank targets": `{"targets":["  ", ""]}`,
		"bad scheme":    `{"targets":["ftp://example.com/"]}`,
		"bad speed":     `{"targets":["example.com"],"requestsPerSecond":-1}`,
		"not JSON":      `{"targets":`,
	}
	for name, body := range cases {
		if rec := postGitDump(t, srv, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400: %s", name, rec.Code, rec.Body.String())
		}
	}

	unset := newGitDumpTestServer(t, "")
	if rec := postGitDump(t, unset, `{"targets":["example.com"]}`); rec.Code != http.StatusInternalServerError {
		t.Errorf("unset dump dir: status %d, want 500", rec.Code)
	}
}

// TestGitDumpQueuesScan checks that a valid request is accepted and registered
// as a pending streamed scan, which is what the WebSocket later claims.
func TestGitDumpQueuesScan(t *testing.T) {
	srv := newGitDumpTestServer(t, t.TempDir())
	rec := postGitDump(t, srv, `{"targets":["example.com","https://example.org/app"]}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var out scanStartResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.ScanID == "" {
		t.Fatalf("no scan id in response: %v %s", err, rec.Body.String())
	}
	srv.streamMu.Lock()
	_, ok := srv.pendingScans[out.ScanID]
	srv.streamMu.Unlock()
	if !ok {
		t.Errorf("scan %s was not registered as pending", out.ScanID)
	}
}

// TestGitDumpRunAndDownload runs the dump against one exposed repository and
// one site with no .git. Only the exposed one may leave a bucket, and its zip
// must be downloadable.
func TestGitDumpRunAndDownload(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	site := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		full := append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "init.defaultBranch=main"}, args...)
		cmd := exec.Command("git", full...)
		cmd.Dir = site
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init")
	if err := os.WriteFile(filepath.Join(site, "app.py"), []byte("print('hi')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", "-A")
	git("commit", "-m", "init")
	git("update-server-info")
	exposed := httptest.NewServer(http.FileServer(http.Dir(site)))
	defer exposed.Close()

	plain := t.TempDir()
	if err := os.WriteFile(filepath.Join(plain, "index.html"), []byte("<html></html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	notExposed := httptest.NewServer(http.FileServer(http.Dir(plain)))
	defer notExposed.Close()

	dumpDir := t.TempDir()
	srv := newGitDumpTestServer(t, dumpDir)
	out, err := srv.runGitDump(context.Background(), scanprogress.Discard, "", []string{exposed.URL, notExposed.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.severity != "high" {
		t.Errorf("severity = %q, want high when a repository is exposed", out.severity)
	}
	result, ok := out.result.(gitDumpResult)
	if !ok || len(result.Targets) != 2 {
		t.Fatalf("unexpected result %#v", out.result)
	}
	hit, miss := result.Targets[0], result.Targets[1]
	if !hit.Exposed || hit.BucketID == "" || hit.ZipBytes == 0 || hit.Files != 1 {
		t.Errorf("exposed target: %+v", hit)
	}
	if miss.Exposed || miss.BucketID != "" {
		t.Errorf("non-exposed target should have no bucket: %+v", miss)
	}

	// Only the exposed target's zip and directory should remain in the dump root.
	entries, err := os.ReadDir(dumpDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("dump root holds %v, want one bucket dir and one zip", names)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/gitdump/buckets/"+hit.BucketID+"/download", nil)
	req.SetPathValue("id", hit.BucketID)
	srv.handleGitDumpDownload(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("download status %d", rec.Code)
	}
	if !bytes.HasPrefix(rec.Body.Bytes(), []byte("PK")) {
		t.Errorf("download is not a zip archive")
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(hit.Host+"/app.py")) {
		t.Errorf("zip is not under the host-named folder %q", hit.Host)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Errorf("Content-Disposition = %q, want attachment", cd)
	}

	// A malformed or traversal-shaped ID must never reach the filesystem.
	for _, bad := range []string{"../etc/passwd", "short", strings.Repeat("g", 32)} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/gitdump/buckets/x/download", nil)
		req.SetPathValue("id", bad)
		srv.handleGitDumpDownload(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("download of %q: status %d, want 404", bad, rec.Code)
		}
	}
}

// TestGitDumpEndToEnd drives the whole path the browser uses: an authenticated
// POST to /api/gitdump/scan, the WebSocket claim on /ws/scans/{id}, and the
// terminal "done" event carrying the result. The scan is saved as a case scan
// under the "gitdump" tool, which is what the tab restores on reload.
func TestGitDumpEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	site := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		full := append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "init.defaultBranch=main"}, args...)
		cmd := exec.Command("git", full...)
		cmd.Dir = site
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init")
	if err := os.WriteFile(filepath.Join(site, "secret.env"), []byte("TOKEN=abc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", "-A")
	git("commit", "-m", "init")
	git("update-server-info")
	target := httptest.NewServer(http.FileServer(http.Dir(site)))
	defer target.Close()

	dumpDir := t.TempDir()
	srv := newGitDumpTestServer(t, dumpDir)
	if err := srv.store.CreateUserWithPassword("tester", "tester@example.com", "pw"); err != nil {
		t.Fatal(err)
	}
	const token = "gitdump-e2e-session"
	if err := srv.store.CreateSession(token, "tester", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	app := httptest.NewServer(srv.Handler())
	defer app.Close()

	body, _ := json.Marshal(gitDumpRequest{Targets: []string{target.URL}})
	req, _ := http.NewRequest(http.MethodPost, app.URL+"/api/gitdump/scan", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST status %d", resp.StatusCode)
	}
	var start scanStartResult
	if err := json.NewDecoder(resp.Body).Decode(&start); err != nil || start.ScanID == "" {
		t.Fatalf("no scan id: %v", err)
	}

	// Claim the scan over the WebSocket, the same way the browser does, and read
	// events until the terminal one arrives.
	wsURL := "ws" + strings.TrimPrefix(app.URL, "http") + "/ws/scans/" + start.ScanID
	hdr := http.Header{"Cookie": []string{sessionCookie + "=" + token}}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, hdr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	var done RunEvent
	// Each pass reads one event off the stream.
	for {
		var ev RunEvent
		if err := conn.ReadJSON(&ev); err != nil {
			t.Fatalf("stream ended before done: %v", err)
		}
		if ev.Type == "done" {
			done = ev
			break
		}
	}
	if done.Status != engine.StatusSucceeded {
		t.Fatalf("done status %q: %s", done.Status, done.Message)
	}
	var result gitDumpResult
	if err := json.Unmarshal(done.Result, &result); err != nil {
		t.Fatalf("result: %v", err)
	}
	if len(result.Targets) != 1 || !result.Targets[0].Exposed || result.Targets[0].BucketID == "" {
		t.Fatalf("unexpected result: %+v", result)
	}

	// The bucket the result names must be downloadable through the real route.
	dl, err := http.NewRequest(http.MethodGet, app.URL+"/api/gitdump/buckets/"+result.Targets[0].BucketID+"/download", nil)
	if err != nil {
		t.Fatal(err)
	}
	dl.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	dlResp, err := http.DefaultClient.Do(dl)
	if err != nil {
		t.Fatal(err)
	}
	defer dlResp.Body.Close()
	zipBody, _ := io.ReadAll(dlResp.Body)
	if dlResp.StatusCode != http.StatusOK || !bytes.HasPrefix(zipBody, []byte("PK")) {
		t.Fatalf("download: status %d, zip magic missing", dlResp.StatusCode)
	}
	// Without a session the download must be refused like every other route.
	anon, err := http.Get(app.URL + "/api/gitdump/buckets/" + result.Targets[0].BucketID + "/download")
	if err != nil {
		t.Fatal(err)
	}
	anon.Body.Close()
	if anon.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous download status %d, want 401", anon.StatusCode)
	}
}
