package gitdump

import (
	"bytes"
	"compress/zlib"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// requireGit skips the test when no git binary is installed. The fixtures
// are real repositories built with git itself, so the tests need one.
func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
}

// gitIn runs git in dir with a fixed identity so commits are reproducible,
// and fails the test on any error.
func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	full := append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"}, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// writeTree writes files (relative path -> content) under root, creating
// directories as needed.
func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// serveSite serves root over HTTP the way a misconfigured web server would:
// every file, .git included, is reachable.
func serveSite(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// readFile returns a file's content under dir, failing the test if it's absent.
func readFile(t *testing.T, dir, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("expected %s to be restored: %v", rel, err)
	}
	return string(b)
}

// fsck runs git fsck --strict against a dumped bucket's .git. A clean run
// proves the downloaded objects form a valid repository, not just files that
// happen to parse.
func fsck(t *testing.T, bucket string) {
	t.Helper()
	gitIn(t, bucket, "--git-dir="+filepath.Join(bucket, ".git"), "fsck", "--strict", "--no-dangling")
}

func TestDumpLooseRepository(t *testing.T) {
	requireGit(t)
	site := t.TempDir()
	gitIn(t, site, "init")
	writeTree(t, site, map[string]string{
		"README.md":   "# demo\n",
		"src/main.go": "package main\n",
		"bin/run.sh":  "#!/bin/sh\necho hi\n",
	})
	if runtime.GOOS != "windows" {
		if err := os.Chmod(filepath.Join(site, "bin/run.sh"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	gitIn(t, site, "add", "-A")
	gitIn(t, site, "commit", "-m", "first")
	writeTree(t, site, map[string]string{"src/main.go": "package main\n\nfunc main() {}\n"})
	gitIn(t, site, "commit", "-am", "second")
	// update-server-info writes info/refs and objects/info/packs, the two files a
	// dumb-HTTP server exposes that make the repository listable.
	gitIn(t, site, "update-server-info")

	srv := serveSite(t, http.FileServer(http.Dir(site)))
	bucket := t.TempDir()
	res, err := Dump(context.Background(), srv.URL, bucket, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Exposed {
		t.Fatalf("expected exposed, got %+v", res)
	}
	if res.Files != 3 {
		t.Errorf("restored %d files, want 3; warnings %v", res.Files, res.Warnings)
	}
	if got := readFile(t, bucket, "src/main.go"); got != "package main\n\nfunc main() {}\n" {
		t.Errorf("src/main.go = %q, want the HEAD revision", got)
	}
	if got := readFile(t, bucket, "README.md"); got != "# demo\n" {
		t.Errorf("README.md = %q", got)
	}
	if res.MissingObjects != 0 {
		t.Errorf("MissingObjects = %d, want 0; warnings %v", res.MissingObjects, res.Warnings)
	}
	if res.RestoredFrom != "HEAD" {
		t.Errorf("RestoredFrom = %q, want HEAD", res.RestoredFrom)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(bucket, "bin/run.sh"))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o100 == 0 {
			t.Errorf("bin/run.sh lost its executable bit: %v", info.Mode())
		}
	}
	fsck(t, bucket)
	if log := gitIn(t, bucket, "--git-dir="+filepath.Join(bucket, ".git"), "log", "--oneline"); strings.Count(log, "\n") != 2 {
		t.Errorf("dumped history has %d commits, want 2:\n%s", strings.Count(log, "\n"), log)
	}
}

func TestDumpPackedRepository(t *testing.T) {
	requireGit(t)
	site := t.TempDir()
	gitIn(t, site, "init")
	// Many near-identical revisions of one file make git store later versions
	// as deltas, so restoring them exercises OFS/REF delta resolution.
	base := strings.Repeat("a line of text that repeats so that delta compression has something to find\n", 300)
	body := base
	for i := 0; i < 15; i++ {
		body += fmt.Sprintf("revision %d\n", i)
		writeTree(t, site, map[string]string{"data/big.txt": body})
		gitIn(t, site, "add", "-A")
		gitIn(t, site, "commit", "-m", fmt.Sprintf("rev %d", i))
	}
	// Packing everything and removing the loose copies means the dump can only
	// get these objects from the pack.
	gitIn(t, site, "repack", "-adf")
	gitIn(t, site, "prune-packed")
	gitIn(t, site, "update-server-info")
	idx, err := filepath.Glob(filepath.Join(site, ".git", "objects", "pack", "pack-*.idx"))
	if err != nil || len(idx) != 1 {
		t.Fatalf("expected one pack index, got %v (%v)", idx, err)
	}
	if verify := gitIn(t, site, "verify-pack", "-v", idx[0]); !strings.Contains(verify, "chain length") {
		t.Fatalf("fixture has no delta chains, so it doesn't exercise delta resolution:\n%s", verify)
	}

	srv := serveSite(t, http.FileServer(http.Dir(site)))
	bucket := t.TempDir()
	res, err := Dump(context.Background(), srv.URL, bucket, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Exposed || res.Packs != 1 {
		t.Fatalf("expected exposed with one pack, got %+v", res)
	}
	if got := readFile(t, bucket, "data/big.txt"); got != body {
		t.Errorf("data/big.txt restored from pack differs from the committed content (len %d, want %d)", len(got), len(body))
	}
	fsck(t, bucket)
}

func TestDumpFallsBackToIndex(t *testing.T) {
	requireGit(t)
	site := t.TempDir()
	gitIn(t, site, "init")
	writeTree(t, site, map[string]string{"staged.txt": "never committed\n", "dir/also.txt": "also staged\n"})
	gitIn(t, site, "add", "-A")
	// HEAD names a branch that doesn't exist, so the commit can't be followed and
	// the only path to the files is the index.
	if err := os.WriteFile(filepath.Join(site, ".git", "HEAD"), []byte("ref: refs/heads/nothing-here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, site, "update-server-info")

	srv := serveSite(t, http.FileServer(http.Dir(site)))
	bucket := t.TempDir()
	res, err := Dump(context.Background(), srv.URL, bucket, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.RestoredFrom != "index" {
		t.Fatalf("RestoredFrom = %q, want index; warnings %v", res.RestoredFrom, res.Warnings)
	}
	if got := readFile(t, bucket, "staged.txt"); got != "never committed\n" {
		t.Errorf("staged.txt = %q", got)
	}
	if got := readFile(t, bucket, "dir/also.txt"); got != "also staged\n" {
		t.Errorf("dir/also.txt = %q", got)
	}
}

func TestDumpNotExposed(t *testing.T) {
	site := t.TempDir()
	writeTree(t, site, map[string]string{"index.html": "<html>nothing to see</html>"})
	srv := serveSite(t, http.FileServer(http.Dir(site)))

	bucket := t.TempDir()
	res, err := Dump(context.Background(), srv.URL, bucket, Options{})
	if err != nil {
		t.Fatalf("a target without git should not be an error: %v", err)
	}
	if res.Exposed {
		t.Errorf("reported exposed for a site with no .git: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(bucket, ".git")); err == nil {
		t.Errorf("created .git for a target that isn't exposed")
	}
}

// TestDumpRejectsSoft404Objects serves a valid HEAD, but every object request
// returns a well-formed zlib blob whose content doesn't hash to the name it was
// requested under. None of them may be stored.
func TestDumpRejectsObjectsThatDoNotHash(t *testing.T) {
	requireGit(t)
	site := t.TempDir()
	gitIn(t, site, "init")
	writeTree(t, site, map[string]string{"a.txt": "real\n"})
	gitIn(t, site, "add", "-A")
	gitIn(t, site, "commit", "-m", "x")
	gitIn(t, site, "update-server-info")
	files := http.FileServer(http.Dir(site))

	bogus := func() []byte {
		var buf bytes.Buffer
		zw := zlib.NewWriter(&buf)
		zw.Write([]byte("blob 3\x00abc"))
		zw.Close()
		return buf.Bytes()
	}()
	srv := serveSite(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/.git/objects/") && !strings.Contains(r.URL.Path, "/info/") {
			w.Write(bogus)
			return
		}
		files.ServeHTTP(w, r)
	}))

	bucket := t.TempDir()
	res, err := Dump(context.Background(), srv.URL, bucket, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Exposed {
		t.Fatalf("HEAD is valid, so the target should be exposed: %+v", res)
	}
	if res.Objects != 0 || res.Files != 0 {
		t.Errorf("stored or restored objects that don't hash to their names: objects=%d files=%d", res.Objects, res.Files)
	}
	if res.MissingObjects == 0 {
		t.Errorf("expected the bogus objects to count as missing")
	}
	if _, err := os.Stat(filepath.Join(bucket, ".git", "objects")); err == nil {
		// Loose objects live in two-hex-character fan-out directories. The
		// objects/info/ metadata file is not one, so it's excluded.
		entries, _ := filepath.Glob(filepath.Join(bucket, ".git", "objects", "[0-9a-f][0-9a-f]", "*"))
		if len(entries) != 0 {
			t.Errorf("wrote %d loose object files that failed verification", len(entries))
		}
	}
}

// TestCandidates pins how the target forms an operator might paste are turned
// into base URLs.
func TestCandidates(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"example.com", []string{"https://example.com/", "http://example.com/"}},
		{"https://x.com/app", []string{"https://x.com/app/"}},
		{"https://x.com/app/.git/HEAD", []string{"https://x.com/app/"}},
		{"https://x.com/.git", []string{"https://x.com/"}},
		{"http://x.com/.github/", []string{"http://x.com/.github/"}},
		{"http://x.com:8080/a/?q=1", []string{"http://x.com:8080/a/"}},
	}
	for _, tc := range cases {
		got, err := Candidates(tc.in)
		if err != nil {
			t.Errorf("Candidates(%q): %v", tc.in, err)
			continue
		}
		if strings.Join(got, " ") != strings.Join(tc.want, " ") {
			t.Errorf("Candidates(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{"", "ftp://x.com/", "https://"} {
		if _, err := Candidates(bad); err == nil {
			t.Errorf("Candidates(%q) should fail", bad)
		}
	}
}

// TestSafeRelPath is the path-traversal guard. A tree that names any of these
// must not be written to disk.
func TestSafeRelPath(t *testing.T) {
	bad := []string{"", "/etc/passwd", "../x", "a/../../b", "a//b", "./a", ".git/config", "a/.GIT/x", "a\\b", "a/\x00b"}
	for _, p := range bad {
		if _, ok := safeRelPath(p); ok {
			t.Errorf("safeRelPath(%q) accepted an unsafe path", p)
		}
	}
	for _, p := range []string{"main.go", "src/x/y.go", ".gitignore", "a.git/b"} {
		if _, ok := safeRelPath(p); !ok {
			t.Errorf("safeRelPath(%q) rejected a safe path", p)
		}
	}
}

// TestApplyDelta builds a small git delta by hand: copy all of the base, then
// insert two literal bytes.
func TestApplyDelta(t *testing.T) {
	base := []byte("hello world")
	// Source size 11, target size 13. Copy op 0x91 takes an offset byte and a
	// size byte, both zero and eleven. Insert op 0x02 adds "!!".
	delta := []byte{11, 13, 0x91, 0x00, 0x0b, 0x02, '!', '!'}
	got, err := applyDelta(base, delta)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello world!!" {
		t.Errorf("applyDelta = %q", got)
	}
	// A copy that runs past the base must be refused, not read out of bounds.
	if _, err := applyDelta(base, []byte{11, 4, 0x91, 0x08, 0x04}); err == nil {
		t.Errorf("out-of-range copy was accepted")
	}
}

// TestZip checks that the archive holds every restored file under the
// host-named top-level folder.
func TestZip(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a/b.txt": "x", "c.txt": "y"})
	out := filepath.Join(t.TempDir(), "out.zip")
	if err := Zip(dir, "example.com", out); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"example.com/a/b.txt", "example.com/c.txt"} {
		if !bytes.Contains(b, []byte(name)) {
			t.Errorf("archive is missing entry %q", name)
		}
	}
}

// TestDumpFindsOutlierGitSpellings serves a repository whose directory is named
// with a spelling other than the standard ".git". The standard path must 404,
// the dump must still find the repository, and GitPath must report the
// spelling that matched.
func TestDumpFindsOutlierGitSpellings(t *testing.T) {
	requireGit(t)
	cases := map[string]string{
		".GIT/":    ".GIT",
		".git;/":   ".git;",
		".git%20/": ".git ",
	}
	for variant, dirName := range cases {
		t.Run(variant, func(t *testing.T) {
			site := t.TempDir()
			gitIn(t, site, "init")
			writeTree(t, site, map[string]string{"main.go": "package main\n"})
			gitIn(t, site, "add", "-A")
			gitIn(t, site, "commit", "-m", "x")
			gitIn(t, site, "update-server-info")
			// Rename the repository directory so only the outlier spelling reaches it.
			if err := os.Rename(filepath.Join(site, ".git"), filepath.Join(site, dirName)); err != nil {
				t.Skipf("filesystem can't hold %q: %v", dirName, err)
			}
			// On a case-insensitive filesystem (macOS default), ".GIT" is the same
			// directory as ".git", so the standard spelling would match first and
			// the outlier could not be isolated.
			if _, err := os.Stat(filepath.Join(site, ".git")); err == nil {
				t.Skipf("filesystem is case-insensitive; %q cannot be isolated from .git", variant)
			}
			srv := serveSite(t, http.FileServer(http.Dir(site)))

			bucket := t.TempDir()
			res, err := Dump(context.Background(), srv.URL, bucket, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if !res.Exposed {
				t.Fatalf("outlier spelling %q was not found: %+v", variant, res)
			}
			if res.GitPath != variant {
				t.Errorf("GitPath = %q, want %q", res.GitPath, variant)
			}
			if got := readFile(t, bucket, "main.go"); got != "package main\n" {
				t.Errorf("main.go = %q", got)
			}
		})
	}
}
