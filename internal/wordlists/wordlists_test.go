package wordlists

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestSafePathRejectsTraversal makes sure a wordlist name can never point
// outside the wordlists directory.
func TestSafePathRejectsTraversal(t *testing.T) {
	for _, bad := range []string{"", "../etc/passwd", "a/../../b", "x..y"} {
		if _, err := safePath(t.TempDir(), bad); err == nil {
			t.Errorf("safePath(%q) accepted a bad name", bad)
		}
	}
}

// TestDownloadSavesBodyAndRejectsErrors checks a successful fetch lands in the
// directory under the requested name, and that a non-200 response is an error
// that writes nothing.
func TestDownloadSavesBodyAndRejectsErrors(t *testing.T) {
	dir := t.TempDir()
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("admin\nlogin\n"))
	}))
	defer ok.Close()
	missing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer missing.Close()

	if err := Download(context.Background(), dir, "words", ok.URL); err != nil {
		t.Fatalf("Download: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "words"))
	if err != nil || string(got) != "admin\nlogin\n" {
		t.Fatalf("saved file = %q, %v", got, err)
	}

	if err := Download(context.Background(), dir, "gone", missing.URL); err == nil {
		t.Fatal("expected an error for a 404 response")
	}
	if _, err := os.Stat(filepath.Join(dir, "gone")); err == nil {
		t.Fatal("a failed download must not leave a file behind")
	}
}

// TestRenameDeleteAndReadLines covers the on-disk management helpers: rename
// moves the file, ReadLines and CountLines see its contents, and delete removes it.
func TestRenameDeleteAndReadLines(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("one\ntwo\nthree\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lines, err := ReadLines(dir, "a")
	if err != nil || !reflect.DeepEqual(lines, []string{"one", "two", "three"}) {
		t.Fatalf("ReadLines = %v, %v", lines, err)
	}
	if n, err := CountLines(filepath.Join(dir, "a")); err != nil || n != 3 {
		t.Fatalf("CountLines = %d, %v; want 3", n, err)
	}
	if err := Rename(dir, "a", "b"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "a")); !os.IsNotExist(err) {
		t.Fatal("old name still exists after rename")
	}
	if err := Delete(dir, "b"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "b")); !os.IsNotExist(err) {
		t.Fatal("file still exists after delete")
	}
}
