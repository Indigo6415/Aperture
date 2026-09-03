// Package wordlists manages the text files ffuf/feroxbuster fuzz with: a
// bundled default so a fresh install can scan immediately, plus a small
// catalog of well-known lists (SecLists, dirb) the user can download on
// demand instead of hunting them down manually.
package wordlists

import (
	"bufio"
	"context"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

//go:embed assets/default.txt
var defaultWordlist []byte

// DefaultName is the filename the bundled wordlist is written out as, and
// the one the auto-generated domain-scan flow points ffuf/feroxbuster at.
const DefaultName = "default.txt"

// maxDownloadBytes caps how large a downloaded wordlist may be, so a
// misbehaving URL (or an accidental multi-GB SecLists file) can't fill the
// user's disk from one click.
const maxDownloadBytes = 50 * 1024 * 1024

// Info describes one wordlist file on disk. Path is the absolute path on
// the machine running the Aperture server -- ffuf/feroxbuster run there as
// subprocesses, so it's what a flow's node config needs to point at (the
// frontend has no filesystem access of its own to resolve Name from).
type Info struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	Lines   int    `json:"lines"`
	Builtin bool   `json:"builtin"`
}

// CatalogEntry is one downloadable well-known wordlist offered in the
// Wordlists UI section, alongside letting the user paste an arbitrary URL.
type CatalogEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
}

// Catalog lists a handful of well-known, modestly-sized content-discovery
// wordlists from SecLists, fetched via GitHub's raw file host. Every URL
// here is verified to resolve -- SecLists reshuffles file layout across
// releases often enough that a stale path is worth checking for if
// downloads start failing.
func Catalog() []CatalogEntry {
	return []CatalogEntry{
		{
			Name:        "seclists-common.txt",
			Description: "SecLists: common web content (~4.6k lines)",
			URL:         "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
		},
		{
			Name:        "seclists-raft-small-directories.txt",
			Description: "SecLists: RAFT small directory list (~2.3k lines)",
			URL:         "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt",
		},
		{
			Name:        "seclists-raft-small-words.txt",
			Description: "SecLists: RAFT small word list (~4.9k lines)",
			URL:         "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-words.txt",
		},
		{
			Name:        "seclists-quickhits.txt",
			Description: "SecLists: curated high-signal quick hits (~600 lines)",
			URL:         "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/quickhits.txt",
		},
	}
}

// EnsureDefault writes the embedded default wordlist into dir if it isn't
// there already, so a brand-new install has something to fuzz with before
// the user has downloaded anything.
func EnsureDefault(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("wordlists: create dir: %w", err)
	}
	path := filepath.Join(dir, DefaultName)
	if _, err := os.Stat(path); err == nil {
		return nil // already present -- don't clobber a user edit
	}
	if err := os.WriteFile(path, defaultWordlist, 0o644); err != nil {
		return fmt.Errorf("wordlists: write default: %w", err)
	}
	return nil
}

// List returns every wordlist file present in dir, with a fast line count
// for each (files here are text wordlists, typically well under the size
// where a full read-through would be noticeably slow).
func List(dir string) ([]Info, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("wordlists: read dir: %w", err)
	}
	out := []Info{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		lines, err := countLines(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		out = append(out, Info{Name: e.Name(), Path: filepath.Join(dir, e.Name()), Size: fi.Size(), Lines: lines, Builtin: e.Name() == DefaultName})
	}
	return out, nil
}

func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	n := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	// Count non-empty lines only, since a trailing newline or a few blank
	// separator lines shouldn't count as fuzzable entries.
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			n++
		}
	}
	return n, scanner.Err()
}

// Delete removes a wordlist by name. The bundled default is protected since
// it's the one thing guaranteed to exist for the auto-generated scan flow.
func Delete(dir, name string) error {
	if name == DefaultName {
		return fmt.Errorf("wordlists: %s is the built-in default and can't be deleted", DefaultName)
	}
	path, err := safePath(dir, name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("wordlists: delete: %w", err)
	}
	return nil
}

var validName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// safePath resolves name to a path inside dir, rejecting anything that
// looks like a path traversal or absolute path attempt before it ever
// reaches the filesystem.
func safePath(dir, name string) (string, error) {
	if name == "" || !validName.MatchString(name) || strings.Contains(name, "..") {
		return "", fmt.Errorf("wordlists: invalid name %q", name)
	}
	return filepath.Join(dir, name), nil
}

// Download fetches url and saves it into dir under name, refusing anything
// over maxDownloadBytes so one request can't fill the disk. Used both for
// Catalog entries and an arbitrary user-supplied URL.
func Download(ctx context.Context, dir, name, url string) error {
	path, err := safePath(dir, name)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("wordlists: build request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("wordlists: download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("wordlists: download: unexpected status %d", resp.StatusCode)
	}

	// Write to a temp file first so a failed/oversized download never
	// leaves a corrupt partial file at the final name.
	tmp := path + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("wordlists: create file: %w", err)
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxDownloadBytes+1))
	f.Close()
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("wordlists: write file: %w", err)
	}
	if n > maxDownloadBytes {
		os.Remove(tmp)
		return fmt.Errorf("wordlists: download exceeds %d byte limit", maxDownloadBytes)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("wordlists: finalize file: %w", err)
	}
	return nil
}
