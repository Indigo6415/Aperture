// Package wordlists manages the text files ffuf/feroxbuster fuzz with: a
// bundled default so a fresh install can scan immediately, plus a small
// catalog of well-known lists (SecLists, dirb) the user can download on
// demand instead of hunting them down manually.
package wordlists

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
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

//go:embed assets/subdomains.txt
var subdomainsWordlist []byte

// DefaultName is the filename the bundled wordlist is written out as, and
// the one the auto-generated domain-scan flow points ffuf/feroxbuster at.
const DefaultName = "default.txt"

// SubdomainsDefaultName is the filename the bundled subdomain/vhost-label
// wordlist is written out as -- the one the auto-generated subdomain- and
// vhost-bruteforce scanners point ffuf at.
const SubdomainsDefaultName = "subdomains-default.txt"

// maxDownloadBytes caps how large a downloaded wordlist may be, so a
// misbehaving URL (or an accidental multi-GB SecLists file) can't fill the
// user's disk from one click.
const maxDownloadBytes = 50 * 1024 * 1024

// Category buckets a wordlist by which scanner it's meant to feed --
// content discovery (Directories), subdomain/vhost bruteforce
// (Subdomains), the extension list ffuf/feroxbuster fan out over
// (Extensions), or nothing scanner-specific (Misc). A wordlist can belong
// to more than one category at once (see SetCategories), so the same list
// can drive two different scanners without keeping two copies on disk.
type Category string

const (
	CategoryDirectories Category = "directories"
	CategorySubdomains  Category = "subdomains"
	CategoryExtensions  Category = "extensions"
	CategoryMisc        Category = "misc"
)

// Categories lists every valid Category, in the fixed order the UI renders
// its category containers.
func Categories() []Category {
	return []Category{CategoryDirectories, CategorySubdomains, CategoryExtensions, CategoryMisc}
}

func validCategory(c Category) bool {
	for _, v := range Categories() {
		if v == c {
			return true
		}
	}
	return false
}

// defaultCategoriesFor is the category a wordlist starts in before the user
// ever assigns one explicitly -- the two bundled defaults and any
// known-subdomain catalog entry land in the category their scanner
// actually needs, so a fresh install works without the user having to
// categorize anything, and everything else starts in Misc.
func defaultCategoriesFor(name string) []Category {
	switch {
	case name == DefaultName:
		return []Category{CategoryDirectories}
	case name == SubdomainsDefaultName, strings.Contains(strings.ToLower(name), "subdomain"):
		return []Category{CategorySubdomains}
	default:
		return []Category{CategoryMisc}
	}
}

// categoriesFile is the sidecar JSON file (name -> categories) that
// persists category assignments alongside the wordlist files themselves.
// It's plain data, not a wordlist, so List skips it.
const categoriesFile = ".categories.json"

func loadCategoryMap(dir string) (map[string][]Category, error) {
	data, err := os.ReadFile(filepath.Join(dir, categoriesFile))
	if os.IsNotExist(err) {
		return map[string][]Category{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("wordlists: read categories: %w", err)
	}
	m := map[string][]Category{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("wordlists: parse categories: %w", err)
	}
	return m, nil
}

func saveCategoryMap(dir string, m map[string][]Category) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("wordlists: encode categories: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, categoriesFile), data, 0o644); err != nil {
		return fmt.Errorf("wordlists: write categories: %w", err)
	}
	return nil
}

// SetCategories replaces the full set of categories name belongs to.
// Passing an empty slice clears every explicit assignment, reverting name
// to its defaultCategoriesFor bucket on the next List.
func SetCategories(dir, name string, cats []Category) error {
	path, err := safePath(dir, name)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("wordlists: %s not found", name)
	}
	seen := map[Category]struct{}{}
	deduped := make([]Category, 0, len(cats))
	for _, c := range cats {
		if !validCategory(c) {
			return fmt.Errorf("wordlists: invalid category %q", c)
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		deduped = append(deduped, c)
	}

	m, err := loadCategoryMap(dir)
	if err != nil {
		return err
	}
	m[name] = deduped
	return saveCategoryMap(dir, m)
}

// Duplicate copies name's file content into a new wordlist called newName
// and assigns it cats (or, if cats is empty, name's own current
// categories). This is how the same underlying content ends up usable by
// two different scanner categories at once -- dragging one wordlist into a
// second category container in the UI calls this rather than moving it,
// so the original keeps feeding its original scanner too.
func Duplicate(dir, name, newName string, cats []Category) error {
	srcPath, err := safePath(dir, name)
	if err != nil {
		return err
	}
	dstPath, err := safePath(dir, newName)
	if err != nil {
		return err
	}
	if _, err := os.Stat(dstPath); err == nil {
		return fmt.Errorf("wordlists: %s already exists", newName)
	}
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("wordlists: read source: %w", err)
	}
	if err := os.WriteFile(dstPath, data, 0o644); err != nil {
		return fmt.Errorf("wordlists: write duplicate: %w", err)
	}

	if len(cats) == 0 {
		m, err := loadCategoryMap(dir)
		if err != nil {
			return err
		}
		cats = m[name]
		if len(cats) == 0 {
			cats = defaultCategoriesFor(name)
		}
	}
	return SetCategories(dir, newName, cats)
}

// Info describes one wordlist file on disk. Path is the absolute path on
// the machine running the Aperture server -- ffuf/feroxbuster run there as
// subprocesses, so it's what a flow's node config needs to point at (the
// frontend has no filesystem access of its own to resolve Name from).
type Info struct {
	Name       string     `json:"name"`
	Path       string     `json:"path"`
	Size       int64      `json:"size"`
	Lines      int        `json:"lines"`
	Builtin    bool       `json:"builtin"`
	Categories []Category `json:"categories"`
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
		{
			Name:        "seclists-subdomains-5000.txt",
			Description: "SecLists: top 5,000 subdomain/vhost names, for subdomain + virtual-host bruteforcing",
			URL:         "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
		},
		{
			Name:        "seclists-subdomains-20000.txt",
			Description: "SecLists: top 20,000 subdomain/vhost names, for subdomain + virtual-host bruteforcing",
			URL:         "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt",
		},
	}
}

// EnsureDefault writes the embedded default content and subdomain
// wordlists into dir if they aren't there already, so a brand-new install
// has something to fuzz with before the user has downloaded anything.
func EnsureDefault(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("wordlists: create dir: %w", err)
	}
	if err := writeIfAbsent(dir, DefaultName, defaultWordlist); err != nil {
		return err
	}
	if err := writeIfAbsent(dir, SubdomainsDefaultName, subdomainsWordlist); err != nil {
		return err
	}
	return nil
}

func writeIfAbsent(dir, name string, content []byte) error {
	path := filepath.Join(dir, name)
	if _, err := os.Stat(path); err == nil {
		return nil // already present -- don't clobber a user edit
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		return fmt.Errorf("wordlists: write %s: %w", name, err)
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
	catMap, err := loadCategoryMap(dir)
	if err != nil {
		return nil, err
	}
	out := []Info{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// The category sidecar and a download-in-progress temp file aren't
		// wordlists themselves.
		if name == categoriesFile || strings.HasSuffix(name, ".part") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		lines, err := CountLines(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		builtin := name == DefaultName || name == SubdomainsDefaultName
		cats := catMap[name]
		if len(cats) == 0 {
			cats = defaultCategoriesFor(name)
		}
		out = append(out, Info{Name: name, Path: filepath.Join(dir, name), Size: fi.Size(), Lines: lines, Builtin: builtin, Categories: cats})
	}
	return out, nil
}

// CountLines counts the non-empty lines in a wordlist file -- also used by
// the ffuf adapter to compute a request-count total for progress reporting.
func CountLines(path string) (int, error) {
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

// Delete removes a wordlist by name. The bundled defaults are protected
// since they're guaranteed to exist for the auto-generated scan flow.
func Delete(dir, name string) error {
	if name == DefaultName || name == SubdomainsDefaultName {
		return fmt.Errorf("wordlists: %s is a built-in default and can't be deleted", name)
	}
	path, err := safePath(dir, name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("wordlists: delete: %w", err)
	}
	if m, err := loadCategoryMap(dir); err == nil {
		if _, ok := m[name]; ok {
			delete(m, name)
			_ = saveCategoryMap(dir, m)
		}
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

// filesInCategory returns the absolute paths of every wordlist tagged with
// cat, in List's (stable, name-sorted-by-ReadDir) order.
func filesInCategory(dir string, cat Category) ([]string, error) {
	list, err := List(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, w := range list {
		for _, c := range w.Categories {
			if c == cat {
				files = append(files, w.Path)
				break
			}
		}
	}
	return files, nil
}

// CombinedForCategory merges every wordlist tagged with cat into one
// deduplicated file a scanner can point -w at. This is what makes
// category assignment actually reach the scanners: content discovery
// fuzzes with whatever's tagged Directories, subdomain/vhost bruteforce
// with whatever's tagged Subdomains, instead of always the small bundled
// default regardless of what the user has downloaded and categorized.
//
// A single tagged file is returned as-is (no copy needed). Zero tagged
// files falls back to fallback -- a built-in default filename inside dir
// -- so a fresh install with nothing categorized yet still has something
// to fuzz with. More than one tagged file is merged into a fresh temp
// file under the OS temp dir; the caller doesn't need to clean it up
// (it's small, and the OS reclaims temp dirs over time), but a given
// call's merge reflects category membership at that moment, not live
// afterward.
func CombinedForCategory(dir string, cat Category, fallback string) (string, error) {
	files, err := filesInCategory(dir, cat)
	if err != nil {
		return "", err
	}
	if len(files) == 0 {
		if fallback == "" {
			return "", fmt.Errorf("wordlists: no wordlist tagged %q", cat)
		}
		return filepath.Join(dir, fallback), nil
	}
	if len(files) == 1 {
		return files[0], nil
	}

	tmp, err := os.CreateTemp("", "aperture-"+string(cat)+"-*.txt")
	if err != nil {
		return "", fmt.Errorf("wordlists: create combined temp file: %w", err)
	}
	defer tmp.Close()

	seen := map[string]struct{}{}
	bw := bufio.NewWriter(tmp)
	for _, path := range files {
		if err := appendUniqueLines(bw, path, seen); err != nil {
			return "", err
		}
	}
	if err := bw.Flush(); err != nil {
		return "", fmt.Errorf("wordlists: write combined temp file: %w", err)
	}
	return tmp.Name(), nil
}

// ExtensionsForCategory reads every wordlist tagged Extensions and returns
// its deduplicated lines (a leading "." is stripped, so both "php" and
// ".php" style lists work) for scanners that take extensions as a literal
// list (ffuf -e / feroxbuster -x) rather than as a -w wordlist.
func ExtensionsForCategory(dir string) ([]string, error) {
	files, err := filesInCategory(dir, CategoryExtensions)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []string
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			ext := strings.TrimPrefix(strings.TrimSpace(scanner.Text()), ".")
			if ext == "" {
				continue
			}
			if _, ok := seen[ext]; ok {
				continue
			}
			seen[ext] = struct{}{}
			out = append(out, ext)
		}
		f.Close()
	}
	return out, nil
}

// appendUniqueLines copies path's non-empty lines into bw, skipping any
// already present in seen (shared across every file in one combine pass,
// so the merge is deduplicated across files, not just within one).
func appendUniqueLines(bw *bufio.Writer, path string, seen map[string]struct{}) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("wordlists: read %s: %w", filepath.Base(path), err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		bw.WriteString(line)
		bw.WriteByte('\n')
	}
	return scanner.Err()
}
