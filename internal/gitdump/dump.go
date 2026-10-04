// Package gitdump recovers source code from publicly exposed .git directories.
//
// A web server that serves its document root with a .git directory inside it
// leaks the whole repository history. Dump checks a target for an exposed
// repository, downloads what's needed to rebuild it (refs, reflog, index,
// packs, and every loose object reachable from them), then restores the HEAD
// working tree from the object store. The bucket directory ends up holding a
// real .git plus the checked-out files.
//
// Nothing downloaded is executed. The remote .git/config and .gitattributes
// can name filter and fsmonitor commands that a local git would run, so the
// local git binary is never used on them. Restoration is done here in Go.
package gitdump

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Indigo6415/Aperture/internal/netgov"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
)

// requestTimeout bounds one request for a .git file or object. Object files are
// small, so a request that runs this long is a stalled target.
const requestTimeout = 15 * time.Second

// objectWorkers is how many object downloads run at once within one wave. The
// netgov transport paces each host on top of this, so a few is plenty.
const objectWorkers = 8

// maxObjects caps how many objects one dump will walk, so an enormous history
// can't turn one target into an unbounded crawl.
const maxObjects = 50000

// maxRestoreFiles and maxRestoreBytes bound the working tree written to disk.
const (
	maxRestoreFiles = 50000
	maxRestoreBytes = 512 << 20
)

// maxWarnings caps how many warning lines one result keeps. Past that, the
// dump still runs; the extra warnings are simply not recorded.
const maxWarnings = 50

// metaFiles are the fixed .git-relative paths fetched alongside HEAD. Each is
// optional: most repositories have some of them, and a missing one is not an
// error.
var metaFiles = []string{
	"config",
	"description",
	"index",
	"packed-refs",
	"info/refs",
	"logs/HEAD",
	"FETCH_HEAD",
	"ORIG_HEAD",
	"COMMIT_EDITMSG",
	"objects/info/packs",
	"refs/stash",
}

// commonBranches are branch refs guessed for when the server doesn't list refs
// anywhere. Git has no directory listing over plain HTTP, so these are the
// cheapest way to find a branch that HEAD doesn't name.
var commonBranches = []string{
	"refs/heads/main",
	"refs/heads/master",
	"refs/heads/develop",
	"refs/heads/dev",
	"refs/heads/staging",
	"refs/heads/production",
	"refs/remotes/origin/HEAD",
}

// zeroSHA is git's null object name, written into reflogs to mean "nothing
// before this entry". It's a placeholder, not an object.
const zeroSHA = "0000000000000000000000000000000000000000"

// headPattern matches a valid HEAD: either a symbolic ref to a refs/ path, or a
// detached commit name. An HTML error page matches neither.
var headPattern = regexp.MustCompile(`^(ref: refs/[A-Za-z0-9._/-]+|[0-9a-f]{40})$`)

// refNamePattern is the character set allowed in a ref name we'll fetch.
var refNamePattern = regexp.MustCompile(`^refs/[A-Za-z0-9._/-]+$`)

// packNamePattern matches the file name of a pack, as listed in objects/info/packs.
var packNamePattern = regexp.MustCompile(`^pack-[0-9a-f]{40,64}\.pack$`)

// Options configures one dump.
type Options struct {
	// Headers is applied to every request, e.g. a saved credential's cookie.
	Headers map[string]string
	// Progress receives phase updates. Nil discards them.
	Progress scanprogress.Reporter
}

// Result is what happened to one target. Exposed is false when no candidate
// URL served a valid HEAD, and then nothing else is filled in.
type Result struct {
	BaseURL string `json:"baseUrl"`
	// GitPath is the .git spelling that matched, such as ".git/" or ".GIT/".
	// Anything other than the standard ".git/" is an outlier worth reporting.
	GitPath        string   `json:"gitPath,omitempty"`
	Host           string   `json:"host"`
	Exposed        bool     `json:"exposed"`
	HeadRef        string   `json:"headRef,omitempty"`
	Refs           int      `json:"refs"`
	Packs          int      `json:"packs"`
	Objects        int      `json:"objects"`
	MissingObjects int      `json:"missingObjects"`
	Files          int      `json:"files"`
	RestoredFrom   string   `json:"restoredFrom,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
}

// Candidates turns one operator-supplied target into the base URLs to try, in
// order. A bare host gets https first and then http. A URL that points into a
// .git directory, such as https://host/app/.git/HEAD, is trimmed back to the
// directory above it, so the operator can paste whichever form they have.
func Candidates(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("target is empty")
	}
	schemed := []string{raw}
	if !strings.Contains(raw, "://") {
		schemed = []string{"https://" + raw, "http://" + raw}
	}
	var out []string
	// Each pass turns one scheme-qualified form of the target into a normalized base URL.
	for _, s := range schemed {
		base, err := baseURL(s)
		if err != nil {
			return nil, err
		}
		out = append(out, base)
	}
	return out, nil
}

// baseURL normalizes one URL to scheme://host/path/ with the query and any
// trailing .git component removed.
func baseURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid target %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("target %q must be http or https", raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("target %q has no host", raw)
	}
	p := u.EscapedPath()
	// Cut at the first "/.git" that ends a path segment, so "/.github/" is left
	// alone but "/.git" and "/.git/HEAD" are both trimmed.
	if i := strings.Index(p, "/.git"); i >= 0 && (i+5 == len(p) || p[i+5] == '/') {
		p = p[:i]
	}
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return u.Scheme + "://" + u.Host + p, nil
}

// hostLabel returns the host part of base, with the port's colon swapped out
// so it's safe to use as a directory name in a zip archive.
func hostLabel(base string) string {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return "target"
	}
	return strings.ReplaceAll(u.Host, ":", "_")
}

// Dump checks target for an exposed .git and, if one is found, downloads and
// restores it into dir. The result is always non-nil. An error comes back only
// when every candidate URL failed at the transport level, or the context was
// cancelled; a target that simply has no exposed repository is not an error.
func Dump(ctx context.Context, target, dir string, opts Options) (*Result, error) {
	progress := opts.Progress
	if progress == nil {
		progress = scanprogress.Discard
	}
	candidates, err := Candidates(target)
	if err != nil {
		return &Result{BaseURL: target, Host: target}, err
	}
	res := &Result{BaseURL: candidates[0], Host: hostLabel(candidates[0])}

	client := netgov.NewClient(requestTimeout, false)
	var f *fetcher
	var head []byte
	var lastErr error
	answered := false
	// Each pass probes one candidate base URL, trying every .git spelling in
	// turn, and stops at the first spelling that serves a valid HEAD.
probed:
	for _, c := range candidates {
		// Each pass tries one spelling of the .git directory under this candidate.
		for _, variant := range gitDirVariants {
			progress.Phase("Checking " + c + variant + "HEAD")
			cand := newFetcher(client, c+variant, opts.Headers)
			body, found, err := cand.get(ctx, "HEAD")
			// A cancelled run must surface as cancelled, not as a target that
			// simply isn't exposed, so the context is checked before the probe
			// result is judged.
			if ctxErr := ctx.Err(); ctxErr != nil {
				return res, ctxErr
			}
			if err != nil {
				lastErr = err
				continue
			}
			answered = true
			if found && headPattern.MatchString(strings.TrimSpace(string(body))) {
				f = cand
				head = body
				res.BaseURL = c
				res.GitPath = variant
				res.Host = hostLabel(c)
				break probed
			}
		}
	}
	if f == nil {
		// Only a total transport failure is an error. If any candidate answered,
		// the target just doesn't expose git.
		if !answered {
			return res, lastErr
		}
		return res, nil
	}

	res.Exposed = true
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		return res, err
	}
	d := &dumper{ctx: ctx, f: f, gitDir: gitDir, res: res, progress: progress, headBody: head}
	if err := d.run(); err != nil {
		return res, err
	}
	return res, nil
}

// fetcher downloads files from one target's .git directory.
type fetcher struct {
	client  *http.Client
	gitURL  string
	headers map[string]string
}

// newFetcher builds a fetcher rooted at base's .git directory.
func newFetcher(client *http.Client, gitURL string, headers map[string]string) *fetcher {
	return &fetcher{client: client, gitURL: gitURL, headers: headers}
}

// gitDirVariants are the spellings of the .git directory name a probe tries, in
// order. The first is the standard one. The rest cover servers that are
// case-insensitive, that strip trailing dots or spaces, that treat ';' as a
// path parameter, or that decode percent-encoding at a different layer from the
// origin, so an exposed repository under an unusual spelling is still found.
var gitDirVariants = []string{".git/", ".GIT/", ".Git/", ".git./", ".git%20/", ".git;/", "%2egit/"}

// get fetches one .git-relative path. It returns found=false, with no error,
// for anything that isn't a 200, so an absent file reads the same as a 404.
func (f *fetcher) get(ctx context.Context, rel string) ([]byte, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.gitURL+rel, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", "Aperture-GitDump")
	netgov.ApplyHeaders(req, f.headers)
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false, nil
	}
	body, err := readCapped(resp.Body)
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", rel, err)
	}
	return body, true, nil
}

// readCapped reads a response body up to maxObjectBytes and fails if it's
// longer, rather than buffering whatever a hostile server sends.
func readCapped(r io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(io.LimitReader(r, maxObjectBytes+1)); err != nil {
		return nil, err
	}
	if buf.Len() > maxObjectBytes {
		return nil, fmt.Errorf("response exceeds %d bytes", maxObjectBytes)
	}
	return buf.Bytes(), nil
}

// dumper holds the state of one target's dump.
type dumper struct {
	ctx      context.Context
	f        *fetcher
	gitDir   string
	res      *Result
	progress scanprogress.Reporter
	headBody []byte
	store    *objectStore
}

// warn records one warning line on the result, up to maxWarnings.
func (d *dumper) warn(format string, args ...any) {
	if len(d.res.Warnings) < maxWarnings {
		d.res.Warnings = append(d.res.Warnings, fmt.Sprintf(format, args...))
	}
}

// save writes body to rel under the local .git. rel is always a fixed name or
// a validated ref or pack name, so it can't leave that directory.
func (d *dumper) save(rel string, body []byte) error {
	path := filepath.Join(d.gitDir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o644)
}

// fetchSave downloads one .git-relative file and stores it locally. A missing
// file returns ok=false with no warning; a transport or write failure is
// recorded as a warning and also returns ok=false.
func (d *dumper) fetchSave(rel string) ([]byte, bool) {
	body, found, err := d.f.get(d.ctx, rel)
	if err != nil {
		if d.ctx.Err() == nil {
			d.warn("%s: %v", rel, err)
		}
		return nil, false
	}
	if !found {
		return nil, false
	}
	if err := d.save(rel, body); err != nil {
		d.warn("save %s: %v", rel, err)
		return nil, false
	}
	return body, true
}

// run performs the whole dump for an exposed repository.
func (d *dumper) run() error {
	defer func() {
		if d.store != nil {
			d.store.close()
		}
	}()
	if err := d.save("HEAD", d.headBody); err != nil {
		return err
	}

	// Metadata first. Every text file is kept so that its 40-hex names can be
	// used as roots below.
	d.progress.Phase("Downloading refs, index and reflog")
	texts := map[string][]byte{"HEAD": d.headBody}
	// Each pass fetches one optional metadata file and keeps it if the server has it.
	for _, rel := range metaFiles {
		if body, ok := d.fetchSave(rel); ok {
			texts[rel] = body
		}
		if err := d.ctx.Err(); err != nil {
			return err
		}
	}

	refNames := map[string]bool{}
	if name, ok := strings.CutPrefix(strings.TrimSpace(string(d.headBody)), "ref: "); ok {
		d.res.HeadRef = name
		refNames[name] = true
	}
	// Each pass queues one guessed branch ref. It's only kept if the server actually has it.
	for _, name := range commonBranches {
		refNames[name] = true
	}
	// packed-refs and info/refs both list "<sha> <refname>" lines, which name
	// refs the HEAD file doesn't.
	for _, rel := range []string{"packed-refs", "info/refs"} {
		// Each pass reads one "<sha> <refname>" line from the ref listings.
		for _, line := range strings.Split(string(texts[rel]), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && validRefName(fields[1]) {
				refNames[fields[1]] = true
			}
		}
	}
	names := make([]string, 0, len(refNames))
	// Copies the valid names into a sorted slice, so refs are fetched in a stable order.
	for name := range refNames {
		if validRefName(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	// Each pass fetches one ref. Its commit name becomes a root if the server has the ref.
	for _, name := range names {
		if body, ok := d.fetchSave(name); ok {
			texts[name] = body
			d.res.Refs++
		}
	}

	// Every 40-hex name in a text file is a candidate root. The index is binary
	// and is handled separately, and objects/info/packs is skipped because its
	// pack names carry hex that is not an object.
	roots := map[string]bool{}
	// Each pass scans one saved text file for the object names it mentions.
	for rel, body := range texts {
		if rel == "index" || rel == "objects/info/packs" || rel == "config" {
			continue
		}
		// Each pass records one object name found in that file as a root.
		for _, sha := range sha1Hex.FindAllString(string(body), -1) {
			roots[sha] = true
		}
	}
	if sha := strings.TrimSpace(string(d.headBody)); validSHA(sha) {
		roots[sha] = true
	}

	// The index names every staged blob, which can include files that were
	// never committed.
	var indexEntries []fileEntry
	if idx, ok := texts["index"]; ok {
		entries, err := parseIndex(idx)
		if err != nil {
			d.warn("index: %v", err)
		} else {
			indexEntries = entries
			// Each pass queues one staged blob. Submodule commits live in another repository, so they're skipped.
			for _, e := range entries {
				if e.mode != "160000" {
					roots[e.sha] = true
				}
			}
		}
	}

	if err := d.downloadPacks(texts["objects/info/packs"]); err != nil {
		return err
	}

	// Opened after the packs are on disk, so their objects are readable locally
	// and only the loose objects that are still missing need downloading.
	d.store = openStore(d.gitDir)
	d.progress.Phase("Downloading objects")
	list := make([]string, 0, len(roots))
	// Each pass copies one root into the list that is then sorted for a deterministic download order.
	for sha := range roots {
		list = append(list, sha)
	}
	sort.Strings(list)
	if err := d.walk(list); err != nil {
		return err
	}

	d.progress.Phase("Restoring working tree")
	d.restore(indexEntries)
	return d.ctx.Err()
}

// downloadPacks fetches each pack that objects/info/packs lists, together with
// its .idx. A pack needs both to be usable, so a half-downloaded one is left
// for the store to skip.
func (d *dumper) downloadPacks(listing []byte) error {
	// Each pass handles one line of the pack listing.
	for _, line := range strings.Split(string(listing), "\n") {
		name, ok := strings.CutPrefix(strings.TrimSpace(line), "P ")
		if !ok || !packNamePattern.MatchString(name) {
			continue
		}
		base := "objects/pack/" + strings.TrimSuffix(name, ".pack")
		if _, ok := d.fetchSave(base + ".idx"); !ok {
			d.warn("%s.idx could not be downloaded", base)
			continue
		}
		if _, ok := d.fetchSave(base + ".pack"); !ok {
			d.warn("%s.pack could not be downloaded", base)
			continue
		}
		d.res.Packs++
		if err := d.ctx.Err(); err != nil {
			return err
		}
	}
	return nil
}

// walk downloads every object reachable from roots. It works in waves: each
// wave fetches the objects the previous one referenced, so a commit's tree is
// requested only after the commit has been read.
func (d *dumper) walk(roots []string) error {
	visited := map[string]bool{}
	var next []string
	add := func(shas ...string) {
		// Each pass takes one candidate name, keeping it if it's new and well-formed.
		// The all-zero name is git's "no object" marker, which reflogs use for
		// their first entry, so it's never a real object to fetch.
		for _, sha := range shas {
			if validSHA(sha) && sha != zeroSHA && !visited[sha] {
				visited[sha] = true
				next = append(next, sha)
			}
		}
	}
	add(roots...)

	wave := 0
	// Each pass downloads one wave of objects and queues what they reference.
	for len(next) > 0 {
		if err := d.ctx.Err(); err != nil {
			return err
		}
		if d.res.Objects+len(next) > maxObjects {
			d.warn("object limit of %d reached; the rest of the history was not downloaded", maxObjects)
			break
		}
		wave++
		current := next
		next = nil
		d.progress.Phase(fmt.Sprintf("Downloading objects: wave %d, %d queued", wave, len(current)))
		// Each pass folds one object's outcome into the counts and queues the objects it references.
		for _, r := range d.fetchWave(current) {
			if r.err != nil {
				d.warn("%v", r.err)
			}
			if r.missing {
				d.res.MissingObjects++
				continue
			}
			d.res.Objects++
			add(r.children...)
		}
	}
	return d.ctx.Err()
}

// objResult is the outcome of obtaining one object.
type objResult struct {
	missing  bool
	err      error
	children []string
}

// fetchWave obtains every object in shas, up to objectWorkers at a time. Each
// goroutine writes only its own slot, so no lock is needed.
func (d *dumper) fetchWave(shas []string) []objResult {
	out := make([]objResult, len(shas))
	sem := make(chan struct{}, objectWorkers)
	var wg sync.WaitGroup
	// Each pass starts one object's download.
	for i, sha := range shas {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			out[i] = d.obtain(sha)
		}()
	}
	wg.Wait()
	return out
}

// obtain returns one object's children, reading it from the local store if
// it's already there (a packed object, say) and otherwise downloading its loose
// file. A downloaded file is kept only if it inflates and hashes to the name it
// was requested under, so a soft-404 page can't pass as an object.
func (d *dumper) obtain(sha string) objResult {
	if d.store.has(sha) {
		typ, data, err := d.store.read(sha)
		if err != nil {
			return objResult{missing: true, err: fmt.Errorf("%s: %w", sha, err)}
		}
		children, _, err := refsOf(typ, data)
		return objResult{children: children, err: err}
	}

	raw, found, err := d.f.get(d.ctx, "objects/"+sha[:2]+"/"+sha[2:])
	if err != nil {
		return objResult{missing: true, err: err}
	}
	if !found {
		return objResult{missing: true}
	}
	typ, data, err := parseLoose(raw)
	if err != nil {
		return objResult{missing: true, err: fmt.Errorf("%s: %w", sha, err)}
	}
	if hashObject(typ, data) != sha {
		return objResult{missing: true, err: fmt.Errorf("%s: served content does not hash to its name", sha)}
	}
	path := d.store.loosePath(sha)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return objResult{err: err}
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return objResult{err: err}
	}
	children, _, err := refsOf(typ, data)
	return objResult{children: children, err: err}
}

// validRefName reports whether name is a refs/ path that is safe to fetch and
// save. The character set is narrow, and "..", empty components and
// dot-prefixed components are refused outright.
func validRefName(name string) bool {
	if !refNamePattern.MatchString(name) || strings.Contains(name, "..") || strings.Contains(name, "//") || strings.HasSuffix(name, "/") {
		return false
	}
	// Each pass checks one path component.
	for _, part := range strings.Split(name, "/") {
		if strings.HasPrefix(part, ".") {
			return false
		}
	}
	return true
}
