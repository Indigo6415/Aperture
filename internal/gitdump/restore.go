package gitdump

import (
	"archive/zip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// maxTreeDepth bounds how deeply nested a tree may be before the restore
// stops descending. It stops a self-referencing or absurdly nested tree from
// running the walk forever.
const maxTreeDepth = 64

// safeRelPath checks a repository path before it is written to disk. A hostile
// tree can name "../x", "a/../../b", "/etc/x" or ".git/config", and writing any
// of those would escape the bucket or overwrite the repository's own metadata.
// Names are also refused if they hold a backslash or NUL, or are longer than a
// filesystem allows. It returns the path unchanged, or false.
func safeRelPath(p string) (string, bool) {
	if p == "" || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\x00\\") {
		return "", false
	}
	// Each pass checks one path component.
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." || strings.EqualFold(part, ".git") || len(part) > 255 {
			return "", false
		}
	}
	return p, true
}

// restore rebuilds the working tree next to .git. It uses the HEAD commit's
// tree when HEAD resolves to a commit in the store, and falls back to the
// index when it doesn't, so a repository missing its HEAD commit still yields
// every staged file.
func (d *dumper) restore(indexEntries []fileEntry) {
	entries := d.headTree()
	from := "HEAD"
	if len(entries) == 0 && len(indexEntries) > 0 {
		entries = indexEntries
		from = "index"
	}
	if len(entries) == 0 {
		return
	}
	d.res.RestoredFrom = from
	d.writeFiles(entries)
}

// headTree flattens the tree of the commit HEAD names. It returns nil and
// records a warning if HEAD can't be followed to a readable commit.
func (d *dumper) headTree() []fileEntry {
	sha, ok := d.resolveHead()
	if !ok {
		d.warn("HEAD does not resolve to a commit that was downloaded")
		return nil
	}
	typ, data, err := d.store.read(sha)
	if err != nil || typ != "commit" {
		d.warn("HEAD commit %s is unreadable", sha)
		return nil
	}
	treeSHA, ok := commitTree(data)
	if !ok {
		d.warn("HEAD commit %s names no tree", sha)
		return nil
	}
	var out []fileEntry
	if err := d.walkTree(treeSHA, "", 0, &out); err != nil {
		d.warn("working tree: %v", err)
	}
	return out
}

// commitTree returns the tree a commit object names on its first header line.
func commitTree(data []byte) (string, bool) {
	header, _, _ := strings.Cut(string(data), "\n\n")
	// Each pass checks one header line for the tree reference.
	for _, line := range strings.Split(header, "\n") {
		if sha, ok := strings.CutPrefix(line, "tree "); ok && validSHA(sha) {
			return sha, true
		}
	}
	return "", false
}

// resolveHead returns the commit name HEAD points at, following a symbolic ref
// through the loose ref file or packed-refs.
func (d *dumper) resolveHead() (string, bool) {
	head := strings.TrimSpace(string(d.headBody))
	if validSHA(head) {
		return head, true
	}
	name, ok := strings.CutPrefix(head, "ref: ")
	if !ok {
		return "", false
	}
	return d.resolveRef(name)
}

// resolveRef finds the commit name a ref holds. The loose ref file is tried
// first, then packed-refs, matching git's own lookup order.
func (d *dumper) resolveRef(name string) (string, bool) {
	if !validRefName(name) {
		return "", false
	}
	if body, err := os.ReadFile(filepath.Join(d.gitDir, filepath.FromSlash(name))); err == nil {
		if sha := strings.TrimSpace(string(body)); validSHA(sha) {
			return sha, true
		}
	}
	packed, err := os.ReadFile(filepath.Join(d.gitDir, "packed-refs"))
	if err != nil {
		return "", false
	}
	// Each pass checks one packed-refs line for the ref.
	for _, line := range strings.Split(string(packed), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == name && validSHA(fields[0]) {
			return fields[0], true
		}
	}
	return "", false
}

// walkTree appends every file under the tree at sha to out, with paths
// prefixed by prefix. A subtree that can't be read is skipped with a warning
// rather than abandoning the rest of the tree.
func (d *dumper) walkTree(sha, prefix string, depth int, out *[]fileEntry) error {
	if depth > maxTreeDepth {
		return fmt.Errorf("tree nesting exceeds %d", maxTreeDepth)
	}
	typ, data, err := d.store.read(sha)
	if err != nil {
		return err
	}
	if typ != "tree" {
		return fmt.Errorf("%s is a %s, not a tree", sha, typ)
	}
	entries, err := parseTree(data)
	if err != nil {
		return err
	}
	// Each pass handles one entry of this directory.
	for _, e := range entries {
		if len(*out) >= maxRestoreFiles {
			return fmt.Errorf("more than %d files; the rest were not restored", maxRestoreFiles)
		}
		path := prefix + e.path
		switch e.mode {
		case "40000":
			if err := d.walkTree(e.sha, path+"/", depth+1, out); err != nil {
				d.warn("%s/: %v", path, err)
			}
		case "160000":
			// A submodule is a commit in another repository, so there's no content
			// here to restore.
		default:
			*out = append(*out, fileEntry{path: path, mode: e.mode, sha: e.sha})
		}
	}
	return nil
}

// writeFiles writes each entry's blob into the bucket. Symlinks (mode 120000)
// are written as ordinary files holding the link target, so no link is ever
// created on disk that could later redirect a write outside the bucket.
func (d *dumper) writeFiles(entries []fileEntry) {
	root := filepath.Dir(d.gitDir)
	var total int64
	// Each pass writes one file.
	for _, e := range entries {
		rel, ok := safeRelPath(e.path)
		if !ok {
			d.warn("skipped unsafe path %q", e.path)
			continue
		}
		typ, data, err := d.store.read(e.sha)
		if err != nil {
			d.warn("%s: %v", rel, err)
			continue
		}
		if typ != "blob" {
			d.warn("%s is a %s, not a blob", rel, typ)
			continue
		}
		total += int64(len(data))
		if total > maxRestoreBytes {
			d.warn("restore size limit of %d bytes reached", maxRestoreBytes)
			return
		}
		dst := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			d.warn("%s: %v", rel, err)
			continue
		}
		perm := os.FileMode(0o644)
		if e.mode == "100755" {
			perm = 0o755
		}
		if err := os.WriteFile(dst, data, perm); err != nil {
			d.warn("%s: %v", rel, err)
			continue
		}
		d.res.Files++
	}
}

// Zip writes everything under dir into a zip archive at zipPath. Every entry
// is placed under a top-level folder named prefix, so an archive opened by
// hand shows the target's name as its root.
func Zip(dir, prefix, zipPath string) error {
	out, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(out)
	walkErr := filepath.WalkDir(dir, func(path string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !de.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		w, err := zw.Create(prefix + "/" + filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(w, f)
		return err
	})
	if err := zw.Close(); walkErr == nil {
		walkErr = err
	}
	if err := out.Close(); walkErr == nil {
		walkErr = err
	}
	return walkErr
}
