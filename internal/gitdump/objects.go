package gitdump

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// maxObjectBytes caps how large one object (or one downloaded file) may be,
// both on the wire and once inflated. A hostile server can claim any size, so
// nothing is read past this.
const maxObjectBytes = 32 << 20

// sha1Hex matches a full object name as it appears in text files (refs,
// reflogs, packed-refs, FETCH_HEAD). The word boundaries keep it from matching
// the middle of a longer hex run.
var sha1Hex = regexp.MustCompile(`\b[0-9a-f]{40}\b`)

// validSHA reports whether s is a 40-character lowercase hex object name.
func validSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && s == strings.ToLower(s)
}

// fileEntry is one path a repository's working tree contains, as read from a
// tree object or the index. Mode is the git octal mode string ("100644",
// "100755", "120000", "160000", or "40000" for a directory in a tree).
type fileEntry struct {
	path string
	mode string
	sha  string
}

// hashObject returns the object name git would give typ/data: the SHA-1 of
// "<type> <size>\0" followed by the content. Every fetched object is checked
// against this, which is what stops a soft-404 page from being stored as one.
func hashObject(typ string, data []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "%s %d\x00", typ, len(data))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// parseLoose inflates the raw bytes of a loose object file and splits its
// "<type> <size>\0" header from its content. It rejects anything whose
// declared size doesn't match what was actually inflated.
func parseLoose(raw []byte) (string, []byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return "", nil, fmt.Errorf("not a zlib stream: %w", err)
	}
	defer zr.Close()
	all, err := io.ReadAll(io.LimitReader(zr, maxObjectBytes+128))
	if err != nil {
		return "", nil, err
	}
	nul := bytes.IndexByte(all, 0)
	if nul < 0 {
		return "", nil, fmt.Errorf("object header has no terminator")
	}
	typ, sizeText, ok := strings.Cut(string(all[:nul]), " ")
	if !ok {
		return "", nil, fmt.Errorf("malformed object header")
	}
	size, err := strconv.Atoi(sizeText)
	if err != nil {
		return "", nil, fmt.Errorf("malformed object size: %w", err)
	}
	data := all[nul+1:]
	if len(data) != size {
		return "", nil, fmt.Errorf("object size mismatch: header says %d, got %d", size, len(data))
	}
	return typ, data, nil
}

// refsOf returns the object names an object points at: a commit's tree and
// parents, a tree's entries (minus submodule commits, which live in another
// repository), a tag's target. Blobs point at nothing.
func refsOf(typ string, data []byte) ([]string, []fileEntry, error) {
	switch typ {
	case "commit":
		var out []string
		// The header is everything before the first blank line; the message
		// that follows can contain anything, so it's excluded.
		header, _, _ := strings.Cut(string(data), "\n\n")
		// Each pass checks one header line for a tree or parent reference.
		for _, line := range strings.Split(header, "\n") {
			if sha, ok := strings.CutPrefix(line, "tree "); ok && validSHA(sha) {
				out = append(out, sha)
			}
			if sha, ok := strings.CutPrefix(line, "parent "); ok && validSHA(sha) {
				out = append(out, sha)
			}
		}
		return out, nil, nil
	case "tree":
		entries, err := parseTree(data)
		if err != nil {
			return nil, nil, err
		}
		var out []string
		// Each pass keeps one tree entry's object name for the walk.
		for _, e := range entries {
			if e.mode != "160000" {
				out = append(out, e.sha)
			}
		}
		return out, entries, nil
	case "tag":
		if sha, ok := strings.CutPrefix(strings.SplitN(string(data), "\n", 2)[0], "object "); ok && validSHA(sha) {
			return []string{sha}, nil, nil
		}
		return nil, nil, nil
	}
	return nil, nil, nil
}

// parseTree decodes a tree object's binary body: a sequence of
// "<octal mode> <name>\0<20 raw sha bytes>" records.
func parseTree(data []byte) ([]fileEntry, error) {
	var out []fileEntry
	// Each pass reads one record; the loop ends when the body is consumed.
	for len(data) > 0 {
		sp := bytes.IndexByte(data, ' ')
		if sp < 0 {
			return nil, fmt.Errorf("tree entry has no mode terminator")
		}
		nul := bytes.IndexByte(data[sp+1:], 0)
		if nul < 0 {
			return nil, fmt.Errorf("tree entry has no name terminator")
		}
		nameEnd := sp + 1 + nul
		if nameEnd+1+20 > len(data) {
			return nil, fmt.Errorf("tree entry truncated")
		}
		out = append(out, fileEntry{
			mode: string(data[:sp]),
			path: string(data[sp+1 : nameEnd]),
			sha:  hex.EncodeToString(data[nameEnd+1 : nameEnd+21]),
		})
		data = data[nameEnd+21:]
	}
	return out, nil
}

// parseIndex reads the entries of a .git/index file (format versions 2 and 3).
// The index lists every staged path with its blob, so it can surface files
// that were never committed. Version 4's prefix-compressed paths aren't
// handled, and an error is returned for it.
func parseIndex(b []byte) ([]fileEntry, error) {
	if len(b) < 12 || string(b[:4]) != "DIRC" {
		return nil, fmt.Errorf("not a git index")
	}
	version := binary.BigEndian.Uint32(b[4:8])
	if version != 2 && version != 3 {
		return nil, fmt.Errorf("unsupported index version %d", version)
	}
	count := binary.BigEndian.Uint32(b[8:12])
	var out []fileEntry
	pos := 12
	// Each pass reads one fixed-size index entry plus its variable-length name.
	for i := uint32(0); i < count; i++ {
		if pos+62 > len(b) {
			return nil, fmt.Errorf("index truncated at entry %d", i)
		}
		start := pos
		mode := binary.BigEndian.Uint32(b[pos+24:])
		sha := hex.EncodeToString(b[pos+40 : pos+60])
		flags := binary.BigEndian.Uint16(b[pos+60:])
		pos += 62
		// Version 3 adds a 2-byte extended-flags field when bit 14 is set.
		if version == 3 && flags&0x4000 != 0 {
			pos += 2
		}
		nameLen := int(flags & 0xfff)
		// A length of 0xfff means the name is longer than the field can hold,
		// so it runs to the NUL terminator instead.
		if nameLen == 0xfff {
			nul := bytes.IndexByte(b[pos:], 0)
			if nul < 0 {
				return nil, fmt.Errorf("index entry %d has no name terminator", i)
			}
			nameLen = nul
		}
		if pos+nameLen > len(b) {
			return nil, fmt.Errorf("index entry %d name truncated", i)
		}
		name := string(b[pos : pos+nameLen])
		out = append(out, fileEntry{path: name, mode: strconv.FormatUint(uint64(mode), 8), sha: sha})
		// Git pads each entry with 1-8 NULs so its total length is a multiple of
		// 8 and at least one byte longer than its unpadded length. Rounding
		// (unpadded + 8) down to a multiple of 8 gives exactly that.
		unpadded := pos - start + nameLen
		pos = start + ((unpadded + 8) &^ 7)
	}
	return out, nil
}

// objectStore reads objects from a local .git directory, whether they're
// loose files or inside a downloaded pack. Reads are safe to run concurrently
// as long as reload isn't called at the same time.
type objectStore struct {
	gitDir string
	packs  []*pack
}

// openStore returns a store over gitDir/objects, opening every pack whose
// .idx and .pack are both present. Call close when finished with it.
func openStore(gitDir string) *objectStore {
	s := &objectStore{gitDir: gitDir}
	s.reload()
	return s
}

// reload picks up packs that have been downloaded since the store was opened.
// Packs that fail to open are skipped rather than failing the whole dump.
func (s *objectStore) reload() {
	s.close()
	idxFiles, _ := filepath.Glob(filepath.Join(s.gitDir, "objects", "pack", "pack-*.idx"))
	// Each pass opens one pack, if its matching .pack file is also on disk.
	for _, idxPath := range idxFiles {
		packPath := strings.TrimSuffix(idxPath, ".idx") + ".pack"
		p, err := openPack(idxPath, packPath)
		if err != nil {
			continue
		}
		s.packs = append(s.packs, p)
	}
}

// close releases every open pack file.
func (s *objectStore) close() {
	// Each pass releases one open pack.
	for _, p := range s.packs {
		p.close()
	}
	s.packs = nil
}

// has reports whether sha is readable locally, as a loose object or in a pack.
func (s *objectStore) has(sha string) bool {
	if _, err := os.Stat(s.loosePath(sha)); err == nil {
		return true
	}
	raw, err := hex.DecodeString(sha)
	if err != nil {
		return false
	}
	var key [20]byte
	copy(key[:], raw)
	// Each pass checks one pack's index for the object.
	for _, p := range s.packs {
		if _, ok := p.offset(key); ok {
			return true
		}
	}
	return false
}

// read returns the type and content of sha, from the loose store first and
// then from packs.
func (s *objectStore) read(sha string) (string, []byte, error) {
	if raw, err := os.ReadFile(s.loosePath(sha)); err == nil {
		typ, data, err := parseLoose(raw)
		if err != nil {
			return "", nil, err
		}
		return typ, data, nil
	}
	key, err := shaBytes(sha)
	if err != nil {
		return "", nil, err
	}
	// Each pass tries one pack, stopping at the first that contains the object.
	for _, p := range s.packs {
		if off, ok := p.offset(key); ok {
			return p.readAt(off, s.read, 0)
		}
	}
	return "", nil, fmt.Errorf("object %s not found locally", sha)
}

// loosePath is where a loose object with this name lives: objects/ab/cdef...
func (s *objectStore) loosePath(sha string) string {
	return filepath.Join(s.gitDir, "objects", sha[:2], sha[2:])
}

// shaBytes converts a hex object name to its 20 raw bytes.
func shaBytes(sha string) ([20]byte, error) {
	var out [20]byte
	raw, err := hex.DecodeString(sha)
	if err != nil || len(raw) != 20 {
		return out, fmt.Errorf("invalid object name %q", sha)
	}
	copy(out[:], raw)
	return out, nil
}
