package pathtraversal

import (
	"encoding/base64"
	"regexp"
	"strings"
)

// fileSig is one known file's signature. strong means the text is specific
// enough to confirm a read on its own (the file is almost never quoted on a
// normal page). A weak signature still needs the negative control before it
// is reported, and it is reported with "likely" confidence instead of "confirmed".
type fileSig struct {
	name   string
	strong bool
	// match returns the matched snippet and true when text contains this file.
	match func(text string) (string, bool)
}

// regexSig builds a fileSig from a regular expression. The evidence is the
// first matching line.
func regexSig(name string, strong bool, pattern string) fileSig {
	re := regexp.MustCompile(pattern)
	return fileSig{name: name, strong: strong, match: func(text string) (string, bool) {
		loc := re.FindString(text)
		return loc, loc != ""
	}}
}

// substrSig builds a fileSig that needs every listed substring to appear.
// The evidence is the first substring, which is what the report will show.
func substrSig(name string, strong bool, subs ...string) fileSig {
	return fileSig{name: name, strong: strong, match: func(text string) (string, bool) {
		for _, s := range subs {
			if !strings.Contains(text, s) {
				return "", false
			}
		}
		return subs[0], true
	}}
}

// passwdLine matches one passwd-format entry: name:password:uid:gid:gecos:home:shell.
var passwdLine = regexp.MustCompile(`(?m)^[^:\s]+:[^:\n]*:\d+:\d+:[^\n]*$`)

// rootPasswdLine matches root's entry with UID and GID 0.
var rootPasswdLine = regexp.MustCompile(`(?m)^root:[^:\n]*:0:0:[^\n]*$`)

// passwdSig matches a passwd listing: root's UID 0 entry plus at least one
// more entry in the same format. A lone "root:x:0:0" line is common in docs
// and forum posts, but a listing that goes on past root is not.
func passwdSig() fileSig {
	return fileSig{name: "/etc/passwd", strong: true, match: func(text string) (string, bool) {
		root := rootPasswdLine.FindString(text)
		// Without root's UID 0 entry this is not a passwd file, so stop there.
		if root == "" {
			return "", false
		}
		// Asking for three matches is enough: root plus one more is what counts.
		if len(passwdLine.FindAllString(text, 3)) < 2 {
			return "", false
		}
		return root, true
	}}
}

// fileSigs is the set of file contents that count as a read. Each entry is
// tied to one specific file on a stock install. Strong signatures come first
// in matchFile's preference, not in table order.
var fileSigs = []fileSig{
	// Root's passwd entry, plus a second entry, so one stray quoted line does
	// not count as a listing (see passwdSig).
	passwdSig(),
	// The Linux kernel banner from /proc/version. The build fields (the
	// builder's user@host and the gcc line) are what make it specific, since a
	// bare "Linux version 5.4" appears in ordinary status pages.
	regexSig("/proc/version", true, `Linux version \d+\.\d+\S* \([^\n]*\) \([^\n]*gcc[^\n]*\) #\d+`),
	// win.ini's comment header, which every default copy of the file has.
	substrSig("win.ini", true, "; for 16-bit app support"),
	// boot.ini needs both its section header and the multi() boot entry.
	substrSig("boot.ini", true, "[boot loader]", "multi(0)"),
	// The Windows hosts file's standard copyright header.
	substrSig("Windows hosts", true, "Copyright (c) 1993-2009 Microsoft Corp."),
	// /etc/hosts' localhost line is common in other text too, so this is weak.
	regexSig("/etc/hosts", false, `(?m)^\s*127\.0\.0\.1\s+localhost[^\n]*`),
	// An opening PHP tag. This is weak: a page that shows PHP code in a code
	// sample has it too. It matters for the php://filter module, which reads
	// a PHP file's source as base64.
	regexSig("PHP source", false, `<\?php\b`),
}

// base64Pattern picks out runs of base64 alphabet characters long enough to
// hold a small file. Shorter runs are mostly ordinary words and identifiers.
var base64Pattern = regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)

// firstSig returns the signature text matches, with the snippet it matched. A
// strong signature wins over a weak one wherever it sits in the table, and
// among signatures of one strength, table order decides. A signature the
// baseline also matches is skipped, so a page that already shows the file is
// not a finding.
func firstSig(text, baseline string) (fileSig, string, bool) {
	var weak fileSig
	var weakSnippet string
	foundWeak := false
	// Table order is the search order. The first strong match returns at once.
	for _, sig := range fileSigs {
		snippet, ok := sig.match(text)
		if !ok {
			continue
		}
		if _, inBaseline := sig.match(baseline); inBaseline {
			continue
		}
		if sig.strong {
			return sig, snippet, true
		}
		// Keep the first weak match, and go on looking for a strong one.
		if !foundWeak {
			weak, weakSnippet, foundWeak = sig, snippet, true
		}
	}
	return weak, weakSnippet, foundWeak
}

// matchFile reports whether text shows a file read that baseline did not show.
// It checks the plain text first. When decode is set it also checks each
// base64 blob, since php://filter returns the file encoded. A strong match
// from either is returned at once. Otherwise the first weak match wins, with
// the plain text checked before the decoded blobs.
func matchFile(text, baseline string, decode bool) (fileSig, string, bool) {
	sig, snippet, ok := firstSig(text, baseline)
	if ok && sig.strong {
		return sig, snippet, true
	}
	if decode {
		// Each candidate blob is decoded and checked the same way as plain text.
		for _, blob := range base64Pattern.FindAllString(text, -1) {
			// A blob that is not valid base64 is ordinary text, so it is skipped.
			decoded, dok := decodeBase64(blob)
			if !dok {
				continue
			}
			dsig, dsnip, dfound := firstSig(decoded, baseline)
			if !dfound {
				continue
			}
			if dsig.strong {
				return dsig, "base64-decoded: " + dsnip, true
			}
			// Keep the first weak decoded match, but a strong one further on still wins.
			if !ok {
				sig, snippet, ok = dsig, "base64-decoded: "+dsnip, true
			}
		}
	}
	return sig, snippet, ok
}

// decodeBase64 decodes a base64 blob, accepting it with or without padding.
// PHP's filter output is padded, but a blob copied from a rendered page may
// have lost its "=" characters.
func decodeBase64(blob string) (string, bool) {
	if raw, err := base64.StdEncoding.DecodeString(blob); err == nil {
		return string(raw), true
	}
	if raw, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(blob, "=")); err == nil {
		return string(raw), true
	}
	return "", false
}
