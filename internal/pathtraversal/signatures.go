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

// fileSigs is the set of file contents that count as a read. Each entry is
// tied to one specific file on a stock install.
var fileSigs = []fileSig{
	// Root's passwd entry: "name:password:uid:gid:gecos:home:shell". UID 0
	// and GID 0 make this line specific.
	regexSig("/etc/passwd", true, `(?m)^root:[^:\n]*:0:0:[^\n]*`),
	// The Linux kernel banner from /proc/version.
	regexSig("/proc/version", true, `Linux version \d+\.\d+[^\n]*`),
	// win.ini's comment header, which every default copy of the file has.
	substrSig("win.ini", true, "; for 16-bit app support"),
	// boot.ini needs both its section header and the multi() boot entry.
	substrSig("boot.ini", true, "[boot loader]", "multi(0)"),
	// The Windows hosts file's standard copyright header.
	substrSig("Windows hosts", true, "Copyright (c) 1993-2009 Microsoft Corp."),
	// /etc/hosts' localhost line is common in other text too, so this is weak.
	regexSig("/etc/hosts", false, `(?m)^\s*127\.0\.0\.1\s+localhost[^\n]*`),
}

// base64Pattern picks out runs of base64 alphabet characters long enough to
// hold a small file. Shorter runs are mostly ordinary words and identifiers.
var base64Pattern = regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)

// matchFile returns the first signature that text matches, in table order,
// together with the matched snippet. A signature the baseline also matches
// is skipped, so a page that already shows the file is not a finding.
func matchFile(text, baseline string, decode bool) (fileSig, string, bool) {
	for _, sig := range fileSigs {
		snippet, ok := sig.match(text)
		if !ok {
			continue
		}
		if _, inBaseline := sig.match(baseline); inBaseline {
			continue
		}
		return sig, snippet, true
	}
	if !decode {
		return fileSig{}, "", false
	}
	// Look for a file inside base64 blobs. Each candidate is decoded and
	// checked the same way as plain text.
	for _, blob := range base64Pattern.FindAllString(text, -1) {
		decoded, ok := decodeBase64(blob)
		if !ok {
			continue
		}
		for _, sig := range fileSigs {
			snippet, ok := sig.match(decoded)
			if !ok {
				continue
			}
			if _, inBaseline := sig.match(baseline); inBaseline {
				continue
			}
			return sig, "base64-decoded: " + snippet, true
		}
	}
	return fileSig{}, "", false
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
