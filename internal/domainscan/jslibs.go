package domainscan

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// jsBannerWindow is how much of a script is searched for a version banner.
// Banners sit at the top of a file. Bounding the search keeps a large bundle
// from matching a version-like string that appears only deep inside other code.
const jsBannerWindow = 8 << 10

// jsAdvisory is one known-vulnerable range of a library: every version below
// below is affected, optionally limited to one major branch.
type jsAdvisory struct {
	// branch limits the advisory to one major version. Zero means every major.
	branch int
	// below is the first fixed version.
	below    string
	cves     []string
	severity string
	summary  string
}

// jsLibrary is one library the module can recognize and version. bannerRe
// reads the version from the top of the script; fileRe reads it from the file
// name when the banner is absent. requireText, when set, must appear in the
// head of the script before bannerRe is trusted, for libraries whose version
// is only one assignment among much other code.
type jsLibrary struct {
	name        string
	bannerRe    *regexp.Regexp
	fileRe      *regexp.Regexp
	requireText string
	advisories  []jsAdvisory
}

// jsLibraries is the signature table. Each advisory is a published fix for a
// named CVE, and a version is flagged only when it is strictly below the fix.
// Libraries whose versions carry no advisory are left out, so a finding always
// names a known problem rather than just a library's presence.
var jsLibraries = []jsLibrary{
	{
		name:     "jQuery",
		bannerRe: regexp.MustCompile(`jQuery(?: JavaScript Library)? v(\d+\.\d+\.\d+)`),
		fileRe:   regexp.MustCompile(`jquery[-.](\d+\.\d+\.\d+)`),
		advisories: []jsAdvisory{
			{below: "3.5.0", cves: []string{"CVE-2020-11022", "CVE-2020-11023"}, severity: "medium", summary: "jQuery XSS when passing HTML from untrusted sources to DOM manipulation methods"},
			{below: "1.9.0", cves: []string{"CVE-2012-6708"}, severity: "medium", summary: "jQuery XSS through selector handling"},
		},
	},
	{
		name:     "jQuery UI",
		bannerRe: regexp.MustCompile(`jQuery UI - v(\d+\.\d+\.\d+)`),
		fileRe:   regexp.MustCompile(`jquery-ui[-.](\d+\.\d+\.\d+)`),
		advisories: []jsAdvisory{
			{below: "1.13.0", cves: []string{"CVE-2021-41182", "CVE-2021-41183", "CVE-2021-41184"}, severity: "medium", summary: "jQuery UI XSS through position and datepicker options"},
		},
	},
	{
		name:     "Bootstrap",
		bannerRe: regexp.MustCompile(`Bootstrap v(\d+\.\d+\.\d+)`),
		fileRe:   regexp.MustCompile(`bootstrap[-.](\d+\.\d+\.\d+)`),
		advisories: []jsAdvisory{
			{branch: 3, below: "3.4.1", cves: []string{"CVE-2019-8331"}, severity: "medium", summary: "Bootstrap XSS through the tooltip and popover data-template attribute"},
			{branch: 4, below: "4.3.1", cves: []string{"CVE-2019-8331"}, severity: "medium", summary: "Bootstrap XSS through the tooltip and popover data-template attribute"},
		},
	},
	{
		// Lodash builds carry no banner version; the version is the VERSION
		// assignment, which is only trusted in a file that names lodash.
		name:        "Lodash",
		bannerRe:    regexp.MustCompile(`VERSION\s*=\s*["'](\d+\.\d+\.\d+)["']`),
		fileRe:      regexp.MustCompile(`lodash(?:\.min)?[-.](\d+\.\d+\.\d+)`),
		requireText: "lodash",
		advisories: []jsAdvisory{
			{below: "4.17.21", cves: []string{"CVE-2021-23337"}, severity: "high", summary: "Lodash command injection through the template function"},
			{below: "4.17.19", cves: []string{"CVE-2020-8203"}, severity: "high", summary: "Lodash prototype pollution in zipObjectDeep"},
		},
	},
	{
		name:     "Moment.js",
		bannerRe: regexp.MustCompile(`//! version : (\d+\.\d+\.\d+)`),
		fileRe:   regexp.MustCompile(`moment[-.](\d+\.\d+\.\d+)`),
		advisories: []jsAdvisory{
			{below: "2.29.4", cves: []string{"CVE-2022-24785"}, severity: "high", summary: "Moment.js path traversal through locale loading"},
			{below: "2.29.4", cves: []string{"CVE-2022-31129"}, severity: "high", summary: "Moment.js regular expression denial of service in date string parsing"},
		},
	},
	{
		name:     "Underscore",
		bannerRe: regexp.MustCompile(`Underscore\.js (\d+\.\d+\.\d+)`),
		fileRe:   regexp.MustCompile(`underscore[-.](\d+\.\d+\.\d+)`),
		advisories: []jsAdvisory{
			{below: "1.12.1", cves: []string{"CVE-2021-23358"}, severity: "high", summary: "Underscore arbitrary code execution through the template function"},
		},
	},
	{
		name:     "axios",
		bannerRe: regexp.MustCompile(`[Aa]xios v(\d+\.\d+\.\d+)`),
		fileRe:   regexp.MustCompile(`axios[-.](\d+\.\d+\.\d+)`),
		advisories: []jsAdvisory{
			{below: "0.21.2", cves: []string{"CVE-2021-3749"}, severity: "high", summary: "axios regular expression denial of service in the trim handling"},
		},
	},
	{
		name:     "DOMPurify",
		bannerRe: regexp.MustCompile(`DOMPurify (\d+\.\d+\.\d+)`),
		fileRe:   regexp.MustCompile(`purify[-.](\d+\.\d+\.\d+)`),
		advisories: []jsAdvisory{
			{below: "2.0.17", cves: []string{"CVE-2020-26870"}, severity: "medium", summary: "DOMPurify mutation XSS that bypasses sanitization"},
		},
	},
}

// splitVersion parses a dotted version into its first three numeric parts,
// with missing parts as zero.
func splitVersion(v string) [3]int {
	var out [3]int
	for i, part := range strings.SplitN(v, ".", 3) {
		n, _ := strconv.Atoi(part)
		out[i] = n
	}
	return out
}

// compareVersions returns -1, 0, or 1 as a is below, equal to, or above b.
func compareVersions(a, b string) int {
	pa, pb := splitVersion(a), splitVersion(b)
	// Compare the parts from major to patch and stop at the first difference.
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// detectLibraryVersion returns the version a script declares for lib. The
// banner is tried first, since it is the library's own statement of version,
// and the file name is the fallback for minified builds that drop the banner.
func detectLibraryVersion(lib jsLibrary, sf scriptFile) (string, bool) {
	head := sf.Body
	if len(head) > jsBannerWindow {
		head = head[:jsBannerWindow]
	}
	text := string(head)
	// The banner is trusted only when the library's own marker is present, if the library has one.
	if lib.bannerRe != nil && (lib.requireText == "" || strings.Contains(strings.ToLower(text), lib.requireText)) {
		if m := lib.bannerRe.FindStringSubmatch(text); m != nil {
			return m[1], true
		}
	}
	if lib.fileRe != nil {
		if m := lib.fileRe.FindStringSubmatch(sf.URL); m != nil {
			return m[1], true
		}
	}
	return "", false
}

// affectedAdvisories returns the advisories that apply to version of lib.
func affectedAdvisories(lib jsLibrary, version string) []jsAdvisory {
	major := splitVersion(version)[0]
	var out []jsAdvisory
	for _, a := range lib.advisories {
		// A branch-limited advisory applies only to its own major version.
		if a.branch != 0 && a.branch != major {
			continue
		}
		if compareVersions(version, a.below) < 0 {
			out = append(out, a)
		}
	}
	return out
}

// libraryFindings reports every known-vulnerable library version declared by
// one downloaded script. The finding names the script that carries the
// version, so an operator can see which file to replace.
func libraryFindings(sf scriptFile) []Finding {
	var findings []Finding
	for _, lib := range jsLibraries {
		version, ok := detectLibraryVersion(lib, sf)
		if !ok {
			continue
		}
		advisories := affectedAdvisories(lib, version)
		if len(advisories) == 0 {
			continue
		}
		// The finding's severity is the worst of its advisories, and its detail
		// lists each advisory with the version that fixes it.
		severity := "info"
		var detail []string
		for _, a := range advisories {
			severity = maxSeverity(severity, a.severity)
			detail = append(detail, fmt.Sprintf("%s (fixed in %s): %s", strings.Join(a.cves, ", "), a.below, a.summary))
		}
		findings = append(findings, Finding{
			Label:    fmt.Sprintf("%s %s has known vulnerabilities", lib.name, version),
			URL:      sf.URL,
			Detail:   strings.Join(detail, "; "),
			Evidence: lib.name + "@" + version,
			Severity: severity,
		})
	}
	return findings
}

// registerJSLibraries adds the library module to the registry. It is called
// from an init so the module is registered the same way retire.go registers its own.
func init() {
	registeredModules = append(registeredModules, jsLibrariesModuleDef)
}

// jsLibrariesModuleDef identifies the JavaScript libraries served by the domain
// and flags the versions that carry a published advisory. It runs in-process,
// so it works where retire.js is not installed, and it reads the same crawl the
// retire module does.
var jsLibrariesModuleDef = moduleDef{
	id:   "js_libraries",
	name: "JavaScript library versions (known advisories)",
	run:  runJSLibrariesModule,
}

// runJSLibrariesModule checks every script in the shared crawl against the
// library table. A scan with no scripts reports no findings and no error.
func runJSLibrariesModule(ctx context.Context, t *Target, opts Options) ([]Finding, error) {
	crawl := sharedCrawl(ctx, t, opts)
	findings := []Finding{}
	for _, sf := range crawl.Scripts {
		findings = append(findings, libraryFindings(sf)...)
	}
	return findings, nil
}
