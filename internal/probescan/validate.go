package probescan

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"unicode"
)

// Structural validators. Each one parses a response the way the file's own
// format requires, so an HTML catch-all page, a login form, or a random
// string cannot satisfy them by accident. The old substring checks ("=",
// "{", "CREATE") matched nearly any web page; these do not.

// looksHTML reports whether a response is a web page rather than a file. A
// config or source file is never served as HTML, so an HTML body disqualifies
// every file-disclosure check.
func looksHTML(r *httpResult) bool {
	if strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "text/html") {
		return true
	}
	head := strings.ToLower(strings.TrimSpace(r.Text))
	if len(head) > 512 {
		head = head[:512]
	}
	return strings.HasPrefix(head, "<!doctype html") || strings.HasPrefix(head, "<html") || strings.Contains(head, "<head>")
}

// notHTML wraps a validator so it only passes for non-HTML bodies.
func notHTML(valid func(r *httpResult) bool) func(r *httpResult) bool {
	return func(r *httpResult) bool {
		return !looksHTML(r) && valid(r)
	}
}

// dotEnvLine matches one KEY=value line, optionally prefixed with "export".
var dotEnvLine = regexp.MustCompile(`^\s*(export\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*=`)

// validDotEnv requires most non-comment lines to be KEY=value assignments.
func validDotEnv(r *httpResult) bool {
	if looksHTML(r) {
		return false
	}
	matched, total := 0, 0
	for _, line := range strings.Split(r.Text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		total++
		if dotEnvLine.MatchString(line) {
			matched++
		}
	}
	return total > 0 && matched > 0 && float64(matched)/float64(total) >= 0.6
}

// validINIMatch returns a validator requiring a line matching pattern, for
// INI-style files such as .git/config or ~/.aws/credentials.
func validINIMatch(pattern string) func(r *httpResult) bool {
	re := regexp.MustCompile(`(?m)^\s*` + pattern + `\s*$`)
	return notHTML(func(r *httpResult) bool { return re.MatchString(r.Text) })
}

// validJSONAnyKey requires the body to parse as a JSON object containing at
// least one of keys at the top level. Files such as tsconfig.json and
// .eslintrc.json allow comments, which strict JSON rejects, so a body that
// fails to parse still passes when it is a braced object naming one of keys.
func validJSONAnyKey(keys ...string) func(r *httpResult) bool {
	return notHTML(func(r *httpResult) bool {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(r.Body, &obj); err == nil {
			for _, k := range keys {
				if _, ok := obj[k]; ok {
					return true
				}
			}
			return false
		}
		text := strings.TrimSpace(r.Text)
		if !strings.HasPrefix(text, "{") {
			return false
		}
		for _, k := range keys {
			if strings.Contains(text, `"`+k+`"`) {
				return true
			}
		}
		return false
	})
}

// validYAMLKey requires a top-level YAML key (a line starting with key:).
func validYAMLKey(key string) func(r *httpResult) bool {
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `\s*:`)
	return notHTML(func(r *httpResult) bool { return re.MatchString(r.Text) })
}

// validXMLRoot requires the first element of the document to be name, after
// an optional XML declaration and comments.
func validXMLRoot(name string) func(r *httpResult) bool {
	re := regexp.MustCompile(`(?s)^\s*(<\?xml[^>]*>\s*)?(<!--.*?-->\s*)*<` + regexp.QuoteMeta(name) + `[\s/>]`)
	return notHTML(func(r *httpResult) bool { return re.MatchString(r.Text) })
}

// validPHPSource requires raw PHP source, which means the interpreter did not
// run the file: the source is leaking.
func validPHPSource(r *httpResult) bool {
	return !looksHTML(r) && strings.Contains(r.Text, "<?php")
}

// validPEMPrivate requires a complete PEM private key block.
func validPEMPrivate(r *httpResult) bool {
	return !looksHTML(r) &&
		strings.Contains(r.Text, "-----BEGIN ") && strings.Contains(r.Text, " PRIVATE KEY-----") &&
		strings.Contains(r.Text, "-----END ")
}

// htpasswdLine matches a user entry with a recognized password hash scheme.
var htpasswdLine = regexp.MustCompile(`^[^:\s]+:(\$apr1\$|\$2[abxy]\$|\{SHA\}|\$1\$|\$5\$|\$6\$)`)

// validHtpasswd requires every non-empty line to be user:hash with a known scheme.
func validHtpasswd(r *httpResult) bool {
	if looksHTML(r) {
		return false
	}
	matched, total := 0, 0
	for _, line := range strings.Split(strings.TrimSpace(r.Text), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		total++
		if htpasswdLine.MatchString(line) {
			matched++
		}
	}
	return total > 0 && matched == total
}

// validZip requires a zip local-file header and an end-of-central-directory
// record, which together identify an archive rather than an arbitrary blob.
func validZip(r *httpResult) bool {
	return bytes.HasPrefix(r.Body, []byte("PK\x03\x04")) && bytes.Contains(r.Body, []byte("PK\x05\x06"))
}

// validTarGz decompresses the first block and checks for the ustar magic.
func validTarGz(r *httpResult) bool {
	if !bytes.HasPrefix(r.Body, []byte{0x1f, 0x8b}) {
		return false
	}
	zr, err := gzip.NewReader(bytes.NewReader(r.Body))
	if err != nil {
		return false
	}
	defer zr.Close()
	block := make([]byte, 512)
	if _, err := io.ReadFull(zr, block); err != nil {
		return false
	}
	return bytes.Equal(block[257:262], []byte("ustar"))
}

// validDSStore checks the Apple Finder .DS_Store magic: a 1 at offset 0 and
// the "Bud1" signature at offset 4.
func validDSStore(r *httpResult) bool {
	return len(r.Body) >= 8 && bytes.Equal(r.Body[0:4], []byte{0, 0, 0, 1}) && bytes.Equal(r.Body[4:8], []byte("Bud1"))
}

// validSQLiteDB checks the SQLite file header.
func validSQLiteDB(r *httpResult) bool {
	return bytes.HasPrefix(r.Body, []byte("SQLite format 3\x00"))
}

// sqlDumpPattern matches statements and headers that only real database dumps contain.
var sqlDumpPattern = regexp.MustCompile(`(?im)^\s*(INSERT\s+INTO|CREATE\s+TABLE|DROP\s+TABLE|CREATE\s+DATABASE|-- MySQL dump|PostgreSQL database dump)`)

// validSQLDump requires dump statements at the start of lines.
func validSQLDump(r *httpResult) bool {
	return !looksHTML(r) && sqlDumpPattern.MatchString(r.Text)
}

// requirementLine matches one pip requirement: a name, optional extras, and
// an optional version specifier.
var requirementLine = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._\-]*(\[[^\]]*\])?\s*((==|>=|<=|~=|!=|>|<)[^\s;#]+)?\s*(#.*)?$`)

// validRequirements requires every non-comment line to be a requirement.
func validRequirements(r *httpResult) bool {
	if looksHTML(r) {
		return false
	}
	matched, total := 0, 0
	for _, line := range strings.Split(r.Text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		total++
		if requirementLine.MatchString(line) {
			matched++
		}
	}
	return total > 0 && matched == total
}

// validGemfile requires a source or gem declaration line.
func validGemfile(r *httpResult) bool {
	re := regexp.MustCompile(`(?m)^\s*(source|gem)\s+['"]`)
	return notHTML(func(r *httpResult) bool { return re.MatchString(r.Text) })(r)
}

// validGitHEAD requires a symbolic ref or a bare commit hash.
func validGitHEAD(r *httpResult) bool {
	t := strings.TrimSpace(r.Text)
	if looksHTML(r) {
		return false
	}
	if strings.HasPrefix(t, "ref: refs/") {
		return true
	}
	return len(t) == 40 && isHex(t)
}

// isHex reports whether s is entirely lowercase or uppercase hex digits.
func isHex(s string) bool {
	for _, r := range s {
		if !unicode.Is(unicode.ASCII_Hex_Digit, r) {
			return false
		}
	}
	return s != ""
}

// validPlainText is the weakest structural check: a non-HTML text body with no
// binary bytes. It cannot confirm what the file is, so findings that use it
// are reported with confidence "likely", never "confirmed".
func validPlainText(r *httpResult) bool {
	if looksHTML(r) || len(r.Body) == 0 {
		return false
	}
	sample := r.Body
	if len(sample) > 512 {
		sample = sample[:512]
	}
	if bytes.IndexByte(sample, 0) >= 0 {
		return false
	}
	printable := 0
	for _, b := range sample {
		if b == '\n' || b == '\r' || b == '\t' || (b >= 0x20 && b < 0x7f) || b >= 0x80 {
			printable++
		}
	}
	return float64(printable)/float64(len(sample)) >= 0.95
}

// jsonObject parses the body as one JSON object and returns its top-level
// members. It reports false for HTML, for text that is not JSON, and for a JSON
// value that is not an object.
func jsonObject(r *httpResult) (map[string]json.RawMessage, bool) {
	if looksHTML(r) {
		return nil, false
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(r.Body, &obj); err != nil || obj == nil {
		return nil, false
	}
	return obj, true
}

// validJSONKeys requires a JSON object with at least one of keys at its top
// level. Unlike validJSONAnyKey it accepts no unparseable text, so an HTML page
// or a script that merely contains a brace cannot pass.
func validJSONKeys(keys ...string) func(r *httpResult) bool {
	return func(r *httpResult) bool {
		obj, ok := jsonObject(r)
		if !ok {
			return false
		}
		// Any one matching member is enough to identify the document.
		for _, k := range keys {
			if _, found := obj[k]; found {
				return true
			}
		}
		return false
	}
}

// validJSONBody requires a well-formed JSON document that is not an HTML page.
// It is for endpoints whose only contract is that they answer with JSON.
func validJSONBody(r *httpResult) bool {
	return !looksHTML(r) && json.Valid(r.Body)
}

// validJSONArrayHasKey requires a JSON array of objects, at least one of which
// has key. It is the shape of WordPress's REST user list.
func validJSONArrayHasKey(key string) func(r *httpResult) bool {
	return func(r *httpResult) bool {
		if looksHTML(r) {
			return false
		}
		var items []map[string]json.RawMessage
		if err := json.Unmarshal(r.Body, &items); err != nil {
			return false
		}
		// Scan the items for the key; one object carrying it identifies the list.
		for _, item := range items {
			if _, found := item[key]; found {
				return true
			}
		}
		return false
	}
}

// validHealthBody accepts the two health-check shapes in common use: a JSON
// object with a "status" member, or a bare status word such as "ok". A plain
// substring check on "ok" would match nearly any page.
func validHealthBody(r *httpResult) bool {
	if looksHTML(r) {
		return false
	}
	if obj, ok := jsonObject(r); ok {
		_, found := obj["status"]
		return found
	}
	switch strings.ToLower(strings.TrimSpace(r.Text)) {
	case "ok", "healthy", "up", "pass":
		return true
	}
	return false
}

// validRegexp requires a body that is not HTML and matches re.
func validRegexp(re *regexp.Regexp) func(r *httpResult) bool {
	return notHTML(func(r *httpResult) bool { return re.MatchString(r.Text) })
}

// matchesRegexp requires the body to match re. Unlike validRegexp it does not
// reject HTML, for checks whose target is itself a web page, such as phpinfo.
func matchesRegexp(re *regexp.Regexp) func(r *httpResult) bool {
	return func(r *httpResult) bool { return re.MatchString(r.Text) }
}

// containsCaseAll requires every substring to appear, case-sensitively. It is
// the AND form of containsCase.
func containsCaseAll(subs ...string) func(r *httpResult) bool {
	return func(r *httpResult) bool {
		for _, s := range subs {
			if !strings.Contains(r.Text, s) {
				return false
			}
		}
		return true
	}
}

// phpSourceWith requires raw PHP source that contains every given substring. A
// configuration file served as source leaks what the interpreter would hide.
func phpSourceWith(subs ...string) func(r *httpResult) bool {
	all := containsCaseAll(subs...)
	return func(r *httpResult) bool {
		return validPHPSource(r) && all(r)
	}
}

// validDjangoSettings requires raw Python that defines a Django settings module:
// a SECRET_KEY together with INSTALLED_APPS or DATABASES.
func validDjangoSettings(r *httpResult) bool {
	return !looksHTML(r) && containsCaseAll("SECRET_KEY")(r) &&
		(containsCaseAll("INSTALLED_APPS")(r) || containsCaseAll("DATABASES")(r))
}

// validRailsMasterKey requires a body that is exactly one 32-character hex
// string, the format of Rails' config/master.key.
func validRailsMasterKey(r *httpResult) bool {
	return !looksHTML(r) && railsMasterKeyLine.MatchString(strings.TrimSpace(r.Text))
}

// Line-anchored formats for files whose identity is one repeated line or shape.
var (
	// railsMasterKeyLine is the single hex line Rails keeps in config/master.key.
	railsMasterKeyLine = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
	// railsSecretsYAML matches a Rails secrets.yml: an environment key at the top
	// level with a nested secret_key_base beneath it.
	railsSecretsYAML = regexp.MustCompile(`(?ms)^(development|production|test):.*^\s+secret_key_base\s*:`)
	// htaccessDirective matches a line that only Apache configuration uses.
	htaccessDirective = regexp.MustCompile(`(?im)^\s*(RewriteEngine|RewriteRule|Options|AuthType|AuthUserFile|Require\s|Deny from|php_value|php_flag|SetEnv)`)
	// netrcMachine matches a .netrc entry, which always names a machine.
	netrcMachine = regexp.MustCompile(`(?im)^\s*machine\s+\S+`)
	// gitCredentialsLine matches a .git-credentials line: scheme, user, password, host.
	gitCredentialsLine = regexp.MustCompile(`(?m)^https?://[^:\s/]+:[^@\s]+@`)
	// npmrcAuthLine matches a .npmrc auth setting, scoped to a registry host.
	npmrcAuthLine = regexp.MustCompile(`(?m)^(//[^\s=]+:_authToken\s*=|_auth\s*=|//[^\s=]+:_password\s*=)`)
	// pgpassLine matches a .pgpass entry: host:port:database:user:password.
	pgpassLine = regexp.MustCompile(`(?m)^[^:\s#]*:[^:\s]*:[^:\s]*:[^:\s]*:\S+\s*$`)
	// laravelLogLine matches one Laravel/Monolog log record.
	laravelLogLine = regexp.MustCompile(`(?m)^\[\d{4}-\d{2}-\d{2}[ T][^\]]*\] \S+\.(ERROR|WARNING|INFO|DEBUG|CRITICAL|NOTICE|ALERT|EMERGENCY):`)
	// phpErrorLogLine matches one PHP error-log record, the form WordPress's
	// debug.log and a server's error_log both use.
	phpErrorLogLine = regexp.MustCompile(`(?m)^\[[^\]]+\] PHP (Warning|Notice|Fatal error|Deprecated|Parse error):`)
	// phpInfoMarker matches the title or the version line of a phpinfo() page.
	phpInfoMarker = regexp.MustCompile(`(?i)<title>phpinfo\(\)</title>|PHP Version\s+\d+\.\d+`)
	// cvsRootLine matches CVS/Root, which holds one CVSROOT such as :pserver:.
	cvsRootLine = regexp.MustCompile(`(?m)^:(pserver|ext|local|gserver|kserver|fork):`)
	// cvsEntriesLine matches a CVS/Entries record: /name/revision/date/.
	cvsEntriesLine = regexp.MustCompile(`(?m)^/[^/\n]+/[^/\n]*/`)
	// hgRequiresLine matches a Mercurial .hg/requires feature name.
	hgRequiresLine = regexp.MustCompile(`(?m)^(revlogv1|store|fncache|dotencode|generaldelta|sparserevlog|dirstate-v2|shared|treemanifest)\s*$`)
	// gitSHALine matches a line holding one full object hash.
	gitSHALine = regexp.MustCompile(`(?m)^[0-9a-f]{40}\s*$`)
	// gitInfoRefLine matches a .git/info/refs line: a hash followed by a ref name.
	gitInfoRefLine = regexp.MustCompile(`(?m)^[0-9a-f]{40}\s+refs/`)
	// gitFetchHeadLine matches a .git/FETCH_HEAD line: a hash, then a tab.
	gitFetchHeadLine = regexp.MustCompile(`(?m)^[0-9a-f]{40}\t`)
	// robotsDirective matches a robots.txt directive line.
	robotsDirective = regexp.MustCompile(`(?im)^\s*(user-agent|disallow|allow|sitemap|crawl-delay)\s*:`)
	// securityTxtContact matches the required Contact field of security.txt.
	securityTxtContact = regexp.MustCompile(`(?im)^\s*contact\s*:`)
	// versionStringLine matches a file whose whole content is one version number.
	versionStringLine = regexp.MustCompile(`^\s*[vV]?\d+(\.\d+)+([-+][0-9A-Za-z.\-]+)?\s*$`)
	// gradleBuildLine matches a Gradle build statement.
	gradleBuildLine = regexp.MustCompile(`(?m)^\s*(apply plugin:|plugins\s*\{|dependencies\s*\{|repositories\s*\{)`)
	// jenkinsfileLine matches a declarative or scripted Jenkins pipeline.
	jenkinsfileLine = regexp.MustCompile(`(?m)^\s*(pipeline\s*\{|node\s*(\(|\{))`)
	// webpackExport matches the CommonJS export that a webpack config uses.
	webpackExport = regexp.MustCompile(`module\.exports\s*=\s*[{(]`)
	// viteExport matches the default export of a Vite config.
	viteExport = regexp.MustCompile(`export default\s*(defineConfig\s*\()?\s*\{`)
	// podfileLine matches a CocoaPods platform or target declaration.
	podfileLine = regexp.MustCompile(`(?m)^\s*(platform|target)\s+[:'"]`)
	// setupPyLine matches the setuptools import that opens a setup.py.
	setupPyLine = regexp.MustCompile(`(?m)^\s*(from setuptools import|import setuptools)`)
)

// maskEvidence shortens and redacts a snippet before it is stored. Values after
// "=" or ":" are replaced so a finding never persists a live credential, and
// PEM key bodies are dropped entirely.
func maskEvidence(s string) string {
	if i := strings.Index(s, "-----BEGIN "); i >= 0 {
		s = s[:i] + "[private key material redacted]"
	}
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if idx := strings.IndexAny(line, "=:"); idx > 0 && strings.TrimSpace(line[:idx]) != "" && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			lines[i] = line[:idx+1] + " ••••••"
		}
	}
	out := strings.Join(lines, "\n")
	if len(out) > 240 {
		out = out[:240] + "…"
	}
	return strings.TrimSpace(out)
}
