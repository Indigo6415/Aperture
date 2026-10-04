package paramminer

// Wordlist is the built-in set of parameter names mining tries. It favors the
// names that injection scanners act on: fetch targets, redirect destinations,
// file and template selectors, and the debug and switch parameters that
// often gate a second code path. It is not exhaustive. Each name costs
// roughly one share of a chunked probe, so the list stays a few hundred
// entries rather than a full dictionary.
var Wordlist = []string{
	// Fetch and navigation targets (SSRF, open redirect).
	"url", "uri", "link", "href", "src", "source", "target", "dest", "destination", "redirect",
	"redirect_uri", "redirect_url", "return", "return_url", "returnTo", "return_to", "next", "next_url",
	"continue", "goto", "to", "out", "view", "forward", "forward_url", "callback", "callback_url",
	"webhook", "endpoint", "host", "domain", "site", "origin", "ref", "referer", "referrer", "feed",
	"proxy", "fetch", "load", "import", "remote", "resource", "preview", "image", "img", "avatar",
	"file_url", "image_url", "img_url", "download", "download_url", "api", "api_url", "server",
	// File and path selectors (path traversal, LFI).
	"file", "filename", "filepath", "path", "dir", "folder", "document", "doc", "page", "template",
	"tpl", "include", "inc", "module", "lang", "language", "locale", "theme", "style", "layout",
	"read", "open", "data", "content", "name", "key", "attachment", "upload", "export", "report",
	// Templated and rendered content (SSTI, XSS reflection).
	"input", "text", "message", "msg", "title", "subject", "body", "comment", "q", "query", "search",
	"s", "keyword", "term", "value", "val", "v", "param", "field", "output", "format", "render",
	"view_name", "tag", "label", "error", "err", "note", "description",
	// Identifiers and selectors that routinely gate a second code path.
	"id", "user_id", "userId", "uid", "account", "account_id", "org_id", "tenant", "item", "itemId",
	"object", "obj", "ticket", "order", "invoice", "doc_id", "file_id", "post_id", "project",
	"type", "kind", "mode", "action", "cmd", "command", "op", "operation", "method", "task", "job",
	"service", "module_name", "plugin", "tool", "engine", "driver", "backend", "handler",
	// Switches and debug parameters.
	"debug", "test", "dev", "admin", "verbose", "trace", "raw", "pretty", "callback_name", "jsonp",
	"format_type", "preview_mode", "beta", "feature", "flag", "enable", "disable", "force", "skip",
	"bypass", "internal", "private", "override", "config", "settings", "option", "options",
	// Pagination and filtering (rarely injectable, but often hidden query inputs).
	"page_size", "per_page", "limit", "offset", "cursor", "sort", "order", "filter", "fields",
	"include", "expand", "select", "where", "status", "state", "role", "scope", "version", "v1",
	// Auth and session carriers.
	"token", "access_token", "auth", "session", "sid", "email", "username", "user", "login", "password",
	"code", "state_token", "nonce", "lang_code",
}
