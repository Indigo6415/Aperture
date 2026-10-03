package secretscan

import "regexp"

// This file ports the regex library from SecretFinder
// (github.com/m4ll0k/SecretFinder), a Python tool that scans JS for exposed
// keys/tokens. It's kept as a separate, opt-in pattern set (see
// Request.SecretFinderEngine) rather than merged into Patterns above,
// because it's deliberately looser than this package's own "core" set --
// missing \b word boundaries, broad character classes, a bare-UUID
// "Heroku API key" match -- exactly the shape of pattern patterns.go's own
// doc comment says core leaves out to avoid burying real findings in false
// positives. Running it is a trade: more false positives, but a real chance
// of catching something core's tighter patterns miss. A few upstream
// patterns are corrected here rather than ported byte-for-byte (see inline
// notes) where the original regex has an escaping/typo bug that makes it
// never match real data -- porting a known-dead pattern wouldn't serve the
// "more coverage" goal this engine exists for.

// mpSF ("make pattern, SecretFinder") mirrors mp but tags the pattern with
// Engine "secretfinder" and wraps it case-insensitive, matching upstream
// SecretFinder's own compile flags (re.VERBOSE | re.I) -- every one of its
// patterns is matched case-insensitively, not just the ones core happens to
// mark (?i) individually.
func mpSF(name, pattern string) Pattern {
	return Pattern{Name: name, Regex: regexp.MustCompile("(?i)" + pattern), Engine: "secretfinder"}
}

// SecretFinderPatterns is the additional, noisier pattern library --
// enabled per-scan via Request.SecretFinderEngine, run alongside (not
// instead of) Patterns.
var SecretFinderPatterns = []Pattern{
	mpSF("AWS Access/Session Key ID", `A[SK]IA[0-9A-Z]{16}`),
	mpSF("Amazon MWS Auth Token", `amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
	mpSF("AWS S3 URL", `s3\.amazonaws\.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws\.com`),
	mpSF("AWS S3 URL (extended)", `[a-zA-Z0-9-._]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9-._]+|s3-[a-zA-Z0-9-._/]+|s3\.amazonaws\.com/[a-zA-Z0-9-._]+|s3\.console\.aws\.amazon\.com/s3/buckets/[a-zA-Z0-9-._]+`),
	mpSF("Facebook Access Token", `EAACEdEose0cBA[0-9A-Za-z]+`),
	mpSF("Google API Key", `AIza[0-9A-Za-z_\-]{35}`),
	mpSF("Google reCAPTCHA Key", `6L[0-9A-Za-z_\-]{38}|^6[0-9a-zA-Z_\-]{39}$`),
	mpSF("Google OAuth Access Token", `ya29\.[0-9A-Za-z\-_]+`),
	mpSF("Firebase Cloud Messaging Key", `AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}`),
	mpSF("Authorization: Basic Header", `basic [a-zA-Z0-9=:_+/\-]{5,100}`),
	mpSF("Authorization: Bearer Header", `bearer [a-zA-Z0-9_\-.=:+/]{5,100}`),
	// Faithful to upstream's own char class (a bracket expression, not
	// alternation -- "key|_key|\s+" is parsed as the set of characters
	// {k,e,y,|,_,whitespace,+}), which is exactly why it's a broad net.
	mpSF("Generic API Key Reference", `api[key|_\s+]+[a-zA-Z0-9_\-]{5,100}`),
	mpSF("Mailgun API Key", `key-[0-9a-zA-Z]{32}`),
	mpSF("Twilio API Key SID", `SK[0-9a-fA-F]{32}`),
	mpSF("Twilio Account SID", `AC[a-zA-Z0-9_\-]{32}`),
	mpSF("Twilio App SID", `AP[a-zA-Z0-9_\-]{32}`),
	mpSF("PayPal Braintree Access Token", `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`),
	mpSF("Square OAuth Secret", `sq0csp-[0-9A-Za-z\-_ ]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}`),
	// Upstream's own pattern is "sqOatp-..." (letter O, not the digit 0) --
	// a typo that keeps it from ever matching a real Square token. Corrected
	// here to the actual "sq0atp-" prefix.
	mpSF("Square Access Token", `sq0atp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}`),
	mpSF("Stripe Live Secret Key", `sk_live_[0-9a-zA-Z]{24}`),
	mpSF("Stripe Restricted Key", `rk_live_[0-9a-zA-Z]{24}`),
	mpSF("GitHub Credentials in URL", `[a-zA-Z0-9_\-]*:[a-zA-Z0-9_\-]+@github\.com`),
	mpSF("PGP Private Key Block", `-----BEGIN PGP PRIVATE KEY BLOCK-----`),
	mpSF("Slack API Token (JSON field)", `"api_token":"(xox[a-zA-Z]-[a-zA-Z0-9\-]+)"`),
	mpSF("Private Key Block (full)", `-----BEGIN [^\s]+ PRIVATE KEY-----[\s]*[^-]*-----END [^\s]+ PRIVATE KEY-----`),
	// Bare UUID shape -- upstream's noisiest pattern by far (matches
	// request IDs, analytics/session IDs, anything UUID-shaped, not just
	// Heroku keys). Kept for fidelity/coverage since that's this engine's
	// whole purpose, but treat hits as "worth a manual look", not confirmed.
	mpSF("Possible Heroku API Key (UUID format)", `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`),
	mpSF("Possible Hardcoded Password", "password\\s*[`=:\"]+\\s*\\S+|password is\\s*[`=:\"]*\\s*\\S+|pwd\\s*[`=:\"]*\\s*\\S+|passwd\\s*[`=:\"]+\\s*\\S+"),
}
