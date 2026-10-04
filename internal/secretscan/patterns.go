// Package secretscan implements Aperture's Go/tsx port of Snitch
// (github.com/indigo/Snitch, the standalone Python secret-scraper): crawl a
// URL, follow its same-origin scripts/links, and regex/entropy-scan every
// response body for recognizable API keys, tokens, and credentials.
package secretscan

import "regexp"

// Pattern is one named regex for a recognizable secret/credential format.
type Pattern struct {
	Name  string
	Regex *regexp.Regexp
	// Engine identifies which pattern library this entry came from -- "core"
	// for this file's own conservative set, "secretfinder" for the
	// SecretFinderPatterns ported in patterns_secretfinder.go. Carried
	// through to Match.Engine so the UI can badge which engine flagged a
	// given result.
	Engine string
	// Public marks keys that are designed to ship in client-side code
	// (publishable payment keys, browser map keys). They are reported at
	// informational level, not as leaked secrets.
	Public bool
	// Validate, when set, must accept the matched secret value (the regex's
	// last capture group, or the whole match when it has none) before the
	// hit is kept. It rejects shapes the regex cannot exclude on its own,
	// such as a bare English word in a keyword-anchored pattern. Nil means
	// the regex alone decides.
	Validate func(value string) bool
}

// mp ("make pattern") panics on an invalid regex -- every entry below is a
// compile-time constant, so a typo is a bug to catch immediately, not a
// runtime error to handle.
func mp(name, pattern string) Pattern {
	return Pattern{Name: name, Regex: regexp.MustCompile(pattern), Engine: "core"}
}

// mpPublic is mp for a key format that is public by design.
func mpPublic(name, pattern string) Pattern {
	p := mp(name, pattern)
	p.Public = true
	return p
}

// mpValid is mp with a validator attached. Use it when the regex's shape is
// common enough that a second check is needed to separate real values from
// words or other look-alikes.
func mpValid(name, pattern string, validate func(string) bool) Pattern {
	p := mp(name, pattern)
	p.Validate = validate
	return p
}

// Patterns is the full library scanText matches every page/script against.
// It's a superset of Snitch's own regex_patterns.py plus
// internal/probescan/secrets.go's list, extended with more services --
// deliberately kept to high-signal, specific key/token *shapes* (fixed
// prefixes, fixed lengths) rather than broad "anything after a word like
// 'key'" matches, which is exactly the class of pattern both of those
// predecessors comment out for burying real findings in false positives
// from minified JS. Bare hex/base64 hash patterns (MD5/SHA-*) are likewise
// deliberately omitted for the same reason. Where a regex is keyword-anchored
// or loose, a Validate function rejects the look-alikes it would otherwise keep.
var Patterns = []Pattern{
	// --- AWS ---
	mp("AWS Access Key ID", `\bAKIA[0-9A-Z]{16}\b`),
	mpValid("AWS Secret Access Key", `(?i)aws_secret_access_key["']?\s*[:=]\s*["']([A-Za-z0-9/+=]{40})["']`, allOf(hasLetterAndDigit, entropyAtLeast(3.5))),
	mp("AWS Session Token", `(?i)aws_session_token["']?\s*[:=]\s*["']([A-Za-z0-9/+=]{100,})["']`),

	// --- Google / Firebase / GCP ---
	// Browser API keys are commonly shipped in client code and restricted by
	// referrer, so they are informational unless the caller proves otherwise.
	mpPublic("Google API Key", `\bAIza[0-9A-Za-z_\-]{35}\b`),
	mp("Google OAuth Access Token", `\bya29\.[0-9A-Za-z\-_]+\b`),
	mp("Google OAuth Refresh Token", `\b1//[0-9A-Za-z\-_]{35,}\b`),
	mp("Google OAuth Client Secret", `\bGOCSPX-[0-9A-Za-z_\-]{28}\b`),
	mpPublic("Google OAuth Client ID", `\b[0-9]{6,}-[0-9a-z]{32}\.apps\.googleusercontent\.com\b`),
	mp("Firebase Cloud Messaging Key", `\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b`),
	mp("GCP Service Account Private Key", `"private_key":\s*"-----BEGIN PRIVATE KEY-----`),

	// --- Microsoft Azure ---
	mpValid("Azure Client Secret", `(?i)azure(.{0,20})?["']([0-9a-zA-Z/+_.~-]{25,50})["']`, hasLetterAndDigit),
	mp("Azure Storage Connection String", `DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{80,}`),

	// --- GitHub / GitLab ---
	mp("GitHub Personal Access Token", `\bghp_[0-9A-Za-z]{36}\b`),
	mp("GitHub OAuth Token", `\bgho_[0-9A-Za-z]{36}\b`),
	mp("GitHub App/User-to-Server Token", `\bgh[us]_[0-9A-Za-z]{36}\b`),
	mp("GitHub Refresh Token", `\bghr_[0-9A-Za-z]{36}\b`),
	mp("GitHub Fine-grained PAT", `\bgithub_pat_[0-9A-Za-z_]{22,}\b`),
	mp("GitLab Personal Access Token", `\bglpat-[0-9A-Za-z\-_]{20}\b`),

	// --- Slack / Discord / Telegram ---
	mp("Slack Token", `\bxox[baprs]-[0-9A-Za-z-]{10,72}\b`),
	mp("Slack Config Access Token", `\bxoxe\.xox[bp]-\d-[0-9A-Za-z-]{163,}\b`),
	mp("Slack Webhook URL", `https://hooks\.slack\.com/services/T[0-9A-Za-z]{8,}/B[0-9A-Za-z]{8,}/[0-9A-Za-z]{24}`),
	mp("Discord Bot Token", `\b[MN][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b`),
	mp("Discord Webhook URL", `https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_\-]{60,}`),
	mp("Telegram Bot Token", `\b[0-9]{8,10}:AA[0-9A-Za-z_-]{33}\b`),

	// --- JWT / generic bearer / basic auth ---
	// A JWT's header decodes to JSON with an "alg" member; a dotted random
	// string does not, which removes the usual noise from minified code.
	mpValid("JWT-shaped Token", `\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`, validJWTHeader),
	mpValid("Bearer Token", `(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}=*`, allOf(hasLetterAndDigit, entropyAtLeast(3.0))),
	mp("Authorization: Basic Header", `(?i)authorization:\s*basic\s+[A-Za-z0-9+/=]{8,}`),
	mpValid("Credentials in URL", `\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/'"<>]+:[^\s/'"<>@]+@[^\s/'"<>]+`, validURLPassword),
	// The scheme group is non-capturing on purpose: secretGroup judges a match by
	// its last capture group, and the validator needs the whole URL.
	mpValid("Database Connection String", `\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s'"<>]+:[^\s'"<>@]+@[^\s'"<>]+`, validURLPassword),

	// --- Private key material ---
	// A key counts only with a body and its END line. A bare BEGIN line is
	// what documentation and tutorials show, so it is not a leaked key.
	mp("Private Key Block", `-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]{20,}?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
	mp("PKCS8 Private Key Block", `-----BEGIN PRIVATE KEY-----[\s\S]{20,}?-----END PRIVATE KEY-----`),
	mp("PGP Private Key Block", `-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]{20,}?-----END PGP PRIVATE KEY BLOCK-----`),

	// --- Payments ---
	mp("Stripe Live Secret Key", `\bsk_live_[0-9a-zA-Z]{24,}\b`),
	mpPublic("Stripe Live Publishable Key", `\bpk_live_[0-9a-zA-Z]{24,}\b`),
	mp("Stripe Restricted Key", `\brk_live_[0-9a-zA-Z]{24,}\b`),
	mp("Stripe Webhook Signing Secret", `\bwhsec_[0-9A-Za-z]{32,}\b`),
	mp("PayPal Braintree Access Token", `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`),
	mp("Square Access Token", `\bsq0atp-[0-9A-Za-z\-_]{22}\b`),
	mp("Square Sandbox Access Token", `\bsandbox-sq0atb-[0-9A-Za-z\-_]{22}\b`),
	mp("Square OAuth Secret", `\bsq0csp-[0-9A-Za-z\-_]{43}\b`),
	mp("Razorpay Live Key", `\brzp_live_[0-9A-Za-z]{14}\b`),
	mp("Plaid Access Token", `\baccess-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`),

	// --- Comms / email ---
	// An Account SID identifies the account but cannot authenticate by itself,
	// so it is informational; the auth token that pairs with it is the secret.
	mpPublic("Twilio Account SID", `\bAC[a-f0-9]{32}\b`),
	mp("Twilio API Key SID", `\bSK[a-f0-9]{32}\b`),
	mp("SendGrid API Key", `\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b`),
	mpValid("Mailgun API Key", `\bkey-[0-9a-zA-Z]{32}\b`, allOf(hasLetterAndDigit, entropyAtLeast(3.0))),
	mp("Mailchimp API Key", `\b[0-9a-f]{32}-us[0-9]{1,2}\b`),
	mp("Brevo API Key", `\bxkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}\b`),

	// --- Social ---
	mp("Facebook Access Token", `\bEAACEdEose0cBA[0-9A-Za-z]+\b`),
	mp("Twitter Bearer Token", `\bAAAAAAAAAAAAAAAAAAAAA[0-9A-Za-z%]{32,60}\b`),
	mpValid("Twitter Access Token", `\b[0-9]{15,20}-[0-9A-Za-z]{40}\b`, hasLetterAndDigit),
	mpValid("LinkedIn Client Secret", `(?i)linkedin(.{0,20})?["']([0-9a-zA-Z]{16})["']`, hasLetterAndDigit),

	// --- Cloud storage / dev tools ---
	mp("Dropbox API Key", `\bsl\.[A-Za-z0-9_\-]{20,100}\b`),
	mpValid("Heroku API Key", `(?i)heroku(.{0,20})?["']([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})["']`, hasLetterAndDigit),
	mp("Shopify Admin Access Token", `\bshpat_[0-9a-fA-F]{32}\b`),
	mp("Shopify Custom App Token", `\bshpca_[0-9a-fA-F]{32}\b`),
	mp("Shopify Shared Secret", `\bshpss_[0-9a-fA-F]{32}\b`),
	mpValid("Coinbase API Key", `(?i)coinbase(.{0,20})?["']([0-9a-zA-Z]{25,50})["']`, hasLetterAndDigit),
	mp("npm Access Token", `\bnpm_[A-Za-z0-9]{36}\b`),
	mp("PyPI Upload Token", `\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b`),
	mp("Postman API Key", `\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b`),
	mp("New Relic API Key", `\bNRAK-[A-Z0-9]{27}\b`),
	mpValid("Datadog API Key", `(?i)datadog(.{0,20})?["']([0-9a-f]{32})["']`, hasLetterAndDigit),
	mpValid("Algolia Admin API Key", `(?i)algolia(.{0,20})?["']([0-9a-zA-Z]{32})["']`, hasLetterAndDigit),
	mp("DigitalOcean Token", `\bdo[opr]_v1_[a-f0-9]{64}\b`),
	mp("Linear API Key", `\blin_api_[A-Za-z0-9]{40}\b`),
	mpValid("Notion Integration Token", `\bsecret_[A-Za-z0-9]{43}\b`, hasLetterAndDigit),
	mp("Figma Personal Access Token", `\bfigd_[A-Za-z0-9_\-]{40,}`),
	mp("Supabase Personal Access Token", `\bsbp_[a-f0-9]{40}\b`),
	mp("Atlassian API Token", `\bATATT3[A-Za-z0-9_\-=]{100,}`),
	mp("Mapbox Secret Token", `\bsk\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`),
	mpPublic("Mapbox Public Token", `\bpk\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`),
	mp("Pulumi Access Token", `\bpul-[a-f0-9]{40}\b`),
	mp("RubyGems API Key", `\brubygems_[a-f0-9]{48}\b`),
	mp("Docker Hub Personal Access Token", `\bdckr_pat_[A-Za-z0-9_\-]{27}`),
	mp("Grafana Cloud API Key", `\bglc_[A-Za-z0-9+/]{32,}={0,2}`),
	mp("Grafana Service Account Token", `\bglsa_[A-Za-z0-9]{32}_[a-f0-9]{8}\b`),
	mp("HashiCorp Vault Service Token", `\bhvs\.[A-Za-z0-9_\-]{24,}`),
	mp("Doppler Token", `\bdp\.(?:pt|st|sa|ct)\.[A-Za-z0-9]{40,}`),
	mpPublic("Sentry DSN", `https://[0-9a-f]{32}@[A-Za-z0-9.\-]*sentry\.io/[0-9]+`),

	// --- AI providers ---
	// The OpenAI shape ("sk-" plus letters) also matches Anthropic's
	// "sk-ant-" keys, so those are excluded here and reported by their own
	// pattern below.
	mpValid("OpenAI API Key", `\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}`, allOf(notPrefix("sk-ant-"), hasLetterAndDigit)),
	mp("Anthropic API Key", `\bsk-ant-[A-Za-z0-9_-]{20,}\b`),
	mpValid("Hugging Face Token", `\bhf_[A-Za-z0-9]{34,}\b`, hasLetterAndDigit),
	mp("Groq API Key", `\bgsk_[A-Za-z0-9]{52}\b`),

	// --- Generic assignment fallback ---
	// Keyword-anchored and loose, so the value must look generated: long enough,
	// high entropy, and with a digit or mixed case. "undefinedundefined" fails.
	mpValid("Generic API Key Assignment", `(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)["']?\s*[:=]\s*["']([A-Za-z0-9_\-]{20,})["']`, allOf(entropyAtLeast(3.0), hasDigitOrMixedCase)),
}
