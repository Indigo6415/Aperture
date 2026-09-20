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
}

// mp ("make pattern") panics on an invalid regex -- every entry below is a
// compile-time constant, so a typo is a bug to catch immediately, not a
// runtime error to handle.
func mp(name, pattern string) Pattern {
	return Pattern{Name: name, Regex: regexp.MustCompile(pattern)}
}

// Patterns is the full library scanText matches every page/script against.
// It's a superset of Snitch's own regex_patterns.py plus
// internal/probescan/secrets.go's list, extended with more services --
// deliberately kept to high-signal, specific key/token *shapes* (fixed
// prefixes, fixed lengths) rather than broad "anything after a word like
// 'key'" matches, which is exactly the class of pattern both of those
// predecessors comment out for burying real findings in false positives
// from minified JS. Bare hex/base64 hash patterns (MD5/SHA-*) are likewise
// deliberately omitted for the same reason.
var Patterns = []Pattern{
	// --- AWS ---
	mp("AWS Access Key ID", `\bAKIA[0-9A-Z]{16}\b`),
	mp("AWS Secret Access Key", `(?i)aws_secret_access_key["']?\s*[:=]\s*["']([A-Za-z0-9/+=]{40})["']`),
	mp("AWS Session Token", `(?i)aws_session_token["']?\s*[:=]\s*["']([A-Za-z0-9/+=]{100,})["']`),

	// --- Google / Firebase / GCP ---
	mp("Google API Key", `\bAIza[0-9A-Za-z_\-]{35}\b`),
	mp("Google OAuth Access Token", `\bya29\.[0-9A-Za-z\-_]+\b`),
	mp("Google OAuth Refresh Token", `\b1//[0-9A-Za-z\-_]{35,}\b`),
	mp("Firebase Cloud Messaging Key", `\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b`),
	mp("GCP Service Account Private Key", `"private_key":\s*"-----BEGIN PRIVATE KEY-----`),

	// --- Microsoft Azure ---
	mp("Azure Client Secret", `(?i)azure(.{0,20})?["'][0-9a-zA-Z/+_.~-]{25,50}["']`),
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
	mp("JWT-shaped Token", `\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
	mp("Bearer Token", `(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}=*`),
	mp("Authorization: Basic Header", `(?i)authorization:\s*basic\s+[A-Za-z0-9+/=]{8,}`),
	mp("Credentials in URL", `\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/'"<>]+:[^\s/'"<>@]+@[^\s/'"<>]+`),
	mp("Database Connection String", `\b(postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s'"<>]+:[^\s'"<>@]+@[^\s'"<>]+`),

	// --- Private key material ---
	mp("Private Key Block", `-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----`),
	mp("PKCS8 Private Key Block", `-----BEGIN PRIVATE KEY-----`),

	// --- Payments ---
	mp("Stripe Live Secret Key", `\bsk_live_[0-9a-zA-Z]{24,}\b`),
	mp("Stripe Live Publishable Key", `\bpk_live_[0-9a-zA-Z]{24,}\b`),
	mp("Stripe Restricted Key", `\brk_live_[0-9a-zA-Z]{24,}\b`),
	mp("PayPal Braintree Access Token", `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`),
	mp("Square Access Token", `\bsq0atp-[0-9A-Za-z\-_]{22}\b`),
	mp("Square Sandbox Access Token", `\bsandbox-sq0atb-[0-9A-Za-z\-_]{22}\b`),
	mp("Square OAuth Secret", `\bsq0csp-[0-9A-Za-z\-_]{43}\b`),

	// --- Comms / email ---
	mp("Twilio Account SID", `\bAC[a-f0-9]{32}\b`),
	mp("Twilio API Key SID", `\bSK[a-f0-9]{32}\b`),
	mp("SendGrid API Key", `\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b`),
	mp("Mailgun API Key", `\bkey-[0-9a-zA-Z]{32}\b`),
	mp("Mailchimp API Key", `\b[0-9a-f]{32}-us[0-9]{1,2}\b`),

	// --- Social ---
	mp("Facebook Access Token", `\bEAACEdEose0cBA[0-9A-Za-z]+\b`),
	mp("Twitter Bearer Token", `\bAAAAAAAAAAAAAAAAAAAAA[0-9A-Za-z%]{32,60}\b`),
	mp("Twitter Access Token", `\b[0-9]{15,20}-[0-9A-Za-z]{40}\b`),
	mp("LinkedIn Client Secret", `(?i)linkedin(.{0,20})?["'][0-9a-zA-Z]{16}["']`),

	// --- Cloud storage / dev tools ---
	mp("Dropbox API Key", `\bsl\.[A-Za-z0-9_\-]{20,100}\b`),
	mp("Heroku API Key", `(?i)heroku(.{0,20})?["'][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}["']`),
	mp("Shopify Admin Access Token", `\bshpat_[0-9a-fA-F]{32}\b`),
	mp("Shopify Custom App Token", `\bshpca_[0-9a-fA-F]{32}\b`),
	mp("Shopify Shared Secret", `\bshpss_[0-9a-fA-F]{32}\b`),
	mp("Coinbase API Key", `(?i)coinbase(.{0,20})?["'][0-9a-zA-Z]{25,50}["']`),
	mp("npm Access Token", `\bnpm_[A-Za-z0-9]{36}\b`),
	mp("PyPI Upload Token", `\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b`),
	mp("Postman API Key", `\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b`),
	mp("New Relic API Key", `\bNRAK-[A-Z0-9]{27}\b`),
	mp("Datadog API Key", `(?i)datadog(.{0,20})?["'][0-9a-f]{32}["']`),
	mp("Algolia Admin API Key", `(?i)algolia(.{0,20})?["'][0-9a-zA-Z]{32}["']`),

	// --- AI providers ---
	mp("OpenAI API Key", `\bsk-(proj-)?[A-Za-z0-9_-]{20,48}\b`),
	mp("Anthropic API Key", `\bsk-ant-[A-Za-z0-9_-]{20,}\b`),

	// --- Generic assignment fallback ---
	mp("Generic API Key Assignment", `(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret)["']?\s*[:=]\s*["']([A-Za-z0-9_\-]{20,})["']`),
}
