package idor

import (
	"encoding/base64"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

// refKind is the shape of an object reference, which decides how neighbouring
// references are generated. A value's kind is inferred from the value itself
// (see classify); a point whose value does not classify but whose name looks
// like an identifier is treated as numeric with a seed value of "1".
type refKind string

const (
	kindNumeric  refKind = "numeric"  // 1001, 42
	kindUUID     refKind = "uuid"     // 8-4-4-4-12 hex
	kindObjectID refKind = "objectid" // 24 hex chars (Mongo ObjectId)
	kindHex      refKind = "hex"      // 16/32/40/64 hex chars (token or hash)
	kindBase64   refKind = "base64"   // base64 that decodes to a short value
	kindEmail    refKind = "email"    // contains "@"
	kindSlug     refKind = "slug"     // short handle, e.g. "john-doe", "acme"
)

var (
	// numericPattern matches an unsigned integer, the most common identifier.
	numericPattern = regexp.MustCompile(`^\d{1,18}$`)
	// uuidPattern matches a canonical UUID, case-insensitively.
	uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	// objectIDPattern matches a 24-character hex Mongo ObjectId.
	objectIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{24}$`)
	// hexPattern matches hex strings the length of common hashes/tokens.
	hexPattern = regexp.MustCompile(`^[0-9a-fA-F]{16}$|^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$`)
	// emailPattern matches a loose e-mail address (local@domain.tld).
	emailPattern = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	// slugPattern matches a short alphanumeric handle with -/_ separators.
	slugPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{1,31}$`)
	// base64Pattern matches a base64 token (standard or URL alphabet).
	base64Pattern = regexp.MustCompile(`^[A-Za-z0-9+/_-]{6,64}={0,2}$`)
	// idNamePattern matches parameter / segment / field names that commonly
	// carry an object reference, so a point is treated as an identity point on
	// its name even when its value is empty or does not classify on its own.
	idNamePattern = regexp.MustCompile(`(?i)(^|[_-])(id|ids|uid|uuid|guid|gid|pid|oid|key|ref|no|num|number|code|token|account|acct|user|userid|customer|order|invoice|doc|document|file|object|item|record|profile|page|group|team|org|company|project|ticket|message|msg|post|comment|node|entity|session|cart)([_-]|$)`)
	// commonWords are slug-shaped values that are almost never object
	// references (locales, booleans, common flags), so they do not make a
	// point an identity point on value alone.
	commonWords = map[string]bool{
		"true": true, "false": true, "null": true, "none": true, "en": true,
		"us": true, "gb": true, "de": true, "fr": true, "es": true, "on": true,
		"off": true, "yes": true, "no": true, "all": true, "default": true,
		"light": true, "dark": true, "asc": true, "desc": true,
	}
)

// classify reports the kind of reference value is, and whether it looks like a
// reference at all. The order matters: the most specific, least ambiguous
// shapes (numeric, UUID, ObjectId) are checked before the looser ones (hex,
// base64, slug) so a value is labelled by the strongest interpretation.
func classify(value string) (refKind, bool) {
	v := strings.TrimSpace(value)
	// An empty value carries no reference to mutate.
	if v == "" {
		return "", false
	}
	switch {
	case numericPattern.MatchString(v):
		return kindNumeric, true
	case uuidPattern.MatchString(v):
		return kindUUID, true
	case objectIDPattern.MatchString(v):
		return kindObjectID, true
	case hexPattern.MatchString(v):
		return kindHex, true
	case emailPattern.MatchString(v):
		return kindEmail, true
	}
	// A base64 token only counts when it actually decodes to a short, printable
	// value -- otherwise half of all slugs would match the alphabet by chance.
	if base64Pattern.MatchString(v) && decodesToReference(v) {
		return kindBase64, true
	}
	// A slug is the loosest kind, so common non-reference words are excluded to
	// keep ordinary flags (locale=en, sort=asc) from becoming identity points.
	if slugPattern.MatchString(v) && !commonWords[strings.ToLower(v)] {
		return kindSlug, true
	}
	return "", false
}

// decodesToReference reports whether a base64 token decodes to something that
// itself looks like a reference (a number or a short printable id), which is
// the pattern behind base64-wrapped identifiers such as "MTAwMQ==" (1001).
func decodesToReference(v string) bool {
	raw, ok := decodeBase64(v)
	if !ok {
		return false
	}
	inner := strings.TrimSpace(string(raw))
	// A decoded value that is itself numeric or a short clean id is the signal
	// that the base64 is wrapping an object reference.
	if numericPattern.MatchString(inner) {
		return true
	}
	return slugPattern.MatchString(inner) && len(inner) <= 24
}

// decodeBase64 tries the standard and URL-safe alphabets, with and without
// padding, and returns the first successful decode.
func decodeBase64(v string) ([]byte, bool) {
	// Try each alphabet/padding combination the wild uses.
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err := enc.DecodeString(v); err == nil && len(raw) > 0 {
			return raw, true
		}
	}
	return nil, false
}

// nameLooksLikeID reports whether a parameter/segment/field/header name is one
// that commonly carries an object reference.
func nameLooksLikeID(name string) bool {
	return idNamePattern.MatchString(strings.TrimSpace(name))
}

// candidate is one mutated reference to try, with a short note describing how
// it relates to the original (used in the finding detail).
type candidate struct {
	value string
	note  string
}

// neighbors returns sibling references for a value of the given kind: other
// identifiers an attacker would try to reach an object they do not own. The
// list is ordered most-promising first, and each module takes as many as it
// needs.
func neighbors(kind refKind, value string) []candidate {
	switch kind {
	case kindNumeric:
		return numericNeighbors(value)
	case kindUUID:
		return uuidNeighbors(value)
	case kindObjectID, kindHex:
		return hexNeighbors(value)
	case kindBase64:
		return base64Neighbors(value)
	case kindEmail:
		return emailNeighbors(value)
	case kindSlug:
		return slugNeighbors(value)
	}
	return nil
}

// numericNeighbors generates identifiers adjacent to an integer id. Adjacent
// ids are the classic IDOR case: /invoice?id=1001 -> id=1000, 1002, ...
func numericNeighbors(value string) []candidate {
	n, ok := new(big.Int).SetString(value, 10)
	// A value that classified as numeric always parses, but guard anyway so a
	// malformed seed cannot panic the scan.
	if !ok {
		return nil
	}
	var out []candidate
	// Small offsets around the value reach the records created just before and
	// after it, the ones most likely to belong to another user.
	for _, d := range []int64{1, -1, 2, -2, 3, -3, 5, -5, 10, -10, 100, -100} {
		cand := new(big.Int).Add(n, big.NewInt(d))
		// A negative result is dropped; ids are almost never below zero, and 0
		// is covered by the boundary module instead.
		if cand.Sign() < 0 {
			continue
		}
		sign := "+"
		if d < 0 {
			sign = ""
		}
		out = append(out, candidate{value: cand.String(), note: "adjacent id (" + sign + strconv.FormatInt(d, 10) + ")"})
	}
	return out
}

// uuidNeighbors generates UUIDs near a given one. A v4 UUID is random, so a
// strict +1 rarely hits a real record; the useful cases are the nil and max
// UUIDs (often seeded fixtures or the first/admin record) and a last-byte
// increment (sequential v1/v7 UUIDs and ULIDs really are adjacent).
func uuidNeighbors(value string) []candidate {
	v := strings.ToLower(value)
	out := []candidate{
		{value: "00000000-0000-0000-0000-000000000000", note: "nil UUID"},
		{value: "ffffffff-ffff-ffff-ffff-ffffffffffff", note: "max UUID"},
	}
	// A hex increment/decrement of the trailing node field reaches the
	// neighbours of time-ordered UUIDs (v1, v6, v7) and ULIDs.
	if inc, ok := bumpHexTail(strings.ReplaceAll(v, "-", ""), 1); ok {
		out = append(out, candidate{value: formatUUID(inc), note: "incremented UUID"})
	}
	if dec, ok := bumpHexTail(strings.ReplaceAll(v, "-", ""), -1); ok {
		out = append(out, candidate{value: formatUUID(dec), note: "decremented UUID"})
	}
	return out
}

// hexNeighbors generates neighbours for a hex token or ObjectId: the all-zero
// and all-f extremes plus a last-nibble increment/decrement. A Mongo ObjectId
// embeds a counter in its low bytes, so adjacent ObjectIds really are created
// back to back.
func hexNeighbors(value string) []candidate {
	v := strings.ToLower(value)
	out := []candidate{
		{value: strings.Repeat("0", len(v)), note: "all-zero id"},
		{value: strings.Repeat("f", len(v)), note: "all-f id"},
	}
	if inc, ok := bumpHexTail(v, 1); ok {
		out = append(out, candidate{value: inc, note: "incremented id"})
	}
	if dec, ok := bumpHexTail(v, -1); ok {
		out = append(out, candidate{value: dec, note: "decremented id"})
	}
	return out
}

// base64Neighbors decodes the token, mutates the inner value (as a number when
// it is one), and re-encodes it with the same alphabet, so the probe reaches
// the record whose wrapped id sits next to this one.
func base64Neighbors(value string) []candidate {
	raw, ok := decodeBase64(value)
	if !ok {
		return nil
	}
	inner := strings.TrimSpace(string(raw))
	var out []candidate
	// A base64-wrapped integer is the common case: decode, step the number,
	// and re-wrap so the app unwraps a neighbouring id.
	if n, ok := new(big.Int).SetString(inner, 10); ok {
		for _, d := range []int64{1, -1, 2, -2} {
			cand := new(big.Int).Add(n, big.NewInt(d))
			if cand.Sign() < 0 {
				continue
			}
			sign := "+"
			if d < 0 {
				sign = ""
			}
			out = append(out, candidate{value: reencodeBase64(value, cand.String()), note: "base64-wrapped id (" + sign + strconv.FormatInt(d, 10) + ")"})
		}
		return out
	}
	// A non-numeric inner value still gets the plaintext tried directly, since
	// some apps accept the decoded form too.
	out = append(out, candidate{value: inner, note: "decoded base64 value"})
	return out
}

// emailNeighbors swaps the local part of an address for common privileged
// accounts while keeping the domain, the pattern behind account-takeover IDORs
// that key on an e-mail address.
func emailNeighbors(value string) []candidate {
	at := strings.LastIndex(value, "@")
	// A classified e-mail always contains "@", but guard for safety.
	if at < 0 {
		return nil
	}
	domain := value[at:]
	var out []candidate
	// Try the usual privileged local parts on the same domain.
	for _, local := range []string{"admin", "administrator", "root", "support", "test"} {
		out = append(out, candidate{value: local + domain, note: "privileged local part"})
	}
	return out
}

// slugNeighbors tries common privileged or seeded handles in place of a slug.
func slugNeighbors(value string) []candidate {
	var out []candidate
	// These handles frequently name the first, admin, or demo record.
	for _, s := range []string{"admin", "administrator", "root", "test", "demo", "1", "0"} {
		// Skip a candidate identical to the value already in place.
		if strings.EqualFold(s, value) {
			continue
		}
		out = append(out, candidate{value: s, note: "common handle"})
	}
	return out
}

// boundaryValues returns edge-case identifiers worth trying at any numeric or
// hex point: the first record, zero, a negative, and integer limits that often
// expose the oldest (frequently admin) object or trip type handling.
func boundaryValues(kind refKind) []candidate {
	switch kind {
	case kindNumeric, kindBase64:
		return []candidate{
			{value: "0", note: "zero"},
			{value: "1", note: "first record"},
			{value: "-1", note: "negative id"},
			{value: "2147483647", note: "int32 max"},
			{value: "2147483648", note: "int32 overflow"},
			{value: "9999999999", note: "large id"},
		}
	case kindUUID:
		return []candidate{
			{value: "00000000-0000-0000-0000-000000000001", note: "first UUID"},
		}
	}
	// ObjectId and hex points get their extremes from hexNeighbors (all-zero,
	// all-f), which already depend on the value's length, so there is nothing
	// length-independent to add here.
	return nil
}

// garbageValue returns a reference of the right shape that is extremely
// unlikely to name a real object, used as the negative control: if even this
// returns content, the endpoint ignores the identifier (a catch-all) and no
// neighbour result can be trusted.
func garbageValue(kind refKind, value string) string {
	switch kind {
	case kindNumeric:
		return "999999999999999"
	case kindBase64:
		return reencodeBase64(value, "999999999999999")
	case kindUUID:
		return "7f3e9c21-0000-4000-8000-deadbeef0000"
	case kindObjectID:
		return "ffffffffdeadbeefdeadbeef"
	case kindHex:
		// A hex control must match the original length so the app's parser
		// accepts it; a fixed deadbeef run padded to length does that.
		return padHex("deadbeefdeadbeef", len(value))
	case kindEmail:
		return "no-such-user-xyzzy@" + afterAt(value)
	case kindSlug:
		return "aperture-no-such-id-xyzzy"
	}
	return "aperture-no-such-id-xyzzy"
}

// primaryVictim is the single neighbour used by the transport-level modules
// (pollution, array wrapping, suffix, encoding) as the "other user's" value
// they try to smuggle past the reference a point already carries.
func primaryVictim(kind refKind, value string) string {
	if ns := neighbors(kind, value); len(ns) > 0 {
		return ns[0].value
	}
	return value
}

// bumpHexTail adds delta to a hex string interpreted as a big integer and
// returns it zero-padded back to the original length. It fails (ok=false) when
// the value is not hex or the result would change length (overflow/underflow),
// since a different-length id would not be accepted by the same parser.
func bumpHexTail(hexStr string, delta int64) (string, bool) {
	n, ok := new(big.Int).SetString(hexStr, 16)
	if !ok {
		return "", false
	}
	n.Add(n, big.NewInt(delta))
	// A negative result has no valid fixed-width hex form.
	if n.Sign() < 0 {
		return "", false
	}
	out := n.Text(16)
	// Overflowing the width changes the id shape, so the mutation is dropped.
	if len(out) > len(hexStr) {
		return "", false
	}
	return padHex(out, len(hexStr)), true
}

// padHex left-pads a hex string with zeros to width, or truncates from the
// left when it is already longer.
func padHex(s string, width int) string {
	if len(s) >= width {
		return s[len(s)-width:]
	}
	return strings.Repeat("0", width-len(s)) + s
}

// formatUUID inserts the 8-4-4-4-12 dashes into a 32-char hex string.
func formatUUID(hex32 string) string {
	// A malformed length cannot be dashed, so it is returned unchanged.
	if len(hex32) != 32 {
		return hex32
	}
	return hex32[0:8] + "-" + hex32[8:12] + "-" + hex32[12:16] + "-" + hex32[16:20] + "-" + hex32[20:32]
}

// reencodeBase64 encodes inner with the same alphabet and padding the original
// token used, so the app's decoder accepts the replacement exactly as it did
// the original.
func reencodeBase64(original, inner string) string {
	enc := base64.StdEncoding
	switch {
	// A URL-safe token (uses - or _, or has no padding but URL chars) is
	// re-encoded URL-safe so the wire form matches the original.
	case strings.ContainsAny(original, "-_"):
		enc = base64.RawURLEncoding
		if strings.HasSuffix(original, "=") {
			enc = base64.URLEncoding
		}
	case !strings.HasSuffix(original, "="):
		enc = base64.RawStdEncoding
	}
	return enc.EncodeToString([]byte(inner))
}

// afterAt returns the domain portion of an e-mail (including the "@"), or a
// fallback when there is none.
func afterAt(email string) string {
	if at := strings.LastIndex(email, "@"); at >= 0 {
		return email[at+1:]
	}
	return "example.com"
}
