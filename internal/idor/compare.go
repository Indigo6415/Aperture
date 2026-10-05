package idor

import "github.com/Indigo6415/Aperture/internal/fingerprint"

// Confidence grades how strongly a finding is supported, matching the strings
// the other scanners and the frontend already use.
const (
	// ConfidenceConfirmed means a second identity demonstrably retrieved the
	// owner's object while a garbage reference under that identity did not --
	// access control is broken, proven by comparison.
	ConfidenceConfirmed = "confirmed"
	// ConfidenceLikely means a distinct, valid object came back for an
	// identifier the client changed, but ownership could not be proven from a
	// single identity, so it needs an operator's eyes.
	ConfidenceLikely = "likely"
	// ConfidenceHeuristic means the response merely differed in a way that
	// could not be ruled out as an error or catch-all page -- a lead.
	ConfidenceHeuristic = "heuristic"
)

// minObjectBytes is the smallest response body treated as a real object. An
// empty or near-empty body is almost always a redirect-stripped denial or an
// error, not another user's record.
const minObjectBytes = 32

// is2xx reports whether a status code is a success.
func is2xx(status int) bool {
	return status >= 200 && status < 300
}

// nonTrivial reports whether a response body is large enough to be a real
// object rather than an empty or stub denial.
func nonTrivial(r *sendResult) bool {
	return r != nil && r.Err == nil && len(r.Body) >= minObjectBytes
}

// distinctObject decides whether a single-identity probe reached a *different,
// real object* than the baseline -- the signal of an enumerable reference.
// It returns the confidence and whether to report.
//
// The reasoning, in order:
//   - the probe must succeed (2xx) and carry a real body; a denial or error is
//     the app correctly refusing, which is the opposite of a finding;
//   - a body byte-identical to the baseline means the app ignored the changed
//     identifier and returned the caller's own object, which proves nothing;
//   - a body that looks like the negative control (a reference that cannot
//     exist) is the generic not-found/error page, so the identifier was not
//     honoured;
//   - anything else is a distinct object that came back for an identifier the
//     caller changed -- reportable, at "likely" when the control ran (a
//     catch-all was ruled out) and "heuristic" when it could not.
func distinctObject(baseline, probe, control *sendResult, controlRan bool) (string, bool) {
	// A failed, non-success, or trivial probe is never a finding.
	if probe == nil || probe.Err != nil || !is2xx(probe.StatusCode) || !nonTrivial(probe) {
		return "", false
	}
	// The app returned our own object regardless of the identifier: no access
	// to anything new was gained.
	if baseline != nil && probe.Body == baseline.Body {
		return "", false
	}
	// The probe matches the not-found/error page, so the identifier selected
	// nothing -- correct behaviour, not a finding.
	if controlRan && control != nil && control.Err == nil && fingerprint.Similar(control.Obs, probe.Obs) {
		return "", false
	}
	// A distinct object came back. The control having run is what lets us call
	// it "likely" rather than a bare lead.
	if controlRan {
		return ConfidenceLikely, true
	}
	return ConfidenceHeuristic, true
}

// crossIdentityObject decides whether a *different* identity (a second
// credential, or no credentials at all) retrieved the object the owner's
// request returns -- the definitive IDOR/BOLA signal.
//
// owner is the baseline response under the legitimate identity; other is the
// same request replayed under the alternate identity; otherControl is a
// garbage reference fetched under that same alternate identity.
//
// It confirms only when the alternate identity got a response matching the
// owner's for the real object but a *different* response for the garbage one:
// that rules out an endpoint that simply serves the same page to everyone
// (a public page or a soft error), which would otherwise look identical.
func crossIdentityObject(owner, other, otherControl *sendResult, controlRan bool) (string, bool) {
	// Both the owner's and the alternate identity's responses must be real
	// successful objects for a comparison to mean anything.
	if !nonTrivial(owner) || !is2xx(owner.StatusCode) {
		return "", false
	}
	if !nonTrivial(other) || other.Err != nil || !is2xx(other.StatusCode) {
		return "", false
	}
	// The alternate identity must have received the owner's object -- either
	// byte-identical or the same page by fingerprint (templated records with
	// dynamic tokens differ by a few bytes but stay Similar).
	if other.Body != owner.Body && !fingerprint.Similar(owner.Obs, other.Obs) {
		return "", false
	}
	// Catch-all guard: if the alternate identity gets that same page even for a
	// reference that cannot exist, the endpoint serves it to everyone and this
	// is not proof of unauthorized object access.
	if controlRan && otherControl != nil && otherControl.Err == nil && fingerprint.Similar(other.Obs, otherControl.Obs) {
		return "", false
	}
	// Object-specific access by another identity, confirmed when the catch-all
	// control actually ran, otherwise reported as likely.
	if controlRan {
		return ConfidenceConfirmed, true
	}
	return ConfidenceLikely, true
}
