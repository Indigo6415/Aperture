package idor

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// moduleMeta is the identity of one check module, the same shape the other
// scanners use so the frontend renders every module card the same way.
type moduleMeta struct {
	id       string
	name     string
	severity string
}

// attempt is one probe a module wants to send against a point: the fully built
// request plus a human-readable payload and a note explaining the technique.
type attempt struct {
	spec    requestSpec
	payload string
	note    string
}

// probeModule is a module that mutates a single point's reference and judges
// the result with distinctObject. applies filters the points it runs against;
// attempts builds the probes for one point, tried in order until one reports.
type probeModule struct {
	moduleMeta
	applies  func(point) bool
	attempts func(point) []attempt
}

// valueModules are the single-identity check modules. Each one runs against
// every point it applies to and stops at the first mutation that returns a
// distinct, real object. They are ordered most to least severe.
var valueModules = []probeModule{
	{
		moduleMeta: moduleMeta{id: "id-enumeration", name: "Object reference enumeration", severity: "high"},
		// Enumeration applies wherever a reference has computable neighbours.
		applies:  func(p point) bool { return len(neighbors(p.kind, p.value)) > 0 },
		attempts: func(p point) []attempt { return valueAttempts(p, neighbors(p.kind, p.value)) },
	},
	{
		moduleMeta: moduleMeta{id: "boundary-values", name: "Boundary & first-record values", severity: "medium"},
		// Boundary values only exist for numeric-like and UUID references.
		applies:  func(p point) bool { return len(boundaryValues(p.kind)) > 0 },
		attempts: func(p point) []attempt { return valueAttempts(p, boundaryValues(p.kind)) },
	},
	{
		moduleMeta: moduleMeta{id: "parameter-pollution", name: "HTTP parameter pollution", severity: "medium"},
		// Pollution needs a point that can carry a parameter more than once.
		applies:  func(p point) bool { return p.buildValues != nil },
		attempts: pollutionAttempts,
	},
	{
		moduleMeta: moduleMeta{id: "array-type-juggling", name: "Array wrapping & type juggling", severity: "medium"},
		// Array/type tricks need either a renamable parameter or a JSON leaf.
		applies:  func(p point) bool { return p.buildArrayName != nil || p.buildJSON != nil },
		attempts: arrayAttempts,
	},
	{
		moduleMeta: moduleMeta{id: "wrapper-suffix", name: "Suffix & wildcard tricks", severity: "low"},
		// Suffix tricks only make sense where neighbours exist to decorate.
		applies:  func(p point) bool { return len(neighbors(p.kind, p.value)) > 0 },
		attempts: suffixAttempts,
	},
	{
		moduleMeta: moduleMeta{id: "encoding-bypass", name: "Encoding & case bypass", severity: "low"},
		// Encoding bypasses only matter in the URL or body, not in a header.
		applies: func(p point) bool {
			return (p.where == "query" || p.where == "path" || p.where == "form") && len(neighbors(p.kind, p.value)) > 0
		},
		attempts: encodingAttempts,
	},
}

// valueAttempts turns a list of candidate references into attempts that each
// set the point to one candidate via its scalar build.
func valueAttempts(p point, cands []candidate) []attempt {
	out := make([]attempt, 0, len(cands))
	// Build one probe per candidate, carrying the candidate as the payload.
	for _, c := range cands {
		out = append(out, attempt{spec: p.build(c.value), payload: c.value, note: c.note})
	}
	return out
}

// pollutionAttempts sends the point's parameter twice -- the owner's value and
// a neighbour's -- in both orders, to see whether the back end resolves the
// duplicate to the smuggled value and returns that object.
func pollutionAttempts(p point) []attempt {
	victim := primaryVictim(p.kind, p.value)
	return []attempt{
		{spec: p.buildValues([]string{p.value, victim}), payload: p.value + "&" + p.name + "=" + victim, note: "duplicate parameter, self then neighbour"},
		{spec: p.buildValues([]string{victim, p.value}), payload: victim + "&" + p.name + "=" + p.value, note: "duplicate parameter, neighbour then self"},
		{spec: p.buildValues([]string{p.value, p.value, victim}), payload: victim, note: "triplicate parameter, neighbour last"},
	}
}

// arrayAttempts wraps a neighbour reference in an array or object the way a
// loose parser might unwrap it, including the NoSQL "$ne" operator that
// matches every record.
func arrayAttempts(p point) []attempt {
	victim := primaryVictim(p.kind, p.value)
	var out []attempt
	// Array-renamed parameter forms, for query and form points.
	if p.buildArrayName != nil && p.name != "" {
		out = append(out,
			attempt{spec: p.buildArrayName(p.name+"[]", victim), payload: p.name + "[]=" + victim, note: "array-bracket parameter"},
			attempt{spec: p.buildArrayName(p.name+"[0]", victim), payload: p.name + "[0]=" + victim, note: "indexed-array parameter"},
		)
	}
	// JSON-typed forms, for JSON body leaves.
	if p.buildJSON != nil {
		out = append(out,
			attempt{spec: p.buildJSON([]any{victim}), payload: "[" + victim + "]", note: "JSON array value"},
			attempt{spec: p.buildJSON(map[string]any{"$ne": nil}), payload: `{"$ne":null}`, note: "NoSQL $ne operator"},
			attempt{spec: p.buildJSON(map[string]any{"$gt": ""}), payload: `{"$gt":""}`, note: "NoSQL $gt operator"},
		)
		// A numeric reference is also tried as a JSON number, in case the app
		// only authorizes the string form.
		if n, err := strconv.ParseFloat(victim, 64); err == nil {
			out = append(out, attempt{spec: p.buildJSON(n), payload: victim + " (number)", note: "numeric type juggling"})
		}
	}
	return out
}

// suffixAttempts decorates a neighbour reference with extensions, path and
// terminator characters, and wildcards that sometimes slip past a route's
// authorization check or widen a lookup to every record.
func suffixAttempts(p point) []attempt {
	victim := primaryVictim(p.kind, p.value)
	var out []attempt
	// Each suffix is a known trick for dodging an exact-match auth rule.
	for _, suf := range []string{".json", ".xml", ".html", "/", ";", "%00"} {
		out = append(out, attempt{spec: p.build(victim + suf), payload: victim + suf, note: "neighbour with " + suf + " suffix"})
	}
	// Wildcards can turn a single-record lookup into a list of all records.
	for _, w := range []string{"*", "%"} {
		out = append(out, attempt{spec: p.build(w), payload: w, note: "wildcard value"})
	}
	return out
}

// encodingAttempts re-encodes and re-cases a neighbour reference, in case a
// decode or case-normalization step happens after the authorization check.
func encodingAttempts(p point) []attempt {
	victim := primaryVictim(p.kind, p.value)
	var out []attempt
	// A pre-encoded value is escaped again by build, yielding a double-encoded
	// reference on the wire.
	out = append(out, attempt{spec: p.build(url.QueryEscape(victim)), payload: url.QueryEscape(victim), note: "double URL-encoded neighbour"})
	// Case folding only changes hex-shaped references.
	if p.kind == kindUUID || p.kind == kindObjectID || p.kind == kindHex {
		upper := strings.ToUpper(victim)
		// Only worth sending when upper-casing actually changes the value.
		if upper != victim {
			out = append(out, attempt{spec: p.build(upper), payload: upper, note: "upper-cased neighbour"})
		}
	}
	return out
}

// runProbeModule runs one value module against every point it applies to,
// returning the findings in point order. Each point gets one negative control
// (a garbage reference), then its attempts in order; the first attempt that
// returns a distinct real object becomes the point's finding and the rest are
// skipped.
func runProbeModule(ctx context.Context, deps runDeps, m probeModule) []Finding {
	// Narrow to the points this module applies to, so the progress grid shows
	// only real work.
	var pts []point
	for _, p := range deps.points {
		if m.applies(p) {
			pts = append(pts, p)
		}
	}

	found := make([]*Finding, len(pts))
	eachPoint(deps, m.moduleMeta, pts, func(i int, pt point) int {
		// One control per point: the same point set to a reference that cannot
		// exist, so a catch-all endpoint is ruled out for every attempt.
		control := probe(ctx, deps, pt.build(garbageValue(pt.kind, pt.value)))
		controlRan := control.Err == nil
		// Try each mutation until one returns a distinct, real object.
		for _, at := range m.attempts(pt) {
			// A cancelled run stops sending further probes.
			if ctx.Err() != nil {
				break
			}
			res := probe(ctx, deps, at.spec)
			if res.Err != nil {
				continue
			}
			conf, ok := distinctObject(deps.baseline, res, control, controlRan)
			if !ok {
				continue
			}
			f := buildFinding(pt, at, res, conf, controlRan)
			found[i] = &f
			return 1
		}
		return 0
	})

	return collectFindings(found)
}

// buildFinding assembles the Finding for a reported attempt, spelling out in
// the detail exactly what was compared so the operator can judge it.
func buildFinding(pt point, at attempt, res *sendResult, confidence string, controlRan bool) Finding {
	detail := fmt.Sprintf("Changing %s to %s (%s) returned a distinct %d response of %d bytes, different from the baseline object.",
		pt.label, at.payload, at.note, res.StatusCode, len(res.Body))
	// Say whether the catch-all control ran, since that is what separates a
	// confirmed-distinct object from a bare lead.
	if controlRan {
		detail += " A control request for a non-existent reference at the same point did not return it."
	} else {
		detail += " The control request could not be fetched, so a catch-all endpoint cannot be fully ruled out."
	}
	detail += " Verify that this object belongs to another user before reporting."
	captured := res.Request
	return Finding{
		Label:      "Possible IDOR via " + pt.label,
		Detail:     detail,
		Evidence:   fmt.Sprintf("HTTP %d, %d bytes", res.StatusCode, len(res.Body)),
		Payload:    at.payload,
		Method:     res.Request.Method,
		StatusCode: res.StatusCode,
		Confidence: confidence,
		Request:    &captured,
	}
}

// runIdentityModule replays the seed request under an alternate identity for
// every identity point, confirming an IDOR when that identity receives the
// owner's object while a garbage reference under the same identity does not.
func runIdentityModule(ctx context.Context, deps runDeps, m moduleMeta, id identity) []Finding {
	pts := deps.points
	found := make([]*Finding, len(pts))
	eachPoint(deps, m, pts, func(i int, pt point) int {
		// The owner's request for this point, replayed under the alternate
		// identity: does that identity get the same object?
		attackerRes := probe(ctx, deps, applyIdentity(pt.build(pt.value), id))
		if attackerRes.Err != nil {
			return 0
		}
		// The same point set to a garbage reference under that identity, to
		// rule out an endpoint that serves one page to everyone.
		control := probe(ctx, deps, applyIdentity(pt.build(garbageValue(pt.kind, pt.value)), id))
		conf, ok := crossIdentityObject(deps.baseline, attackerRes, control, control.Err == nil)
		if !ok {
			return 0
		}
		captured := attackerRes.Request
		detail := fmt.Sprintf("Replaying the request for %s (%s) under %s returned HTTP %d of %d bytes matching the owner's object, while a non-existent reference under the same identity did not.",
			pt.label, pt.value, id.label, attackerRes.StatusCode, len(attackerRes.Body))
		found[i] = &Finding{
			Label:      "Broken object-level authorization via " + pt.label,
			Detail:     detail,
			Evidence:   fmt.Sprintf("%s got HTTP %d, %d bytes", id.label, attackerRes.StatusCode, len(attackerRes.Body)),
			Payload:    pt.value,
			Method:     attackerRes.Request.Method,
			StatusCode: attackerRes.StatusCode,
			Confidence: conf,
			Request:    &captured,
		}
		return 1
	})
	return collectFindings(found)
}

// collectFindings flattens the per-point result slice, dropping the points
// that produced nothing, in point order.
func collectFindings(found []*Finding) []Finding {
	out := []Finding{}
	for _, f := range found {
		if f != nil {
			out = append(out, *f)
		}
	}
	return out
}
