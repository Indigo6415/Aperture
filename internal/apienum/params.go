package apienum

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	uuidPattern    = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	filePathHint   = regexp.MustCompile(`(?i)(file|path|dir|folder|upload|doc|attachment|template|include)`)
	queryLikeHint  = regexp.MustCompile(`(?i)(query|filter|sort|order|search|where|q$|expr|cmd|command)`)
	idHint         = regexp.MustCompile(`(?i)(^id$|_id$|^id_|id$|uuid|guid|key$|token|ref$|code$)`)
	redirectHint   = regexp.MustCompile(`(?i)(url|redirect|return|callback|next|target|dest|continue)`)
	paginationHint = regexp.MustCompile(`(?i)^(page|per_page|perpage|limit|offset|cursor|skip|size)$`)
)

// guessType infers a parameter's shape from its name and (when available) a
// sample value actually observed on the wire -- a cheap heuristic, not a
// schema, but enough to make the injection-point list say something more
// useful than "string" for every entry (see the package doc's "parameter
// type guesses" goal).
func guessType(name, sample string) string {
	switch {
	case uuidPattern.MatchString(sample):
		return "uuid"
	case sample != "" && isNumeric(sample):
		return "numeric-id"
	case sample == "true" || sample == "false":
		return "boolean"
	case filePathHint.MatchString(name):
		return "file-path"
	case idHint.MatchString(name):
		return "id-shaped"
	default:
		return "free-text"
	}
}

func isNumeric(s string) bool {
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}

// flagParam decides whether p is worth staging as an injection point and,
// if so, fills in Flagged/Reason -- the heuristic behind the package doc's
// "even a cheap heuristic beats an undifferentiated dump" goal. Order
// matters: the first matching reason wins, roughly most-to-least
// actionable (an open-redirect-shaped param first since that's a single
// clear vuln class, then ID-shaped since that's the core BOLA/IDOR signal,
// then the broader free-text/query-context catch-alls).
func flagParam(p Param) Param {
	if p.TypeGuess == "" {
		p.TypeGuess = guessType(p.Name, p.Sample)
	}
	name := p.Name
	switch {
	case redirectHint.MatchString(name):
		p.Flagged, p.Reason = true, "redirect/URL-shaped parameter -- open redirect / SSRF candidate"
	case filePathHint.MatchString(name) || p.TypeGuess == "file-path":
		p.Flagged, p.Reason = true, "file-path-shaped parameter -- path traversal / LFI candidate"
	case p.TypeGuess == "numeric-id" || p.TypeGuess == "uuid" || p.TypeGuess == "id-shaped":
		p.Flagged, p.Reason = true, "ID-shaped parameter -- BOLA/IDOR candidate"
	case queryLikeHint.MatchString(name):
		p.Flagged, p.Reason = true, "used in a query/filter-like context -- injection candidate"
	case p.Location == LocationBody || p.Location == LocationQuery:
		p.Flagged, p.Reason = true, "free-text input -- generic injection candidate"
	default:
		p.Flagged = false
	}
	return p
}

// mergeParams folds additions into existing, deduplicating by name+location
// (the same query param declared on both a path item and its GET operation
// in a spec, for instance) and preferring whichever copy already carries a
// sample value.
func mergeParams(existing, additions []Param) []Param {
	index := make(map[string]int, len(existing))
	for i, p := range existing {
		index[string(p.Location)+":"+p.Name] = i
	}
	for _, p := range additions {
		key := string(p.Location) + ":" + p.Name
		if i, ok := index[key]; ok {
			if existing[i].Sample == "" && p.Sample != "" {
				existing[i].Sample = p.Sample
			}
			continue
		}
		index[key] = len(existing)
		existing = append(existing, p)
	}
	return existing
}

// pathGroup is the base path a route trees under in the UI's grouped view
// -- the first two path segments (e.g. "/api/v1" for "/api/v1/users/{id}"),
// or just "/" for a bare root/one-segment path. Deliberately coarse: a
// third segment's worth of grouping would mean a group per resource rather
// than per API surface, which is finer than the tree view needs.
func pathGroup(path string) string {
	trimmed := strings.TrimPrefix(path, "/")
	if trimmed == "" {
		return "/"
	}
	segments := strings.Split(trimmed, "/")
	return "/" + strings.Join(segments[:min(2, len(segments))], "/")
}

// collectInjectionPoints walks every characterized route's flagged
// parameters into the flat InjectionPoint list Result carries -- one entry
// per flagged param per method the route accepts it on, since the same
// query param can behave differently (or matter differently) depending on
// the method it rides with.
func collectInjectionPoints(routes []Route) []InjectionPoint {
	var out []InjectionPoint
	for _, r := range routes {
		methods := r.Methods
		if len(methods) == 0 {
			// A route characterization found no allowed method at all still
			// keeps its originally-observed method (GET, almost always) for
			// the injection point's own record -- better than silently
			// dropping a flagged parameter because every method probe 404'd.
			methods = []MethodProbe{{Method: "GET"}}
		}
		for _, p := range r.Params {
			if !p.Flagged {
				continue
			}
			for _, m := range methods {
				if !m.Allowed && len(r.Methods) > 0 {
					continue
				}
				out = append(out, InjectionPoint{
					Endpoint: r.Path, Method: m.Method, Param: p.Name,
					Location: p.Location, TypeGuess: p.TypeGuess, Sample: p.Sample, Reason: p.Reason,
				})
			}
		}
	}
	return out
}

// isPaginationField reports whether name looks like a pagination control
// (page/limit/offset/cursor/...) -- used both on query params mined from
// JS and on top-level JSON response field names, feeding Route.Paginated.
func isPaginationField(name string) bool {
	return paginationHint.MatchString(strings.ToLower(name))
}
