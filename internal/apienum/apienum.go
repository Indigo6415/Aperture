// Package apienum is Aperture's API enumerator: pointed at a target, it
// finds API endpoints through every source a real operator would check --
// an OpenAPI/Swagger spec when one is exposed, GraphQL introspection, a
// same-origin crawl, the JS bundles that crawl turns up (mined for
// fetch/axios/XHR calls and API-shaped string literals), and a wordlist
// brute force of common API path segments -- then characterizes each route
// it finds (which HTTP methods it actually accepts, whether it requires
// auth, what content types it'll parse, roughly what its response looks
// like) and enumerates its parameters well enough to flag the ones worth a
// closer look.
//
// This package deliberately stops at flagging: it never fires an actual
// injection payload. A flagged parameter becomes an InjectionPoint on
// Result -- staged for the operator to review and hand to another tool
// (Tester, SQLi/XSS/SSTI scanners, ...) or export into a case target list
// (see internal/api/handlers_apienum.go's saveCaseScan and the frontend's
// "save to list" handoff), never auto-attacked here. Every request this
// package issues is a GET/OPTIONS/HEAD or a harmless method-probe/content-
// type-negotiation request -- nothing destructive, nothing that mutates
// state on the target. See bypass403's package doc for the same
// "authorized-testing tooling" posture this package follows.
package apienum

import (
	"github.com/Indigo6415/Aperture/internal/probescan"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
)

// Target and ResolveTarget are probescan's own -- an API enum run starts
// from exactly the same "URL, hostname, or IP" input every other scanner
// here does. Aliased rather than re-exported as a fresh type for the same
// reason domainscan.Target is (see its own doc comment): no import of
// probescan has to leak into every call site, including the WebSocket
// events in internal/api.
type Target = probescan.Target

var ResolveTarget = probescan.ResolveTarget

// ParamLocation is where in a request a parameter was found or could be
// placed.
type ParamLocation string

const (
	LocationQuery  ParamLocation = "query"
	LocationBody   ParamLocation = "body"
	LocationHeader ParamLocation = "header"
	LocationPath   ParamLocation = "path"
)

// Param is one parameter enumerated for a route -- from a parsed spec, from
// JS mining (a body's JSON.stringify keys, a query string template
// literal), or from a known-header probe (X-Forwarded-For, X-Api-Key, ...).
// Flagged/Reason is the injection-point heuristic: Flagged means this
// parameter is interesting enough to stage as an InjectionPoint, Reason is
// the cheap, human-readable justification ("ID-shaped", "reflected in
// response", "file-path-shaped", ...) rather than an undifferentiated dump
// of every parameter a route happens to take.
type Param struct {
	Name      string        `json:"name"`
	Location  ParamLocation `json:"location"`
	TypeGuess string        `json:"typeGuess"` // numeric-id | uuid | boolean | file-path | free-text
	Sample    string        `json:"sample,omitempty"`
	Flagged   bool          `json:"flagged"`
	Reason    string        `json:"reason,omitempty"`
}

// MethodProbe is one HTTP method's own characterization against a route:
// whether the server actually accepts it (as opposed to 404/405/501-ing),
// and a rough fingerprint of what it sent back.
type MethodProbe struct {
	Method     string `json:"method"`
	Allowed    bool   `json:"allowed"`
	StatusCode int    `json:"statusCode"`
	// ContentType/BodyShape/ResponseBytes are the response-shape fingerprint
	// -- enough for the UI to show more than a bare status code (see the
	// package doc's "response shape fingerprinting" goal) without the
	// overhead of keeping a full body around for every method on every
	// route.
	ContentType   string `json:"contentType,omitempty"`
	BodyShape     string `json:"bodyShape,omitempty"` // object | array | empty | text | binary
	ResponseBytes int    `json:"responseBytes"`
}

// AuthProbe is one route's auth-requirement signal: the status code a
// request with no credentials at all got back, and -- only when the run
// was given a credential to test with -- the status code an authenticated
// request got back alongside it. RequiresAuth is the derived verdict a
// caller can render directly rather than re-deriving it from the two codes
// every time.
type AuthProbe struct {
	UnauthenticatedStatus int  `json:"unauthenticatedStatus"`
	AuthenticatedStatus   *int `json:"authenticatedStatus,omitempty"`
	RequiresAuth          bool `json:"requiresAuth"`
}

// Route is one discovered endpoint, method-agnostic (MethodProbe is where
// the per-method detail lives) -- Confirmed/Source is what lets the UI
// split "confirmed" routes (an actual clean fetch returned something) from
// the "uncertain/needs verification" bucket a brute-forced or JS-mined path
// lands in until something confirms it's real (see the package doc's
// display goals).
type Route struct {
	ID    string `json:"id"`
	Path  string `json:"path"`
	Group string `json:"group"` // base path this route trees under in the UI, e.g. "/api/v1"
	// Source is where this route was first discovered: "spec" (OpenAPI/
	// Swagger), "graphql", "crawl" (an actual link/form on the site),
	// "js" (mined from a downloaded script), or "bruteforce" (a wordlist
	// guess that got a non-404 response).
	Source    string        `json:"source"`
	Confirmed bool          `json:"confirmed"`
	Methods   []MethodProbe `json:"methods"`
	Auth      AuthProbe     `json:"auth"`
	Params    []Param       `json:"params"`
	// ContentTypesAccepted is content-type negotiation's own result: which
	// of application/json, application/x-www-form-urlencoded, and
	// application/xml a write method on this route didn't reject outright
	// (see the package doc's "content-type negotiation" goal) -- an XML
	// accept here is the signal worth a closer look for XXE.
	ContentTypesAccepted []string          `json:"contentTypesAccepted,omitempty"`
	RateLimitHeaders     map[string]string `json:"rateLimitHeaders,omitempty"`
	// Paginated is a cheap heuristic: true when a response (or this
	// route's own query string, as mined from JS) carries a
	// page/limit/offset/cursor-shaped field.
	Paginated bool `json:"paginated,omitempty"`
}

// InjectionPoint is one flagged parameter staged for the operator to pick
// up manually -- the package's core "set these aside, don't auto-attack
// them" deliverable. Carries enough context (location, type guess, a
// sample value, why it was flagged) to be actionable on its own, whether
// the operator reads it here or exports it into a case target list (see
// internal/api/handlers_apienum.go).
type InjectionPoint struct {
	Endpoint  string        `json:"endpoint"`
	Method    string        `json:"method"`
	Param     string        `json:"param"`
	Location  ParamLocation `json:"location"`
	TypeGuess string        `json:"typeGuess"`
	Sample    string        `json:"sample,omitempty"`
	Reason    string        `json:"reason"`
}

// SchemaInfo is the outcome of checking for an exposed OpenAPI/Swagger
// spec -- the highest-signal source when present (see the package doc),
// found at all or not, and however many routes parsing it directly
// contributed.
type SchemaInfo struct {
	Found      bool   `json:"found"`
	Kind       string `json:"kind"` // openapi | swagger
	URL        string `json:"url"`
	RouteCount int    `json:"routeCount"`
}

// GraphQLSummary is the outcome of probing for a GraphQL endpoint and, when
// found, attempting introspection -- deliberately lightweight compared to
// internal/graphqlenum's own full schema recovery and misconfiguration
// battery: this package only needs enough to list queries/mutations as
// routes and point the operator at the dedicated GraphQL Enumeration tool
// for the deep dive.
type GraphQLSummary struct {
	Found           bool     `json:"found"`
	URL             string   `json:"url"`
	IntrospectionOn bool     `json:"introspectionOn"`
	TypeCount       int      `json:"typeCount,omitempty"`
	Queries         []string `json:"queries,omitempty"`
	Mutations       []string `json:"mutations,omitempty"`
}

// Stats summarizes one run for a header/summary line -- every number here
// is also derivable from Routes/InjectionPoints, but computed once so the
// UI (and the case-scan summary persisted in handlers_apienum.go) doesn't
// have to re-walk the full route list just to show a count.
type Stats struct {
	RoutesFound     int `json:"routesFound"`
	ConfirmedRoutes int `json:"confirmedRoutes"`
	UncertainRoutes int `json:"uncertainRoutes"`
	RequestsSent    int `json:"requestsSent"`
	InjectionPoints int `json:"injectionPoints"`
}

// Result is one run's full output.
type Result struct {
	Target          *Target          `json:"target"`
	Schema          *SchemaInfo      `json:"schema,omitempty"`
	GraphQL         *GraphQLSummary  `json:"graphql,omitempty"`
	Routes          []Route          `json:"routes"`
	InjectionPoints []InjectionPoint `json:"injectionPoints"`
	Stats           Stats            `json:"stats"`
}

// Options tunes a run beyond the target itself.
type Options struct {
	// Concurrency bounds how many requests this run has in flight at once.
	Concurrency int
	// RateLimit caps requests/sec across the whole run -- the "doesn't look
	// like/behave like a DoS against the target" guardrail the package doc
	// calls for. 0 means unlimited; see handlers_apienum.go for where a
	// non-zero floor gets applied by default.
	RateLimit int
	// Headers are applied to every request as the "authenticated" side of
	// each auth-requirement probe (e.g. a saved credential's Authorization/
	// Cookie) -- every other request this run makes (crawling, brute
	// forcing, the unauthenticated half of an auth probe) deliberately
	// omits them.
	Headers map[string]string
	// CrawlDepth/MaxPages tune the same-origin crawl that seeds JS mining --
	// see crawl.go.
	CrawlDepth int
	MaxPages   int
	// ExtraWordlist adds caller-supplied path segments to the bundled
	// default wordlist brute force draws from (see wordlist.go) -- e.g. a
	// wordlist the operator has already downloaded/curated for this target.
	ExtraWordlist []string
	// Progress, when set, receives one check per module as it starts and
	// finishes. Nil means nobody is watching.
	Progress scanprogress.Reporter `json:"-"`
}
