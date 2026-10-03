package domainscan

import "github.com/Indigo6415/Aperture/internal/probescan"

// Target and ResolveTarget are probescan's own -- a domain scan starts from
// exactly the same "URL, hostname, or IP" input probe does, so there's no
// reason to duplicate its parsing/scheme-defaulting/IP-resolution logic
// (see probescan/target.go). Aliased rather than re-exported as a fresh
// type so callers (and the WebSocket events in internal/api) can use
// *domainscan.Target without an import of probescan leaking into every
// call site.
type Target = probescan.Target

var ResolveTarget = probescan.ResolveTarget
