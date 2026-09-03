// Package webui embeds the built frontend (web/, output configured to
// land directly in dist/ here) into the aperture binary, so `go build`
// produces a single static executable with no separate assets to ship.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var distFS embed.FS

// FS returns the embedded frontend build rooted at dist/, so paths match
// what an HTTP file server expects ("index.html", "assets/...", ...).
func FS() fs.FS {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic(err) // dist is embedded at compile time; only a broken embed directive can cause this
	}
	return sub
}
