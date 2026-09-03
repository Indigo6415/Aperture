// Package adapters wraps external recon tools (ffuf, feroxbuster, ...) as
// subprocesses and normalizes their native output into model.Finding. This
// is the only layer that knows about tool-specific flags/output formats --
// everything above it (engine, filters, API, UI) only ever sees Finding.
package adapters

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/Indigo6415/Aperture/internal/model"
)

// newFindingID generates a random 128-bit hex identifier for a Finding.
func newFindingID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Emit is called once per Finding as it is produced by a running tool, so
// callers can stream partial results downstream instead of waiting for the
// scan to finish.
type Emit func(model.Finding)

// RunMeta carries identifiers that get stamped onto every Finding an
// adapter produces.
type RunMeta struct {
	RunID  string
	NodeID string
}

// Adapter runs one external recon tool and streams its results as
// model.Finding via emit. Run blocks until the tool exits, ctx is
// cancelled, or an unrecoverable error occurs.
type Adapter interface {
	Name() string
	Run(ctx context.Context, config json.RawMessage, meta RunMeta, emit Emit) error
}

// Registry maps a node type name to the adapter that implements it.
var Registry = map[string]Adapter{}

func register(a Adapter) {
	Registry[a.Name()] = a
}

// ErrConfig wraps a config-decoding/validation failure so callers can
// distinguish "bad node config" from "tool execution failed".
type ErrConfig struct {
	Adapter string
	Err     error
}

func (e *ErrConfig) Error() string {
	return fmt.Sprintf("%s: invalid config: %v", e.Adapter, e.Err)
}

func (e *ErrConfig) Unwrap() error { return e.Err }
