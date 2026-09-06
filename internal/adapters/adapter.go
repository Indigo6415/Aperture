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
	"github.com/Indigo6415/Aperture/internal/wordlists"
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

// Progress reports how far a running tool has gotten. total == 0 means the
// total is unknowable (e.g. feroxbuster's recursive crawling), in which
// case done is just a running counter and callers should render an
// indeterminate progress indicator instead of a percentage.
type Progress func(done, total int)

// RunMeta carries identifiers that get stamped onto every Finding an
// adapter produces.
type RunMeta struct {
	RunID  string
	NodeID string
}

// Adapter runs one external recon tool and streams its results as
// model.Finding via emit, reporting progress via progress as it goes. Run
// blocks until the tool exits, ctx is cancelled, or an unrecoverable error
// occurs.
type Adapter interface {
	Name() string
	Run(ctx context.Context, config json.RawMessage, meta RunMeta, emit Emit, progress Progress) error
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

// maxFuzzRequests bounds how many requests one ffuf/feroxbuster run may fan
// a wordlist out to (lines times extensions, plus one for the bare word).
// Both tools build their whole job set in memory before starting, so an
// oversized combination -- most commonly a large directory wordlist paired
// with a long extensions list -- can exhaust several GB of RAM before a
// single request goes out. 2,000,000 is generous for a legitimate scan
// (even a big wordlist with no/few extensions fits comfortably under it)
// while still catching the multiplicative blowups.
const maxFuzzRequests = 2_000_000

// checkFuzzRequestCount refuses a wordlist+extensions combination that would
// produce more than maxFuzzRequests requests. A failure to count the
// wordlist's lines is left non-fatal (nil, nil) -- the tool's own error
// message once it tries to open the file will be clearer than ours, and
// the caller should still be free to try.
func checkFuzzRequestCount(adapterName, wordlistPath string, extensions []string) error {
	lines, err := wordlists.CountLines(wordlistPath)
	if err != nil {
		return nil
	}
	multiplier := 1 + len(extensions)
	if total := lines * multiplier; total > maxFuzzRequests {
		return &ErrConfig{Adapter: adapterName, Err: fmt.Errorf(
			"%d requests (%d wordlist lines x %d extensions) exceeds the %d-request safety cap -- the tool builds its whole job queue in memory upfront, so this would likely exhaust available RAM; use a smaller wordlist or fewer extensions",
			total, lines, len(extensions), maxFuzzRequests,
		)}
	}
	return nil
}
