package adapters

import (
	"context"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/fingerprint"
	"github.com/Indigo6415/Aperture/internal/netgov"
)

// catchAllTimeout bounds each probe request made to build a host's profile.
const catchAllTimeout = 8 * time.Second

// catchAllBase returns the part of a fuzzing URL that precedes FUZZ, which is
// where random nonexistent names are probed. A URL without FUZZ is returned
// unchanged.
func catchAllBase(rawURL string) string {
	if i := strings.Index(rawURL, "FUZZ"); i >= 0 {
		return rawURL[:i]
	}
	return rawURL
}

// buildCatchAll returns the catch-all profile for the path a fuzzer is about
// to walk, or nil when no profile can be built. Vhost runs (FUZZ in a header)
// are not profiled here, because their calibration is already handled by the
// tool's own autocalibration on the Host header.
func buildCatchAll(ctx context.Context, base string, headers map[string]string) *fingerprint.Profile {
	base = strings.TrimRight(catchAllBase(base), "/")
	if base == "" || strings.Contains(base, "FUZZ") {
		return nil
	}
	client := netgov.NewClient(catchAllTimeout, false)
	profile, err := fingerprint.BuildProfile(ctx, client, base, headers)
	if err != nil {
		return nil
	}
	return profile
}
