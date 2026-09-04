package engine

// Preset names for per-scan tuning. "custom" (or "") means every field on
// ScanOptions is taken literally, with zero meaning "use the tool's own
// default" -- the same as before per-scan tuning existed.
const (
	PresetAggressive = "aggressive"
	PresetStealth    = "stealth"
	PresetCustom     = "custom"
)

// ScanOptions is the per-scan tuning a scan can be started with, instead of
// only the engine-wide defaults previously baked into buildContentDiscoveryFlow
// etc.: thread count, per-request timeout, wordlist choice, and a rate
// limit, plus an "aggressive"/"stealth" preset shorthand for the first
// three. It's stored as opaque JSON on store.Scan and threaded through
// every flow-builder in api/handlers_scan.go.
type ScanOptions struct {
	Preset         string `json:"preset,omitempty"`
	Threads        int    `json:"threads,omitempty"`
	TimeoutSeconds int    `json:"timeoutSeconds,omitempty"`
	RateLimit      int    `json:"rateLimit,omitempty"` // requests/sec across the whole run; 0 = unlimited
	Wordlist       string `json:"wordlist,omitempty"`  // explicit wordlist filename, overriding the usual category-tag selection
}

// presetDefaults backs each preset's Threads/TimeoutSeconds/RateLimit --
// aggressive favors speed (many threads, a rate limit doesn't help attacker
// stealth so it's left unlimited), stealth favors staying under the radar
// (few threads, a generous per-request timeout, and a capped rate).
var presetDefaults = map[string]ScanOptions{
	PresetAggressive: {Threads: 80, TimeoutSeconds: 5, RateLimit: 0},
	PresetStealth:    {Threads: 3, TimeoutSeconds: 15, RateLimit: 5},
}

// Resolved fills in any field the caller left at its zero value from o's
// preset, so picking "aggressive" and overriding just Threads doesn't
// require also spelling out TimeoutSeconds/RateLimit. Wordlist is never
// preset-driven -- it either names an explicit file or is left for the
// caller's own category-based fallback.
func (o ScanOptions) Resolved() ScanOptions {
	preset := presetDefaults[o.Preset]
	if o.Threads == 0 {
		o.Threads = preset.Threads
	}
	if o.TimeoutSeconds == 0 {
		o.TimeoutSeconds = preset.TimeoutSeconds
	}
	if o.RateLimit == 0 {
		o.RateLimit = preset.RateLimit
	}
	return o
}
