// theme.ts is Aperture's whole theming layer: which themes/modes exist,
// which are active, and how that choice gets applied/persisted. Theme
// (palette) and Mode (light/dark) are two independent choices -- every
// palette below supports both -- applied as two separate attributes on
// <html> (data-theme, data-mode). The palettes themselves are plain CSS,
// keyed off those attributes -- see index.css's `[data-theme="..."]
// [data-mode="..."]` blocks, which remap the neutral-*/sky-* Tailwind
// utility classes the rest of the app is built from. Keeping the mapping in
// CSS (rather than, say, swapping Tailwind class names at render time) means
// no component has to know themes exist at all.
export type Theme = 'default' | 'professional' | 'burp' | 'hacker' | 'prussian-amber' | 'teal-slate' | 'linen-sun' | 'stone-almond'
export type Mode = 'light' | 'dark'

export interface ThemeMeta {
  id: Theme
  label: string
  description: string
}

// THEMES lists every palette in the order the picker shows them -- 'default'
// is first since it's the app's original look (see index.css: its dark
// block matches Tailwind's own palette exactly, so only its light block is
// actually a departure from how the app always looked).
export const THEMES: ThemeMeta[] = [
  { id: 'default', label: 'Default', description: "Aperture's original palette" },
  { id: 'professional', label: 'Professional', description: 'Muted corporate blue' },
  { id: 'burp', label: 'Burp Suite', description: "Burp's gray-and-orange palette" },
  { id: 'hacker', label: 'Hacker', description: 'Green-on-black terminal palette' },
  { id: 'prussian-amber', label: 'Prussian Amber', description: 'Navy blue with an amber accent' },
  { id: 'teal-slate', label: 'Teal Slate', description: 'Slate gray with a teal accent' },
  { id: 'linen-sun', label: 'Linen Sun', description: 'Warm linen with a sunflower accent' },
  { id: 'stone-almond', label: 'Stone Almond', description: 'Earthy stone and almond tones' },
]

const THEME_STORAGE_KEY = 'aperture.theme'
const MODE_STORAGE_KEY = 'aperture.mode'
const DEFAULT_THEME: Theme = 'default'
const DEFAULT_MODE: Mode = 'dark'

function isTheme(value: string | null): value is Theme {
  return value !== null && THEMES.some((t) => t.id === value)
}

function isMode(value: string | null): value is Mode {
  return value === 'light' || value === 'dark'
}

// readStored centralizes the try/catch every localStorage read below needs
// -- private browsing, blocked site data, or a full storage quota all throw
// rather than just returning null, and a cosmetic preference is never worth
// crashing the app over.
function readStored<T extends string>(key: string, isValid: (v: string | null) => v is T, fallback: T): T {
  try {
    const stored = localStorage.getItem(key)
    return isValid(stored) ? stored : fallback
  } catch {
    return fallback
  }
}

export function getStoredTheme(): Theme {
  return readStored(THEME_STORAGE_KEY, isTheme, DEFAULT_THEME)
}

export function getStoredMode(): Mode {
  return readStored(MODE_STORAGE_KEY, isMode, DEFAULT_MODE)
}

// applyTheme sets the <html> attribute every themed CSS rule keys off of,
// and persists the choice for next load. Called once at startup (see
// main.tsx) with whatever getStoredTheme()/getStoredMode() return, and again
// any time the user picks a new palette or toggles light/dark in Settings.
export function applyTheme(theme: Theme) {
  document.documentElement.setAttribute('data-theme', theme)
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme)
  } catch {
    // Same as readStored -- a failed save just means the choice won't
    // survive a reload, not a reason to throw.
  }
}

// applyMode is applyTheme's counterpart for the light/dark toggle -- kept as
// a separate function (rather than folding mode into applyTheme) because the
// two are genuinely independent controls in the UI (see Settings.tsx's
// ThemePicker/ModeToggle) and are read/written independently everywhere else
// too.
export function applyMode(mode: Mode) {
  document.documentElement.setAttribute('data-mode', mode)
  try {
    localStorage.setItem(MODE_STORAGE_KEY, mode)
  } catch {
    // See applyTheme.
  }
}
