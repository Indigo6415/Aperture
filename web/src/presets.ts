import type { JobOptionsPreset } from './types'

// JOB_PRESETS is the shared stealth/normal/aggressive spectrum offered by
// every launcher that accepts a JobOptionsPreset -- CaseView's Directory/
// Subdomain/VHost/FFuF tabs and Probe's scan launcher both render this same
// list rather than keeping their own copies in sync by hand.
export const JOB_PRESETS: { id: JobOptionsPreset; label: string; description: string }[] = [
  { id: 'custom', label: 'Default', description: 'Engine defaults (balanced speed).' },
  { id: 'stealth', label: 'Stealth', description: 'Few threads, longer timeout, rate-limited — slower, quieter.' },
  { id: 'normal', label: 'Normal', description: 'Balanced thread count and timeout — a reasonable middle ground.' },
  { id: 'aggressive', label: 'Aggressive', description: 'Many threads, short timeout, no rate limit — fastest, loudest.' },
]
