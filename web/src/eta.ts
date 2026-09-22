// estimateEtaSeconds derives a remaining-time estimate from a steady
// completion rate since startedAt (ms epoch) -- null when there isn't
// enough signal yet to trust it (no known total, no progress, or too
// little elapsed time for the rate to mean anything).
export function estimateEtaSeconds(done: number, total: number, startedAt: number | null): number | null {
  if (total <= 0 || done <= 0 || startedAt === null) return null
  const elapsedSeconds = (Date.now() - startedAt) / 1000
  if (elapsedSeconds < 2) return null
  const rate = done / elapsedSeconds
  if (rate <= 0) return null
  const remaining = total - done
  return remaining > 0 ? remaining / rate : 0
}

// formatEta renders a seconds count as a short human string.
export function formatEta(seconds: number): string {
  return `~${formatDuration(seconds)}`
}

// formatDuration renders a seconds count as a short human string with no
// "approximately" tilde -- for an already-elapsed duration (e.g. how long a
// node has been running) rather than an estimate of time remaining.
export function formatDuration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds))
  if (s < 60) return `${s}s`
  const totalMinutes = Math.round(s / 60)
  if (totalMinutes < 60) return `${totalMinutes}m`
  const hours = Math.floor(totalMinutes / 60)
  const minutes = totalMinutes % 60
  return minutes > 0 ? `${hours}h ${minutes}m` : `${hours}h`
}
