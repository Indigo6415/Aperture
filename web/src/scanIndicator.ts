import { createContext, useContext, useEffect } from 'react'
import type { ProbeSeverity } from './types'

// ScanPhase is where one scanner tab's latest run stands: never run (idle),
// still in flight (running), or finished with or without findings (done).
export type ScanPhase = 'idle' | 'running' | 'done'

// IndicatorSeverity is the worst thing a finished run found, which picks the
// border color in the case nav. callback outranks every severity, since a
// callback proves the finding; info-only results carry no severity at all.
export type IndicatorSeverity = 'low' | 'medium' | 'high' | 'critical' | 'callback'

// ScanIndicator is one scanner tab's state as the case nav shows it.
export interface ScanIndicator {
  phase: ScanPhase
  severity: IndicatorSeverity | null
}

export const IDLE_INDICATOR: ScanIndicator = { phase: 'idle', severity: null }

// SEVERITY_RANK orders the severities so the worst one can be picked with a
// single comparison.
const SEVERITY_RANK: Record<IndicatorSeverity, number> = { low: 1, medium: 2, high: 3, critical: 4, callback: 5 }

// INDICATOR_COLOR is the border color for each state. The callback purple
// matches the CALLBACK tag on finding rows (see FindingBadges.tsx).
export const INDICATOR_COLOR: Record<'running' | 'clean' | IndicatorSeverity, string> = {
  running: '#4ade80', // green-400: the bar sweeping around a running tab
  clean: '#22c55e', // green-500: finished with nothing worth a look
  low: '#facc15', // yellow-400
  medium: '#fb923c', // orange-400
  high: '#ef4444', // red-500
  critical: '#b91c1c', // red-700: the darker red
  callback: '#d946ef', // fuchsia-500: the CALLBACK tag's purple
}

// BADGE_LABEL is the short word a finished tab's badge shows for its result.
export const BADGE_LABEL: Record<'clean' | IndicatorSeverity, string> = {
  clean: 'Done',
  low: 'Low',
  medium: 'Med',
  high: 'High',
  critical: 'Crit',
  callback: 'Callback',
}

// IndicatorModule is the slice of a check module the indicator reads. Each
// finding is typed loosely because scanners' finding shapes differ; only an
// optional callback flag is read off them.
export interface IndicatorModule {
  severity: ProbeSeverity
  findings: readonly unknown[]
}

// worseSeverity returns whichever of a and b ranks higher, treating null as
// "nothing found yet".
export function worseSeverity(a: IndicatorSeverity | null, b: IndicatorSeverity | null): IndicatorSeverity | null {
  if (a === null) return b
  if (b === null) return a
  return SEVERITY_RANK[b] > SEVERITY_RANK[a] ? b : a
}

// severityOfModules returns the worst severity among the modules that have
// findings. A module whose findings include a callback counts as callback
// no matter its own severity; info-only modules count for nothing.
export function severityOfModules(modules: readonly IndicatorModule[]): IndicatorSeverity | null {
  let worst: IndicatorSeverity | null = null
  for (const m of modules) {
    // A module that found nothing contributes nothing to the border.
    if (m.findings.length === 0) continue
    const callback = m.findings.some((f) => (f as { callback?: boolean }).callback === true)
    const severity: IndicatorSeverity | null = callback ? 'callback' : m.severity === 'info' ? null : m.severity
    worst = worseSeverity(worst, severity)
  }
  return worst
}

// severityOfName maps a plain severity string (such as a nuclei finding's)
// onto the indicator's severities, returning null for anything else.
export function severityOfName(name: string | undefined): IndicatorSeverity | null {
  switch (name) {
    case 'low':
    case 'medium':
    case 'high':
    case 'critical':
      return name
    default:
      return null
  }
}

// indicatorOfScans reads one scanner tab's per-target scans: running while any
// target is still in flight, otherwise done with the worst severity any target
// found. modulesOf pulls a target's check modules out of its scan.
export function indicatorOfScans<S extends { status: string }>(scans: Record<string, S>, modulesOf: (scan: S) => readonly IndicatorModule[]): ScanIndicator {
  let phase: ScanPhase = 'idle'
  let severity: IndicatorSeverity | null = null
  for (const scan of Object.values(scans)) {
    // Any target still running means the tab is running, whatever the others did.
    if (scan.status === 'running') return { phase: 'running', severity: null }
    phase = 'done'
    severity = worseSeverity(severity, severityOfModules(modulesOf(scan)))
  }
  return { phase, severity }
}

// ScanIndicatorReporter is what a scanner tab calls to publish its indicator,
// keyed by the tab's id.
export type ScanIndicatorReporter = (key: string, indicator: ScanIndicator) => void

// ScanIndicatorContext hands the case nav's reporter down to every scanner
// tab inside it. The default does nothing, so a scanner rendered outside a
// case still works.
export const ScanIndicatorContext = createContext<ScanIndicatorReporter>(() => {})

// useReportScanIndicator publishes one tab's indicator to the case nav. It only
// re-reports when the phase or severity actually changes, so a caller can pass
// a freshly built indicator on every render.
export function useReportScanIndicator(key: string, indicator: ScanIndicator): void {
  const report = useContext(ScanIndicatorContext)
  const { phase, severity } = indicator
  useEffect(() => {
    report(key, { phase, severity })
  }, [report, key, phase, severity])
}
