import type { ProbeSeverity } from './types'

// SEVERITY_META is Probe's counterpart to statusMeta.ts's STATUS_META --
// one consistent color/label per severity, reused by the summary tiles,
// module section headers, and per-finding badges in Probe.tsx.
export const SEVERITY_META: Record<ProbeSeverity, { label: string; dot: string; text: string; badge: string; border: string }> = {
  critical: { label: 'Critical', dot: '#f87171', text: 'text-red-400', badge: 'border-red-700 bg-red-950/60 text-red-300', border: 'border-l-red-500' },
  high: { label: 'High', dot: '#fb923c', text: 'text-orange-400', badge: 'border-orange-700 bg-orange-950/60 text-orange-300', border: 'border-l-orange-500' },
  medium: { label: 'Medium', dot: '#facc15', text: 'text-amber-400', badge: 'border-amber-700 bg-amber-950/60 text-amber-300', border: 'border-l-amber-500' },
  low: { label: 'Low', dot: '#34d399', text: 'text-emerald-400', badge: 'border-emerald-700 bg-emerald-950/60 text-emerald-300', border: 'border-l-emerald-500' },
  info: { label: 'Info', dot: '#38bdf8', text: 'text-sky-400', badge: 'border-sky-700 bg-sky-950/60 text-sky-300', border: 'border-l-sky-500' },
}

export const SEVERITY_ORDER: ProbeSeverity[] = ['critical', 'high', 'medium', 'low', 'info']
