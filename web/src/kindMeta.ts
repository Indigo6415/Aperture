import type { NodeKind, NodeStatus } from './types'

export const KIND_META: Record<NodeKind, { label: string; accent: string; icon: string; summary: (c: Record<string, unknown>) => string }> = {
  ffuf: {
    label: 'ffuf',
    accent: '#f97316',
    icon: '⚡',
    summary: (c) => (c.url as string) || 'no target set',
  },
  feroxbuster: {
    label: 'Feroxbuster',
    accent: '#eab308',
    icon: '🦊',
    summary: (c) => (c.url as string) || 'no target set',
  },
  filter: {
    label: 'Filter',
    accent: '#38bdf8',
    icon: '⏳',
    summary: (c) => {
      const parts: string[] = []
      if (Array.isArray(c.statusCodes) && c.statusCodes.length) parts.push(`status ${(c.statusCodes as number[]).join(',')}`)
      if (c.urlRegex) parts.push(`/${c.urlRegex}/`)
      return parts.length ? parts.join(' · ') : 'no constraints'
    },
  },
  merge: {
    label: 'Merge',
    accent: '#a78bfa',
    icon: '⑃',
    summary: (c) => (c.dedup ? 'dedup on' : 'dedup off'),
  },
  table: {
    label: 'Table',
    accent: '#34d399',
    icon: '▤',
    summary: () => 'live results',
  },
  export: {
    label: 'Export',
    accent: '#f472b6',
    icon: '⇩',
    summary: (c) => ((c.path as string) ? `${c.format || 'json'} → ${c.path}` : 'no path set'),
  },
}

export const STATUS_META: Record<NodeStatus, { label: string; dot: string }> = {
  pending: { label: 'Pending', dot: '#6b7280' },
  running: { label: 'Running', dot: '#facc15' },
  succeeded: { label: 'Done', dot: '#34d399' },
  failed: { label: 'Failed', dot: '#f87171' },
}
