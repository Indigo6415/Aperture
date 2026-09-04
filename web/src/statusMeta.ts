import type { NodeStatus } from './types'

export const STATUS_META: Record<NodeStatus, { label: string; dot: string }> = {
  pending: { label: 'Pending', dot: '#6b7280' },
  running: { label: 'Running', dot: '#facc15' },
  succeeded: { label: 'Done', dot: '#34d399' },
  failed: { label: 'Failed', dot: '#f87171' },
  cancelled: { label: 'Cancelled', dot: '#9ca3af' },
}
