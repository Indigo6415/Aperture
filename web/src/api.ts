import type {
  Finding,
  Run,
  RunEvent,
  Scan,
  ScanEvent,
  ScanKind,
  ScanOptions,
  ScanRun,
  ScanRunStartResult,
  ScanSummary,
  ScreenshotMeta,
  ToolInfo,
  WordlistCatalogEntry,
  WordlistCategory,
  WordlistInfo,
} from './types'

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    headers: init?.body ? { 'Content-Type': 'application/json' } : undefined,
    ...init,
  })
  if (!res.ok) {
    const body = await res.text()
    throw new Error(`${res.status} ${res.statusText}: ${body}`)
  }
  if (res.status === 204) return undefined as T
  return res.json() as Promise<T>
}

export const api = {
  listTools: () => req<ToolInfo[]>('/api/tools'),

  getRun: (runId: string) => req<Run>(`/api/runs/${runId}`),
  listFindings: (runId: string, nodeId?: string) =>
    req<Finding[]>(`/api/runs/${runId}/findings${nodeId ? `?nodeId=${encodeURIComponent(nodeId)}` : ''}`),

  startScan: (domain: string, options?: ScanOptions) =>
    req<{ scanId: string }>('/api/scan', { method: 'POST', body: JSON.stringify({ domain, options }) }),
  listScans: () => req<ScanSummary[]>('/api/scans'),
  getScan: (id: string) => req<Scan>(`/api/scans/${id}`),
  listScanRuns: (scanId: string) => req<ScanRun[]>(`/api/scans/${scanId}/runs`),
  runContentDiscovery: (scanId: string, targets: string[]) =>
    req<ScanRunStartResult>(`/api/scans/${scanId}/content-discovery`, { method: 'POST', body: JSON.stringify({ targets }) }),
  restartScan: (scanId: string) => req<{ scanId: string }>(`/api/scans/${scanId}/restart`, { method: 'POST' }),
  cancelScan: (scanId: string) => req<void>(`/api/scans/${scanId}/cancel`, { method: 'POST' }),
  restartScanRun: (scanId: string, kind: ScanKind, targets?: string[]) =>
    req<ScanRunStartResult>(`/api/scans/${scanId}/runs/${kind}/restart`, {
      method: 'POST',
      body: targets ? JSON.stringify({ targets }) : undefined,
    }),

  listScreenshots: (scanId: string) => req<ScreenshotMeta[]>(`/api/scans/${scanId}/screenshots`),
  screenshotUrl: (scanId: string, hostname: string) => `/api/scans/${scanId}/screenshots/${encodeURIComponent(hostname)}`,
  reportUrl: (scanId: string, format: 'json' | 'html' | 'pdf') => `/api/scans/${scanId}/report?format=${format}`,

  listWordlists: () => req<WordlistInfo[]>('/api/wordlists'),
  wordlistCatalog: () => req<WordlistCatalogEntry[]>('/api/wordlists/catalog'),
  downloadWordlist: (name: string, url?: string) =>
    req<void>('/api/wordlists/download', { method: 'POST', body: JSON.stringify({ name, url }) }),
  deleteWordlist: (name: string) => req<void>(`/api/wordlists/${encodeURIComponent(name)}`, { method: 'DELETE' }),
  setWordlistCategories: (name: string, categories: WordlistCategory[]) =>
    req<void>(`/api/wordlists/${encodeURIComponent(name)}/categories`, {
      method: 'PATCH',
      body: JSON.stringify({ categories }),
    }),
  duplicateWordlist: (name: string, newName: string, categories?: WordlistCategory[]) =>
    req<void>(`/api/wordlists/${encodeURIComponent(name)}/duplicate`, {
      method: 'POST',
      body: JSON.stringify({ newName, categories }),
    }),
}

// watchRun opens a WebSocket streaming live RunEvents for one run and
// returns a cleanup function. Reconnection is intentionally not handled
// here: a run is a one-shot process, and REST (listFindings/getRun) is
// always available as a fallback if the socket drops.
export function watchRun(runId: string, onEvent: (ev: RunEvent) => void): () => void {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
  const ws = new WebSocket(`${proto}//${location.host}/ws/runs/${runId}`)
  ws.onmessage = (ev) => {
    try {
      onEvent(JSON.parse(ev.data))
    } catch {
      // ignore malformed frames
    }
  }
  return () => ws.close()
}

// watchScan opens a WebSocket streaming live ScanEvents (recon checks, then
// a "scanRun" event per scanner once its flow starts) for one scan and
// returns a cleanup function, mirroring watchRun above.
export function watchScan(scanId: string, onEvent: (ev: ScanEvent) => void): () => void {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
  const ws = new WebSocket(`${proto}//${location.host}/ws/scans/${scanId}`)
  ws.onmessage = (ev) => {
    try {
      onEvent(JSON.parse(ev.data))
    } catch {
      // ignore malformed frames
    }
  }
  return () => ws.close()
}
