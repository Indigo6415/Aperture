import type {
  Finding,
  Flow,
  FlowSummary,
  Run,
  RunEvent,
  ScanEvent,
  ScanSummary,
  Scan,
  ToolInfo,
  WordlistCatalogEntry,
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

  listFlows: () => req<FlowSummary[]>('/api/flows'),
  createFlow: (flow: Partial<Flow>) =>
    req<Flow>('/api/flows', { method: 'POST', body: JSON.stringify(flow) }),
  getFlow: (id: string) => req<Flow>(`/api/flows/${id}`),
  updateFlow: (id: string, flow: Flow) =>
    req<Flow>(`/api/flows/${id}`, { method: 'PUT', body: JSON.stringify(flow) }),
  deleteFlow: (id: string) => req<void>(`/api/flows/${id}`, { method: 'DELETE' }),

  runFlow: (id: string) => req<{ runId: string }>(`/api/flows/${id}/run`, { method: 'POST' }),
  listRuns: (flowId: string) => req<Run[]>(`/api/flows/${flowId}/runs`),
  getRun: (runId: string) => req<Run>(`/api/runs/${runId}`),
  listFindings: (runId: string, nodeId?: string) =>
    req<Finding[]>(`/api/runs/${runId}/findings${nodeId ? `?nodeId=${encodeURIComponent(nodeId)}` : ''}`),

  startScan: (domain: string) => req<{ scanId: string }>('/api/scan', { method: 'POST', body: JSON.stringify({ domain }) }),
  listScans: () => req<ScanSummary[]>('/api/scans'),
  getScan: (id: string) => req<Scan>(`/api/scans/${id}`),

  listWordlists: () => req<WordlistInfo[]>('/api/wordlists'),
  wordlistCatalog: () => req<WordlistCatalogEntry[]>('/api/wordlists/catalog'),
  downloadWordlist: (name: string, url?: string) =>
    req<void>('/api/wordlists/download', { method: 'POST', body: JSON.stringify({ name, url }) }),
  deleteWordlist: (name: string) => req<void>(`/api/wordlists/${encodeURIComponent(name)}`, { method: 'DELETE' }),
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
// a "flow" event once the auto-generated ffuf/feroxbuster flow starts) for
// one scan and returns a cleanup function, mirroring watchRun above.
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
