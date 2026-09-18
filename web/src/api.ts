import type {
  AuthUser,
  Case,
  CaseSummary,
  Check,
  Finding,
  Job,
  JobOptions,
  JobStartResult,
  JwtScanRequest,
  JwtScanResponse,
  Run,
  RunEvent,
  ScreenshotMeta,
  SettingsInfo,
  Target,
  TargetKind,
  Tool,
  ToolInfo,
  WordlistCatalogEntry,
  WordlistCategory,
  WordlistInfo,
} from './types'

// ApiError carries the HTTP status alongside the usual message so callers
// (App's initial auth probe, in particular) can tell "not signed in" (401)
// apart from every other failure without parsing response text.
export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    headers: init?.body ? { 'Content-Type': 'application/json' } : undefined,
    ...init,
  })
  if (!res.ok) {
    const body = await res.text()
    throw new ApiError(res.status, `${res.status} ${res.statusText}: ${body}`)
  }
  if (res.status === 204) return undefined as T
  return res.json() as Promise<T>
}

// screenshotPreviewEnabled is the frontend half of the screenshot preview
// feature's on/off switch (see the matching constant in
// internal/api/screenshots.go, which stops the backend from capturing
// anything). Kept false here too so no component tries to fetch an image
// the backend will never have produced.
export const screenshotPreviewEnabled = false

export const api = {
  login: (email: string, password: string) =>
    req<AuthUser>('/api/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),
  logout: () => req<void>('/api/auth/logout', { method: 'POST' }),
  me: () => req<AuthUser>('/api/auth/me'),

  getSettings: () => req<SettingsInfo>('/api/settings'),
  setDNSDumpsterKey: (apiKey: string) =>
    req<SettingsInfo>('/api/settings/dnsdumpster-key', { method: 'PUT', body: JSON.stringify({ apiKey }) }),
  setNVDKey: (apiKey: string) =>
    req<SettingsInfo>('/api/settings/nvd-key', { method: 'PUT', body: JSON.stringify({ apiKey }) }),

  listTools: () => req<ToolInfo[]>('/api/tools'),

  getRun: (runId: string) => req<Run>(`/api/runs/${runId}`),
  listFindings: (runId: string, nodeId?: string) =>
    req<Finding[]>(`/api/runs/${runId}/findings${nodeId ? `?nodeId=${encodeURIComponent(nodeId)}` : ''}`),

  createCase: (name: string, description?: string) =>
    req<{ caseId: string }>('/api/cases', { method: 'POST', body: JSON.stringify({ name, description }) }),
  listCases: () => req<CaseSummary[]>('/api/cases'),
  getCase: (id: string) => req<Case>(`/api/cases/${id}`),
  deleteCase: (id: string) => req<void>(`/api/cases/${id}`, { method: 'DELETE' }),
  listCaseChecks: (caseId: string) => req<Check[]>(`/api/cases/${caseId}/checks`),
  reportUrl: (caseId: string, format: 'json' | 'html' | 'pdf') => `/api/cases/${caseId}/report?format=${format}`,

  listTargets: (caseId: string) => req<Target[]>(`/api/cases/${caseId}/targets`),
  addTarget: (caseId: string, value: string, kind?: TargetKind, notes?: string) =>
    req<Target>(`/api/cases/${caseId}/targets`, { method: 'POST', body: JSON.stringify({ value, kind, notes }) }),
  promoteTargets: (caseId: string, jobId: string, values: string[]) =>
    req<Target[]>(`/api/cases/${caseId}/targets/promote`, { method: 'POST', body: JSON.stringify({ jobId, values }) }),
  deleteTarget: (id: string) => req<void>(`/api/targets/${id}`, { method: 'DELETE' }),

  listJobs: (caseId: string) => req<Job[]>(`/api/cases/${caseId}/jobs`),
  startJob: (caseId: string, tool: Tool, targets: string[], options?: JobOptions) =>
    req<JobStartResult>(`/api/cases/${caseId}/jobs`, {
      method: 'POST',
      body: JSON.stringify({
        tool,
        targets,
        options: {
          preset: options?.preset,
          threads: options?.threads,
          timeoutSeconds: options?.timeoutSeconds,
          rateLimit: options?.rateLimit,
          wordlist: options?.wordlist,
          recursive: options?.recursive,
        },
        scheme: options?.scheme,
        hostSuffix: options?.hostSuffix,
      }),
    }),
  getJob: (jobId: string) => req<Job>(`/api/jobs/${jobId}`),
  cancelJob: (jobId: string) => req<void>(`/api/jobs/${jobId}/cancel`, { method: 'POST' }),

  listScreenshots: (caseId: string) => req<ScreenshotMeta[]>(`/api/cases/${caseId}/screenshots`),
  screenshotUrl: (caseId: string, target: string) => `/api/cases/${caseId}/screenshots/${encodeURIComponent(target)}`,

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

  jwtScan: (scanReq: JwtScanRequest) => req<JwtScanResponse>('/api/jwt/scan', { method: 'POST', body: JSON.stringify(scanReq) }),
}

// watchJob opens a WebSocket streaming live RunEvents for one job (whatever
// its tool) and returns a cleanup function. Reconnection is intentionally
// not handled here: a job is a one-shot process, and REST (listFindings/
// getJob/listCaseChecks) is always available as a fallback if the socket
// drops.
export function watchJob(jobId: string, onEvent: (ev: RunEvent) => void): () => void {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
  const ws = new WebSocket(`${proto}//${location.host}/ws/jobs/${jobId}`)
  ws.onmessage = (ev) => {
    try {
      onEvent(JSON.parse(ev.data))
    } catch {
      // ignore malformed frames
    }
  }
  return () => ws.close()
}
