import type {
  ActiveCallbackServer,
  ApiEnumRequest,
  ApiEnumStartResult,
  AuthUser,
  BreachCheckRequest,
  BreachCrawlRequest,
  Bypass403Request,
  Case,
  CaseScan,
  CaseSummary,
  Check,
  CollaboratorConfig,
  CollaboratorAddresses,
  CollabTLSStatus,
  CollaboratorConfigResponse,
  CollaboratorInteraction,
  CollaboratorNewTokenResponse,
  CookieVaultEntry,
  CorsScanRequest,
  Credential,
  CsrfScanRequest,
  DomainScanModuleInfo,
  DomainScanRequest,
  DomainScanStartResult,
  Finding,
  GitDumpRequest,
  GraphqlEnumRequest,
  Job,
  JobOptions,
  JobStartResult,
  JobTemplate,
  JwtScanRequest,
  OpenRedirectRequest,
  ProbeModuleInfo,
  ProbeScanRequest,
  ProbeScanStartResult,
  PwResetRequest,
  NodeRequestLog,
  RequestRecord,
  Run,
  RunEvent,
  ScanStartResult,
  ScanTool,
  ScreenshotMeta,
  SecretScanRequest,
  SettingsInfo,
  SsrfRequest,
  SstiScanRequest,
  PathTraversalRequest,
  IdorRequest,
  XxeRequest,
  Target,
  TargetList,
  TargetListKind,
  TargetPingResult,
  TesterRequest,
  TesterResponse,
  Tool,
  ToolInfo,
  TriageStatus,
  WebhookSiteToken,
  WordlistCatalogEntry,
  WordlistCategory,
  WordlistInfo,
  XssRequest,
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

// CaseScope is a case's allowlist of hosts scans may touch. An empty list
// means the case is unrestricted. See internal/netgov/scope.go for the
// accepted pattern forms.
export interface CaseScope {
  patterns: string[]
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

// streamPingTargetList runs the list liveness check and calls onResult for each
// target's verdict as the server finishes it. The endpoint answers with NDJSON
// (one JSON object per line), so the body is read incrementally instead of
// waiting for the whole response. Resolves once the server closes the stream.
async function streamPingTargetList(id: string, onResult: (r: TargetPingResult) => void): Promise<void> {
  const res = await fetch(`/api/target-lists/${id}/ping`, { method: 'POST' })
  if (!res.ok) {
    const body = await res.text()
    throw new ApiError(res.status, `${res.status} ${res.statusText}: ${body}`)
  }
  if (!res.body) throw new Error('ping: response has no body')

  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  // buffer holds a trailing partial line until the rest of it arrives.
  let buffer = ''
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    let nl: number
    while ((nl = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, nl).trim()
      buffer = buffer.slice(nl + 1)
      if (line) onResult(JSON.parse(line) as TargetPingResult)
    }
  }
  // Flush any final line that had no trailing newline.
  buffer += decoder.decode()
  const last = buffer.trim()
  if (last) onResult(JSON.parse(last) as TargetPingResult)
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
  setHIBPKey: (apiKey: string) =>
    req<SettingsInfo>('/api/settings/hibp-key', { method: 'PUT', body: JSON.stringify({ apiKey }) }),

  listTools: () => req<ToolInfo[]>('/api/tools'),

  getRun: (runId: string) => req<Run>(`/api/runs/${runId}`),
  // q narrows the log to requests whose method, URL, status, or raw request or
  // response contains it; without q the whole log comes back.
  listNodeRequests: (runId: string, nodeId: string, q?: string) =>
    req<NodeRequestLog>(
      `/api/runs/${runId}/nodes/${encodeURIComponent(nodeId)}/requests${q ? `?q=${encodeURIComponent(q)}` : ''}`,
    ),
  getNodeRequest: (runId: string, nodeId: string, requestId: number) =>
    req<RequestRecord>(`/api/runs/${runId}/nodes/${encodeURIComponent(nodeId)}/requests/${requestId}`),
  listFindings: (runId: string, nodeId?: string) =>
    req<Finding[]>(`/api/runs/${runId}/findings${nodeId ? `?nodeId=${encodeURIComponent(nodeId)}` : ''}`),
  updateFindingTriage: (id: string, status: TriageStatus, note?: string) =>
    req<{ status: TriageStatus; note?: string }>(`/api/findings/${id}/triage`, {
      method: 'PATCH',
      body: JSON.stringify({ status, note }),
    }),

  createCase: (name: string, description?: string) =>
    req<{ caseId: string }>('/api/cases', { method: 'POST', body: JSON.stringify({ name, description }) }),
  listCases: () => req<CaseSummary[]>('/api/cases'),
  getCase: (id: string) => req<Case>(`/api/cases/${id}`),
  deleteCase: (id: string) => req<void>(`/api/cases/${id}`, { method: 'DELETE' }),
  listCaseChecks: (caseId: string) => req<Check[]>(`/api/cases/${caseId}/checks`),
  getCaseScope: (caseId: string) => req<CaseScope>(`/api/cases/${caseId}/scope`),
  setCaseScope: (caseId: string, patterns: string[]) =>
    req<CaseScope>(`/api/cases/${caseId}/scope`, { method: 'PUT', body: JSON.stringify({ patterns }) }),
  reportUrl: (caseId: string, format: 'json' | 'html' | 'pdf') => `/api/cases/${caseId}/report?format=${format}`,
  // tool narrows the list to one scan tool's own history (e.g. its "Scans"
  // tab); omit it for the case-wide list.
  listCaseScans: (caseId: string, tool?: ScanTool) =>
    req<CaseScan[]>(`/api/cases/${caseId}/scans${tool ? `?tool=${encodeURIComponent(tool)}` : ''}`),
  // getCaseScan fetches one scan's full record, including its raw result
  // payload -- listCaseScans above omits it, matching the backend's list
  // view (see store.ListCaseScans' doc comment).
  getCaseScan: (id: string) => req<CaseScan>(`/api/scans/${id}`),

  listTargets: (caseId: string) => req<Target[]>(`/api/cases/${caseId}/targets`),
  addTarget: (caseId: string, value: string, listId: string, notes?: string) =>
    req<Target>(`/api/cases/${caseId}/targets`, { method: 'POST', body: JSON.stringify({ value, listId, notes }) }),
  promoteTargets: (caseId: string, jobId: string, listId: string, values: string[]) =>
    req<Target[]>(`/api/cases/${caseId}/targets/promote`, { method: 'POST', body: JSON.stringify({ jobId, listId, values }) }),
  deleteTarget: (id: string) => req<void>(`/api/targets/${id}`, { method: 'DELETE' }),

  listTargetLists: (caseId: string) => req<TargetList[]>(`/api/cases/${caseId}/target-lists`),
  createTargetList: (caseId: string, name: string, kind: TargetListKind) =>
    req<TargetList>(`/api/cases/${caseId}/target-lists`, { method: 'POST', body: JSON.stringify({ name, kind }) }),
  renameTargetList: (id: string, name: string) =>
    req<TargetList>(`/api/target-lists/${id}`, { method: 'PATCH', body: JSON.stringify({ name }) }),
  deleteTargetList: (id: string) => req<void>(`/api/target-lists/${id}`, { method: 'DELETE' }),
  pingTargetList: (id: string, onResult: (r: TargetPingResult) => void) => streamPingTargetList(id, onResult),

  listCredentials: (caseId: string) => req<Credential[]>(`/api/cases/${caseId}/credentials`),
  addCredential: (
    caseId: string,
    fields: {
      name: string
      headers?: Record<string, string>
      cookie?: string
      notes?: string
      username?: string
      password?: string
      loginUrl?: string
      loginMethod?: string
      usernameField?: string
      passwordField?: string
      tokenField?: string
    },
  ) => req<Credential>(`/api/cases/${caseId}/credentials`, { method: 'POST', body: JSON.stringify(fields) }),
  deleteCredential: (id: string) => req<void>(`/api/credentials/${id}`, { method: 'DELETE' }),
  // createCredentialSession logs a saved test credential in (see
  // handleCreateCredentialSession) and returns it with headers/cookie
  // overwritten by the resulting session.
  createCredentialSession: (id: string) => req<Credential>(`/api/credentials/${id}/session`, { method: 'POST' }),

  listCookieVault: (caseId: string) => req<CookieVaultEntry[]>(`/api/cases/${caseId}/cookie-vault`),
  setCookieVaultEntry: (caseId: string, domain: string, cookie: string) =>
    req<CookieVaultEntry>(`/api/cases/${caseId}/cookie-vault/${encodeURIComponent(domain)}`, {
      method: 'PUT',
      body: JSON.stringify({ cookie }),
    }),

  listJobTemplates: (tool: Tool) => req<JobTemplate[]>(`/api/job-templates?tool=${encodeURIComponent(tool)}`),
  saveJobTemplate: (tool: Tool, name: string, options: JobOptions) =>
    req<JobTemplate>('/api/job-templates', { method: 'POST', body: JSON.stringify({ tool, name, options }) }),
  deleteJobTemplate: (id: string) => req<void>(`/api/job-templates/${id}`, { method: 'DELETE' }),

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
        ffuf: options?.ffuf,
        credentialId: options?.credentialId,
      }),
    }),
  getJob: (jobId: string) => req<Job>(`/api/jobs/${jobId}`),
  cancelJob: (jobId: string) => req<void>(`/api/jobs/${jobId}/cancel`, { method: 'POST' }),
  // cancelScan stops one streamed scan (any scanner started by a POST that
  // returned a scanId). Like cancelJob, stopping a scan that already finished
  // is a harmless no-op.
  cancelScan: (scanId: string) => req<void>(`/api/scans/${scanId}/cancel`, { method: 'POST' }),

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
  renameWordlist: (name: string, newName: string) =>
    req<void>(`/api/wordlists/${encodeURIComponent(name)}/rename`, {
      method: 'POST',
      body: JSON.stringify({ newName }),
    }),

  jwtScan: (scanReq: JwtScanRequest) => req<ScanStartResult>('/api/jwt/scan', { method: 'POST', body: JSON.stringify(scanReq) }),

  listProbeModules: () => req<ProbeModuleInfo[]>('/api/probe/modules'),
  probeScan: (scanReq: ProbeScanRequest) =>
    req<ProbeScanStartResult>('/api/probe/scan', { method: 'POST', body: JSON.stringify(scanReq) }),

  listDomainScanModules: () => req<DomainScanModuleInfo[]>('/api/domainscan/modules'),
  domainScan: (scanReq: DomainScanRequest) =>
    req<DomainScanStartResult>('/api/domainscan/scan', { method: 'POST', body: JSON.stringify(scanReq) }),

  apiEnumScan: (scanReq: ApiEnumRequest) =>
    req<ApiEnumStartResult>('/api/apienum/scan', { method: 'POST', body: JSON.stringify(scanReq) }),

  secretScan: (scanReq: SecretScanRequest) => req<ScanStartResult>('/api/secrets/scan', { method: 'POST', body: JSON.stringify(scanReq) }),

  breachCheck: (checkReq: BreachCheckRequest) =>
    req<ScanStartResult>('/api/breach/check', { method: 'POST', body: JSON.stringify(checkReq) }),
  crawlEmails: (crawlReq: BreachCrawlRequest) =>
    req<ScanStartResult>('/api/breach/crawl-emails', { method: 'POST', body: JSON.stringify(crawlReq) }),

  bypass403: (runReq: Bypass403Request) => req<ScanStartResult>('/api/bypass403/run', { method: 'POST', body: JSON.stringify(runReq) }),

  gitDump: (runReq: GitDumpRequest) => req<ScanStartResult>('/api/gitdump/scan', { method: 'POST', body: JSON.stringify(runReq) }),

  pwReset: (scanReq: PwResetRequest) => req<ScanStartResult>('/api/pwreset/scan', { method: 'POST', body: JSON.stringify(scanReq) }),

  graphqlEnum: (scanReq: GraphqlEnumRequest) =>
    req<ScanStartResult>('/api/graphqlenum/scan', { method: 'POST', body: JSON.stringify(scanReq) }),

  corsScan: (scanReq: CorsScanRequest) => req<ScanStartResult>('/api/corsscan/scan', { method: 'POST', body: JSON.stringify(scanReq) }),

  openRedirect: (scanReq: OpenRedirectRequest) =>
    req<ScanStartResult>('/api/openredirect/scan', { method: 'POST', body: JSON.stringify(scanReq) }),

  ssrfScan: (scanReq: SsrfRequest) => req<ScanStartResult>('/api/ssrf/scan', { method: 'POST', body: JSON.stringify(scanReq) }),

  csrfScan: (scanReq: CsrfScanRequest) => req<ScanStartResult>('/api/csrf/scan', { method: 'POST', body: JSON.stringify(scanReq) }),

  sstiScan: (scanReq: SstiScanRequest) => req<ScanStartResult>('/api/sstiscan/scan', { method: 'POST', body: JSON.stringify(scanReq) }),

  pathTraversalScan: (scanReq: PathTraversalRequest) => req<ScanStartResult>('/api/pathtraversal/scan', { method: 'POST', body: JSON.stringify(scanReq) }),
  idorScan: (scanReq: IdorRequest) => req<ScanStartResult>('/api/idor/scan', { method: 'POST', body: JSON.stringify(scanReq) }),
  xxeScan: (scanReq: XxeRequest) => req<ScanStartResult>('/api/xxe/scan', { method: 'POST', body: JSON.stringify(scanReq) }),

  xssScan: (scanReq: XssRequest) => req<ScanStartResult>('/api/xss/scan', { method: 'POST', body: JSON.stringify(scanReq) }),

  testerSend: (sendReq: TesterRequest) => req<TesterResponse>('/api/tester/send', { method: 'POST', body: JSON.stringify(sendReq) }),

  getCollaboratorConfig: () => req<CollaboratorConfigResponse>('/api/collaborator/config'),
  getCollaboratorAddresses: () => req<CollaboratorAddresses>('/api/collaborator/addresses'),
  getCollabTLS: () => req<CollabTLSStatus>('/api/collaborator/tls'),
  setCollabTLS: (enabled: boolean) =>
    req<CollabTLSStatus>('/api/collaborator/tls', { method: 'PUT', body: JSON.stringify({ enabled }) }),
  regenerateCollabTLS: () => req<CollabTLSStatus>('/api/collaborator/tls/regenerate', { method: 'POST' }),
  setCollaboratorConfig: (cfg: CollaboratorConfig) =>
    req<CollaboratorConfigResponse>('/api/collaborator/config', { method: 'PUT', body: JSON.stringify(cfg) }),
  newCollaboratorToken: () => req<CollaboratorNewTokenResponse>('/api/collaborator/new', { method: 'POST' }),
  pollCollaborator: (token: string) => req<CollaboratorInteraction[]>(`/api/collaborator/poll?token=${encodeURIComponent(token)}`),
  newWebhookSiteToken: () => req<WebhookSiteToken>('/api/collaborator/webhooksite/new', { method: 'POST' }),
  pollWebhookSite: (uuid: string) =>
    req<CollaboratorInteraction[]>(`/api/collaborator/webhooksite/poll?uuid=${encodeURIComponent(uuid)}`),
  listActiveCallbackServers: () => req<ActiveCallbackServer[]>('/api/collaborator/active'),
  removeActiveCallbackServer: (token: string) =>
    req<void>(`/api/collaborator/active?token=${encodeURIComponent(token)}`, { method: 'DELETE' }),
}

// watchJob opens a WebSocket streaming live RunEvents for one job (whatever
// its tool) and returns a cleanup function. Reconnection is intentionally
// not handled here: a job is a one-shot process, and REST (listFindings/
// getJob/listCaseChecks) is always available as a fallback if the socket
// drops.
export function watchJob(jobId: string, onEvent: (ev: RunEvent) => void): () => void {
  return watchSocket(`/ws/jobs/${jobId}`, onEvent)
}

// watchProbeScan is watchJob's counterpart for a probe scan (see
// handleProbeScan/runProbeScan in internal/api) -- same RunEvent stream,
// keyed by scanId instead of jobId, emitting "module" events as each check
// module finishes and a terminal "done" event with the resolved target/
// health once every module has.
export function watchProbeScan(scanId: string, onEvent: (ev: RunEvent) => void): () => void {
  return watchSocket(`/ws/probe/${scanId}`, onEvent)
}

// watchDomainScan is watchProbeScan's counterpart for a domain scan (see
// handleDomainScan/runDomainScan in internal/api) -- same RunEvent stream,
// emitting "domainModule" events as each module finishes and a terminal
// "done" event with the resolved target once every module has.
export function watchDomainScan(scanId: string, onEvent: (ev: RunEvent) => void): () => void {
  return watchSocket(`/ws/domainscan/${scanId}`, onEvent)
}

// watchApiEnumScan is watchProbeScan's counterpart for an API enumeration
// run (see handleApiEnumScan/runApiEnumScan in internal/api) -- same
// RunEvent stream, emitting "apiEnumPhase" events as each discovery phase
// progresses, "apiEnumRoute" events as each route finishes
// characterization, and a terminal "done" event with the resolved target/
// schema/GraphQL summary/injection points/stats once the run finishes.
export function watchApiEnumScan(scanId: string, onEvent: (ev: RunEvent) => void): () => void {
  return watchSocket(`/ws/apienum/${scanId}`, onEvent)
}

// watchScan is the shared streaming route for every scanner that reports
// per-check progress (see internal/api/scan_stream.go) -- the same RunEvent
// stream as the per-tool watchers above, keyed by the scanId its POST
// /scan endpoint returned. onClose fires if the socket drops, so a caller
// can tell a lost connection apart from a scan that finished cleanly (which
// always ends on a "done" event first).
export function watchScan(scanId: string, onEvent: (ev: RunEvent) => void, onClose?: () => void): () => void {
  return watchSocket(`/ws/scans/${scanId}`, onEvent, onClose)
}

// watchEvents opens the global events socket (see handleWatchEvents in
// internal/api) and keeps it open for the whole session -- unlike the
// per-job watchers above, it is not tied to any one scan. The notification
// engine uses it to hear network-governor "hostEvent"s (throttling/drift/
// block). onClose lets the caller reconnect if the socket drops.
export function watchEvents(onEvent: (ev: RunEvent) => void, onClose?: () => void): () => void {
  return watchSocket('/ws/events', onEvent, onClose)
}

// notificationTap, when set, receives every RunEvent off every watched
// socket (keyed by the socket's path) in addition to the event's own
// handler. It is the single chokepoint the notification engine hooks so it
// can observe findings/callbacks/scan-completion across every active scan
// stream without each scanner component having to opt in. Set it once near
// app startup (see notifications.ts).
let notificationTap: ((path: string, ev: RunEvent) => void) | null = null
export function setNotificationTap(tap: ((path: string, ev: RunEvent) => void) | null): void {
  notificationTap = tap
}

function watchSocket(path: string, onEvent: (ev: RunEvent) => void, onClose?: () => void): () => void {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
  const ws = new WebSocket(`${proto}//${location.host}${path}`)
  ws.onmessage = (ev) => {
    try {
      const parsed: RunEvent = JSON.parse(ev.data)
      onEvent(parsed)
      // Mirror the event into the notification engine, if one is listening.
      // Wrapped so a throwing tap can never break the scanner that owns the
      // socket.
      if (notificationTap) {
        try {
          notificationTap(path, parsed)
        } catch {
          // a misbehaving tap must not disrupt the scan stream
        }
      }
    } catch {
      // ignore malformed frames
    }
  }
  if (onClose) ws.onclose = onClose
  return () => ws.close()
}
