// Mirrors internal/model.Finding and internal/engine.Flow's JSON shapes.

export interface Finding {
  id: string
  url: string
  statusCode: number
  contentLength: number
  words: number
  lines: number
  contentType?: string
  redirectLocation?: string
  method?: string
  headers?: Record<string, string>
  sourceTool: string
  sourceNodeId: string
  runId: string
  tags?: string[]
  timestamp: string
}

export type ToolInfo = {
  name: string
  available: boolean
}

export type RunStatus = 'pending' | 'running' | 'succeeded' | 'failed' | 'cancelled'

export interface Run {
  id: string
  flowId: string
  status: RunStatus
  error?: string
  startedAt: string
  finishedAt?: string
}

export type NodeStatus = 'pending' | 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled'

export interface RunEvent {
  type: 'finding' | 'status' | 'progress' | 'check' | 'module' | 'done'
  nodeId?: string
  finding?: Finding
  check?: Check
  status?: NodeStatus
  message?: string
  // Set only on a "progress" event -- total 0 (or absent) means the total
  // is unknowable, so render an indeterminate indicator instead of a
  // percentage.
  done?: number
  total?: number
  // Set on a "module" event: one probe check module just finished (see
  // ProbeModuleResult below). probeTarget/probeHealth are set alongside
  // status on a probe scan's terminal "done" event.
  module?: ProbeModuleResult
  probeTarget?: ProbeTarget
  probeHealth?: ProbeHealth
}

// --- Cases (a named container of targets + jobs run against them) ---

export type CheckKind =
  | 'dns'
  | 'tls'
  | 'http'
  | 'subdomains'
  | 'subdomains-verified'
  | 'whois'
  | 'takeover'
  | 'dnsdumpster'
  | 'technologies'
  | 'asn'
export type CheckStatus = 'running' | 'done' | 'error'

// CVE mirrors internal/cve.CVE -- one NVD record for a fingerprinted
// technology's version (see TechDetection below). kev/epss are exploit-
// likelihood signals layered on top of NVD's own CVSS severity (see
// internal/cve.EnrichExploitSignals) -- kev is true when CISA's Known
// Exploited Vulnerabilities catalog confirms active exploitation, epss is
// FIRST.org's predicted 30-day exploitation probability (0-1).
export interface CVE {
  id: string
  description: string
  severity: string
  score: number
  published: string
  references?: string[]
  kev?: boolean
  epss?: number
}

// TechDetection mirrors internal/api's techCVEResult -- one fingerprinted
// technology plus whatever CVEs were found for its detected version. Carried
// on a "technologies" Check's data.technologies array.
export interface TechDetection {
  name: string
  category: string
  version?: string
  cves?: CVE[]
}

// AsnInfo mirrors an 'asn' Check's data shape (see internal/recon/asn.go's
// checkASN) -- the hosting network Team Cymru's DNS-based lookup resolved
// for a target's first IPv4 address.
export interface AsnInfo {
  ip: string
  asn: string
  org: string
  country: string
  prefix: string
}

export interface Check {
  domain: string
  kind: CheckKind
  status: CheckStatus
  data?: Record<string, unknown>
  error?: string
  startedAt: string
  finishedAt?: string
}

export interface Case {
  id: string
  name: string
  description?: string
  createdAt: string
  updatedAt: string
}

export interface CaseSummary extends Case {
  targetCount: number
  jobCount: number
  findingCount: number
  running: boolean
}

// TargetKind is a UI hint only -- the backend never branches on it.
export type TargetKind = 'domain' | 'subdomain' | 'url' | 'ip' | 'other'

export interface Target {
  id: string
  caseId: string
  value: string
  kind?: TargetKind
  sourceTool?: string
  sourceJobId?: string
  notes?: string
  createdAt: string
}

// Tool identifies which job a case can run -- mirrors the tool constants in
// internal/api/handlers_jobs.go.
export type Tool = 'feroxbuster' | 'ffuf-subdomain' | 'ffuf-vhost' | 'ffuf-custom' | 'identify'

// JobOptionsPreset mirrors internal/engine.ScanOptions' Preset field --
// "aggressive"/"normal"/"stealth" fill in Threads/TimeoutSeconds/RateLimit
// with a preset default for any of those left unset, "custom" (or omitted)
// takes every field literally (and, in practice, leaves unset fields at
// whichever binary default the tool itself falls back to).
export type JobOptionsPreset = 'aggressive' | 'normal' | 'stealth' | 'custom'

export interface JobOptions {
  preset?: JobOptionsPreset
  threads?: number
  timeoutSeconds?: number
  rateLimit?: number
  wordlist?: string
  // scheme is feroxbuster/ffuf-subdomain only (default "https" if omitted).
  scheme?: string
  // hostSuffix is ffuf-vhost only: the domain fuzzed into the Host header
  // while each target (an IP) is hit directly.
  hostSuffix?: string
  // recursive is feroxbuster only: fuzz found directories again with the
  // same wordlist. Defaults to false (off) if omitted.
  recursive?: boolean
  // ffuf is ffuf-custom only -- mirrors internal/api.FFufJobOptions.
  ffuf?: FfufOptions
  // credentialId optionally names a saved case credential (see Credential
  // below) whose headers/cookie are applied to every request feroxbuster/
  // ffuf issues for this job.
  credentialId?: string
}

// FfufOptions mirrors internal/api.FFufJobOptions -- every ffuf-custom
// field that isn't already covered by JobOptions' own threads/timeoutSeconds/
// rateLimit/wordlist.
export interface FfufOptions {
  method?: string
  headers?: Record<string, string>
  body?: string
  extensions?: string[]
  matchCodes?: string
  filterCodes?: string
  matchSize?: string
  filterSize?: string
  autoCalibrate?: boolean
  followRedirects?: boolean
  delay?: string
  proxy?: string
  extraArgs?: string[]
}

// JobNodeDetail mirrors internal/api.JobNodeDetail -- one target node's
// actual scan config (wordlist, estimated candidate count, tuning), derived
// server-side from the job's saved flow.
export interface JobNodeDetail {
  nodeId: string
  target: string
  wordlist?: string
  extensions?: string[]
  candidates?: number
  threads?: number
  timeoutSeconds?: number
  rateLimit?: number
}

export interface Job {
  id: string
  caseId: string
  tool: Tool
  flowId?: string
  runId?: string
  targets: string[]
  status: RunStatus
  error?: string
  createdAt: string
  finishedAt?: string
  // nodes is populated server-side from the job's saved flow (see
  // internal/api.handleGetJob/handleListCaseJobs) -- absent for jobs with no
  // flow (e.g. identify).
  nodes?: JobNodeDetail[]
}

// JobStartResult is the response shape for POST .../jobs.
export interface JobStartResult {
  jobId?: string
}

export interface ScreenshotMeta {
  target: string
  url: string
  capturedAt: string
}

// --- Wordlists ---

export type WordlistCategory = 'directories' | 'subdomains' | 'extensions' | 'misc'

export interface WordlistInfo {
  name: string
  path: string
  size: number
  lines: number
  builtin: boolean
  categories: WordlistCategory[]
}

export interface WordlistCatalogEntry {
  name: string
  description: string
  url: string
}

// --- Auth & settings ---

export interface AuthUser {
  email: string
}

export interface SettingsInfo {
  dnsdumpsterApiKeySet: boolean
  nvdApiKeySet: boolean
}

// --- JWT scanner (mirrors internal/jwtscan) ---

export type JwtTestStatus = 'vulnerable' | 'safe' | 'skipped'

export interface JwtAttempt {
  label: string
  token: string
  httpStatus?: number
  hit: boolean
  error?: string
}

export interface JwtTestResult {
  id: string
  name: string
  status: JwtTestStatus
  summary: string
  token?: string
  attempts?: JwtAttempt[]
}

export interface JwtBaseline {
  validStatus: number
  validLength: number
  invalidStatus: number
  invalidLength: number
  identical: boolean
}

export interface JwtScanResponse {
  header: Record<string, unknown>
  payload: Record<string, unknown>
  baseline: JwtBaseline
  results: JwtTestResult[]
  crackedSecret?: string
  secretsTried: number
}

export interface JwtScanRequest {
  url: string
  token: string
  method?: string
  cookie?: string
  headers?: Record<string, string>
  pubKeyPem?: string
  wordlist?: string
  extraSecrets?: string
  credentialId?: string
  // caseId optionally scopes this scan to a case: when set, the result is
  // persisted to that case's scan history (see CaseScan below) instead of
  // only ever existing in this tab.
  caseId?: string
}

// --- Probe scanner (mirrors internal/probescan) ---

export interface ProbeTarget {
  raw: string
  url: string
  hostname: string
  ip?: string
  port: number
}

export interface ProbeHealth {
  tcp: boolean
  http: boolean
  https: boolean
}

export interface ProbeFinding {
  label: string
  url?: string
  detail?: string
  // evidence/method/statusCode are the "how was this found" specifics --
  // the exact matched content (a leaked key's value, a SQL error string, a
  // reflected payload) and the request that triggered it -- shown when a
  // finding is expanded, rather than inline in the summary list.
  evidence?: string
  method?: string
  statusCode?: number
}

export type ProbeSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export interface ProbeModuleResult {
  id: string
  name: string
  severity: ProbeSeverity
  findings: ProbeFinding[]
}

export interface ProbeScanResponse {
  target: ProbeTarget
  health: ProbeHealth
  modules: ProbeModuleResult[]
}

export interface ProbeScanRequest {
  target: string
  preset?: JobOptionsPreset
  credentialId?: string
  // caseId -- see JwtScanRequest.caseId's doc comment.
  caseId?: string
}

// ProbeModuleInfo is one registered check module's identity with no
// findings yet -- from GET /api/probe/modules, used to render the full test
// list (greyed out) before a scan has produced anything.
export interface ProbeModuleInfo {
  id: string
  name: string
  severity: ProbeSeverity
}

// ProbeScanStartResult is the response to starting an async probe scan --
// see watchProbeScan in api.ts for how scanId is then used to stream
// per-module progress.
export interface ProbeScanStartResult {
  scanId: string
}

// --- Secret scanner (mirrors internal/secretscan -- Aperture's Go/tsx port
// of Snitch) ---

export type SecretMatchMethod = 'regex' | 'entropy'

export interface SecretMatch {
  type: string
  method: SecretMatchMethod
  value: string
  location: string
}

export interface SecretScanRequest {
  url: string
  recursionDepth?: number
  entropy?: boolean
  headers?: Record<string, string>
  credentialId?: string
  // caseId -- see JwtScanRequest.caseId's doc comment.
  caseId?: string
}

export interface SecretScanResponse {
  pagesScanned: string[]
  scriptsScanned: string[]
  matches: SecretMatch[]
}

// --- Manual request repeater (mirrors internal/repeater) ---

export type BodyEncoding = 'utf8' | 'base64'

export interface RepeaterRequest {
  method: string
  url: string
  headers?: Record<string, string>
  body?: string
  followRedirects?: boolean
  credentialId?: string
  // caseId optionally scopes this send to a case: when set, the request
  // and its response are recorded to that case's Repeater history (see
  // RepeaterHistoryEntry below).
  caseId?: string
}

// RepeaterHistoryEntry mirrors internal/api's repeaterEntryResponse -- one
// past Repeater send recorded for a case.
export interface RepeaterHistoryEntry {
  id: string
  caseId: string
  method: string
  url: string
  requestHeaders?: Record<string, string>
  requestBody?: string
  response: RepeaterResponse
  createdAt: string
}

export interface RepeaterResponse {
  statusCode: number
  status: string
  headers: Record<string, string>
  body: string
  bodyEncoding: BodyEncoding
  contentLength: number
  durationMs: number
  raw: string
  error?: string
}

// --- Credential vault (mirrors internal/store.Credential) ---

// Credential is a saved auth bundle for one case. Unlike SettingsInfo's
// app-wide API keys, values here are returned in full -- see the backend
// schema comment on the credentials table for why.
export interface Credential {
  id: string
  caseId: string
  name: string
  headers?: Record<string, string>
  cookie?: string
  notes?: string
  createdAt: string
}

// --- Job launch templates (mirrors internal/store.JobTemplate) ---

// JobTemplate is a named, reusable bundle of job-launch options for one
// tool. `options` is exactly a JobOptions object -- the same one already
// built for api.startJob -- so applying a template can be handed straight
// back into a launcher's state.
export interface JobTemplate {
  id: string
  tool: Tool
  name: string
  options: JobOptions
  createdAt: string
}

// --- Case activity timeline (mirrors internal/store.Activity) ---

export interface ActivityEvent {
  id: string
  caseId: string
  kind: string
  message: string
  createdAt: string
}

// --- Persisted scan history (mirrors internal/store.CaseScan) ---

export type ScanTool = 'probe' | 'jwt' | 'secrets'

// CaseScan is one Probe/JWT/Secret Scanner run persisted for a case (only
// when that scan was launched with a case selected -- see ScanTool
// request types' own caseId field). severity is on the same
// info/low/medium/high/critical scale ProbeSeverity already uses.
export interface CaseScan {
  id: string
  caseId: string
  target: string
  tool: ScanTool
  severity: ProbeSeverity
  summary: string
  createdAt: string
}
