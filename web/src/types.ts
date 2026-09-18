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
  type: 'finding' | 'status' | 'progress' | 'check' | 'done'
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
export type CheckStatus = 'running' | 'done' | 'error'

// CVE mirrors internal/cve.CVE -- one NVD record for a fingerprinted
// technology's version (see TechDetection below).
export interface CVE {
  id: string
  description: string
  severity: string
  score: number
  published: string
  references?: string[]
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
export type Tool = 'feroxbuster' | 'ffuf-subdomain' | 'ffuf-vhost' | 'identify'

// JobOptionsPreset mirrors internal/engine.ScanOptions' Preset field --
// "aggressive"/"stealth" fill in Threads/TimeoutSeconds/RateLimit with a
// preset default for any of those left unset, "custom" (or omitted) takes
// every field literally.
export type JobOptionsPreset = 'aggressive' | 'stealth' | 'custom'

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
}
