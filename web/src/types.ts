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
  type: 'finding' | 'status' | 'progress' | 'done'
  nodeId?: string
  finding?: Finding
  status?: NodeStatus
  message?: string
  // Set only on a "progress" event -- total 0 (or absent) means the total
  // is unknowable, so render an indeterminate indicator instead of a
  // percentage.
  done?: number
  total?: number
}

// --- Domain scans (recon checks + the scanner tabs each scan runs) ---

export type CheckKind = 'dns' | 'tls' | 'http' | 'subdomains' | 'whois' | 'takeover' | 'dnsdumpster'
export type CheckStatus = 'running' | 'done' | 'error'

export interface Check {
  domain: string
  kind: CheckKind
  status: CheckStatus
  data?: Record<string, unknown>
  error?: string
  startedAt: string
  finishedAt?: string
}

// ScanKind identifies one of the independent scanners a scan runs -- mirrors
// internal/store.ScanKind.
export type ScanKind = 'content-discovery' | 'subdomain-bruteforce' | 'vhost-bruteforce' | 'port-scan' | 'vuln-scan' | 'service-profile'

export interface ScanRun {
  kind: ScanKind
  flowId: string
  runId: string
  status: RunStatus
  targets?: string[]
  createdAt: string
}

// ScanOptionsPreset mirrors internal/engine.ScanOptions' Preset field --
// "aggressive"/"stealth" fill in Threads/TimeoutSeconds/RateLimit with a
// preset default for any of those left unset, "custom" (or omitted) takes
// every field literally.
export type ScanOptionsPreset = 'aggressive' | 'stealth' | 'custom'

export interface ScanOptions {
  preset?: ScanOptionsPreset
  threads?: number
  timeoutSeconds?: number
  rateLimit?: number
  wordlist?: string
}

export interface Scan {
  id: string
  domain: string
  scheme?: string
  options?: string
  createdAt: string
  checks?: Check[]
}

export interface ScanSummary {
  id: string
  domain: string
  scheme?: string
  createdAt: string
  subdomainCount: number
  findingCount: number
  httpStatus?: number
  httpTitle?: string
  cloudflare: boolean
  running: boolean
}

export interface ScanEvent {
  type: 'check' | 'scanRun' | 'screenshot' | 'done'
  check?: Check
  message?: string
  kind?: ScanKind
  flowId?: string
  runId?: string
  // Set only on a "scanRun" event for a scanner with a per-target concept
  // (content discovery) -- see store.ScanRun.Targets/RunEvent.Targets.
  targets?: string[]
}

// ScanRunStartResult is the response shape for every endpoint that starts
// (or declines to start) a scanner run -- runId is set on success; skipped
// is set instead when every requested target was already covered by a
// running-or-succeeded run of that kind (see store.CoveredTargets), with
// message explaining why nothing new was started.
export interface ScanRunStartResult {
  runId?: string
  skipped?: boolean
  message?: string
}

export interface ScreenshotMeta {
  hostname: string
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
}
