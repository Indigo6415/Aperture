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

export type NodeKind = 'ffuf' | 'feroxbuster' | 'filter' | 'merge' | 'table' | 'export'

export const NODE_KINDS: NodeKind[] = ['ffuf', 'feroxbuster', 'filter', 'merge', 'table', 'export']

export const SOURCE_KINDS = new Set<NodeKind>(['ffuf', 'feroxbuster'])

export interface FlowNodeData {
  id: string
  kind: NodeKind
  label?: string
  config: Record<string, unknown>
  position?: { x: number; y: number }
}

export interface FlowEdgeData {
  id: string
  from: string
  to: string
}

export interface Flow {
  id: string
  name: string
  nodes: FlowNodeData[]
  edges: FlowEdgeData[]
}

export interface FlowSummary {
  id: string
  name: string
  updatedAt: string
}

export type RunStatus = 'pending' | 'running' | 'succeeded' | 'failed'

export interface Run {
  id: string
  flowId: string
  status: RunStatus
  error?: string
  startedAt: string
  finishedAt?: string
}

export type NodeStatus = 'pending' | 'running' | 'succeeded' | 'failed'

export interface RunEvent {
  type: 'finding' | 'status' | 'done'
  nodeId?: string
  finding?: Finding
  status?: NodeStatus
  message?: string
}

export interface ToolInfo {
  name: string
  available: boolean
}

// --- Domain scans (recon checks + the auto-generated ffuf/feroxbuster flow) ---

export type CheckKind = 'dns' | 'tls' | 'http' | 'subdomains' | 'whois'
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

export interface Scan {
  id: string
  domain: string
  flowId?: string
  runId?: string
  createdAt: string
  checks?: Check[]
}

export type ScanSummary = Pick<Scan, 'id' | 'domain' | 'flowId' | 'runId' | 'createdAt'>

export interface ScanEvent {
  type: 'check' | 'flow' | 'done'
  check?: Check
  message?: string
  flowId?: string
  runId?: string
}

// --- Wordlists ---

export interface WordlistInfo {
  name: string
  path: string
  size: number
  lines: number
  builtin: boolean
}

export interface WordlistCatalogEntry {
  name: string
  description: string
  url: string
}
