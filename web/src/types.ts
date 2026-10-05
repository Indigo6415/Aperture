// Mirrors internal/model.Finding and internal/engine.Flow's JSON shapes.

// TriageStatus mirrors internal/model.TriageStatus -- a finding's place in
// the operator's own review workflow, set after the fact (see
// api.updateFindingTriage), never by the tool that produced the finding.
export type TriageStatus = 'new' | 'confirmed' | 'false_positive' | 'reported'

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
  triageStatus: TriageStatus
  triageNote?: string
  // Detail fields: the rule behind a result (nuclei), its own rating, the matcher
  // that fired, a repeat command, and how sure the check is.
  template?: string
  severity?: string
  matcher?: string
  reproduce?: string
  confidence?: Confidence
}

// Confidence is how strongly a check supports its claim. "confirmed" means the
// behavior was reproduced or observed directly; "likely" means a signature or
// inference matched; "heuristic" is a lead to check by hand.
export type Confidence = 'confirmed' | 'likely' | 'heuristic'

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
  type:
    | 'finding'
    | 'status'
    | 'progress'
    | 'check'
    | 'module'
    | 'domainModule'
    | 'apiEnumPhase'
    | 'apiEnumRoute'
    | 'plan'
    | 'checkStart'
    | 'checkDone'
    | 'phase'
    | 'done'
    // hostEvent is not tied to a job: it is a network-governor state change
    // (throttling/drift/block) broadcast on the global /ws/events channel
    // (see internal/api hub.go). host names the affected host, hostKind is
    // netgov's event kind, and message carries the human-readable reason.
    | 'hostEvent'
  nodeId?: string
  host?: string
  hostKind?: string
  // Set on a "plan" event: checks a streamed scan has registered (see
  // internal/scanprogress). checkId is set on "checkStart"/"checkDone";
  // findings on "checkDone" (message carries its error, if any). A "phase"
  // event carries its text in message. result is set on a streamed scan's
  // terminal "done" event -- the scanner's full response, untyped here since
  // each caller knows which response it asked for.
  checks?: ScanCheckInfo[]
  checkId?: string
  findings?: number
  result?: unknown
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
  // Set on a "domainModule" event: one domain scan module just finished
  // (see DomainScanModuleResult above). domainTarget is set alongside
  // status on a domain scan's terminal "done" event.
  domainModule?: DomainScanModuleResult
  domainTarget?: DomainScanTarget
  // Set on an "apiEnumPhase" event: coarse phase progress (spec discovery,
  // GraphQL, crawl, brute force, characterization). Set on an
  // "apiEnumRoute" event: one route just finished characterization -- the
  // UI accumulates these into its route tree the same way Probe
  // accumulates "module" events. apiEnumTarget/Schema/Graphql/
  // InjectionPoints/Stats are set alongside status on an API enum run's
  // terminal "done" event.
  apiEnumPhase?: ApiEnumPhaseEvent
  apiEnumRoute?: ApiRoute
  apiEnumTarget?: ApiEnumTarget
  apiEnumSchema?: ApiSchemaInfo
  apiEnumGraphql?: ApiGraphqlSummary
  apiEnumInjectionPoints?: ApiInjectionPoint[]
  apiEnumStats?: ApiEnumStats
}

// ScanCheckInfo is one check a streamed scan has registered (see
// internal/scanprogress.Check): id is stable for the run and what later
// checkStart/checkDone events refer back to; label names it for display;
// group is the category it belongs to, when the scanner gives one.
export interface ScanCheckInfo {
  id: string
  label: string
  group?: string
}

// ScanStartResult is the response to starting any streamed scan (a POST to
// a scanner's /scan endpoint): the ID its progress is watched by, over
// GET /ws/scans/{id} (see watchScan in api.ts).
export interface ScanStartResult {
  scanId: string
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

// TargetListKind is a UI hint only -- the backend never branches on it.
export type TargetListKind = 'domain' | 'directory' | 'file' | 'url' | 'other'

// TargetList is a named, user-created collection of targets within a case
// (domains, directories, files, login-form URLs, ...) -- every Target
// belongs to exactly one of these, like a Spotify playlist.
export interface TargetList {
  id: string
  caseId: string
  name: string
  kind: TargetListKind
  createdAt: string
}

export interface Target {
  id: string
  caseId: string
  listId: string
  // listName/listKind are denormalized onto the target by the backend so
  // callers can group/tab targets by list without a second request.
  listName: string
  listKind: TargetListKind
  value: string
  sourceTool?: string
  sourceJobId?: string
  notes?: string
  createdAt: string
}

// TargetPingResult is one target's answer from the list ping endpoint. alive
// means the host sent back any HTTP response; otherwise error says why not.
export interface TargetPingResult {
  targetId: string
  value: string
  alive: boolean
  statusCode?: number
  url?: string
  error?: string
}

// Tool identifies which job a case can run -- mirrors the tool constants in
// internal/api/handlers_jobs.go.
export type Tool =
  | 'feroxbuster'
  | 'ffuf-subdomain'
  | 'ffuf-vhost'
  | 'ffuf-custom'
  | 'identify'
  | 'subfinder'
  | 'katana'
  | 'nuclei'

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
  hibpApiKeySet: boolean
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
  // requestsPerSecond is the scan speed (Slow/Normal/Fast/Custom); omitted means the server default.
  requestsPerSecond?: number
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
  // callback optionally names a callback server picked from the Callback
  // button above the form -- enables the kid-SSRF/jku/x5u tests (see
  // JwtTestResult), which are otherwise reported as skipped.
  callback?: CallbackSelection
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
  confidence?: Confidence
  // headers/body are the request that triggered the finding -- set only by
  // checks that send a body (a POST), so Send to Tester can replay it exactly.
  headers?: Record<string, string>
  body?: string
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
  // requestsPerSecond is the scan speed (Slow/Normal/Fast/Custom); omitted means the server default.
  requestsPerSecond?: number
  target: string
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

// --- Domain scan (mirrors internal/domainscan) -- Aperture's "master"
// vulnerability/misconfiguration scanner: unlike Probe (which checks
// individual paths on an already-known route), every module here is a
// whole external tool -- retire.js first -- pointed at an entire domain,
// responsible for its own crawling. See internal/domainscan's package doc
// comment for the full reasoning. ---

export interface DomainScanFinding {
  label: string
  url?: string
  detail?: string
  evidence?: string
  severity: ProbeSeverity
}

export interface DomainScanModuleResult {
  id: string
  name: string
  severity: ProbeSeverity
  findings: DomainScanFinding[]
  // error is set when the module's own tool couldn't run at all (most
  // commonly not installed) -- distinct from running cleanly and finding
  // nothing.
  error?: string
}

export interface DomainScanTarget {
  raw: string
  url: string
  hostname: string
  ip?: string
  port: number
}

export interface DomainScanResponse {
  target: DomainScanTarget
  modules: DomainScanModuleResult[]
}

export interface DomainScanRequest {
  // requestsPerSecond is the scan speed (Slow/Normal/Fast/Custom); omitted means the server default.
  requestsPerSecond?: number
  target: string
  credentialId?: string
  crawlDepth?: number
  maxPages?: number
  // caseId -- see JwtScanRequest.caseId's doc comment.
  caseId?: string
}

// DomainScanModuleInfo is one registered module's identity with no
// findings yet -- from GET /api/domainscan/modules, same role as
// ProbeModuleInfo.
export interface DomainScanModuleInfo {
  id: string
  name: string
}

// DomainScanStartResult is the response to starting an async domain scan --
// see watchDomainScan in api.ts for how scanId is then used to stream
// per-module progress.
export interface DomainScanStartResult {
  scanId: string
}

// --- Secret scanner (mirrors internal/secretscan -- Aperture's Go/tsx port
// of Snitch) ---

export type SecretMatchMethod = 'regex' | 'entropy'
export type SecretMatchEngine = 'core' | 'secretfinder'

export interface SecretMatch {
  type: string
  method: SecretMatchMethod
  value: string
  location: string
  engine: SecretMatchEngine
  // headers are the headers the page was fetched with, so Send to Tester can
  // replay the request authenticated.
  headers?: Record<string, string>
}

export interface SecretScanRequest {
  // requestsPerSecond is the scan speed (Slow/Normal/Fast/Custom); omitted means the server default.
  requestsPerSecond?: number
  url: string
  recursionDepth?: number
  entropy?: boolean
  // secretFinderEngine also matches against SecretFinderPatterns (a second,
  // broader pattern library ported from the SecretFinder tool) -- off by
  // default, same "opt-in, noisier" posture as entropy.
  secretFinderEngine?: boolean
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
  // Username/password/loginUrl are optional and, together, make this a
  // "test credential": a valid login the operator can trigger via
  // api.createCredentialSession, which performs the login and overwrites
  // headers/cookie above with the resulting session -- see
  // handleCreateCredentialSession.
  username?: string
  password?: string
  loginUrl?: string
  loginMethod?: string
  usernameField?: string
  passwordField?: string
  tokenField?: string
  sessionAt?: string
  createdAt: string
}

// --- Cookie vault (mirrors internal/api.cookieVaultEntry) ---

// CookieVaultEntry is one domain known to a case, plus whatever Cookie
// header is currently saved to be sent automatically with every request
// this case makes against it (empty when nothing's saved yet). Unlike a
// Credential, this is never picked per-request -- it's always on for its
// domain, which is what makes authenticated scans against that domain work
// without re-selecting a credential every time.
export interface CookieVaultEntry {
  domain: string
  cookie?: string
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

// --- Persisted scan history (mirrors internal/store.CaseScan) ---

export type ScanTool =
  | 'probe'
  | 'jwt'
  | 'secrets'
  | 'breach'
  | 'breach-crawl'
  | 'domainscan'
  | 'bypass403'
  | 'gitdump'
  | 'pwreset'
  | 'graphqlenum'
  | 'corsscan'
  | 'openredirect'
  | 'ssrf'
  | 'csrf'
  | 'sstiscan'
  | 'pathtraversal'
  | 'idor'
  | 'xxe'
  | 'xss'
  | 'tester'
  | 'apienum'

// CaseScan is one scan-tool run persisted for a case (only when that scan
// was launched with a case selected -- see each ScanTool request type's own
// caseId field). severity is on the same info/low/medium/high/critical
// scale ProbeSeverity already uses. data carries the tool's raw JSON
// response -- omitted from the case-wide list view (see
// store.ListCaseScans), only populated by GET /api/scans/{id}.
export interface CaseScan {
  id: string
  caseId: string
  target: string
  tool: ScanTool
  severity: ProbeSeverity
  summary: string
  data?: string
  createdAt: string
}

// --- Tester (mirrors internal/tester + internal/api's tester handler) ---
// The Tester is the manual request replay/edit tool every scanner's
// findings can be sent to (see web/src/testerHandoff.ts) -- pick any
// finding, land in the Tester with its exact captured request already
// loaded, then replay/edit/resend and inspect the raw response.

export interface TesterRequest {
  method: string
  url: string
  headers?: Record<string, string>
  body?: string
  followRedirects?: boolean
  credentialId?: string
  // caseId optionally scopes this send to a case: when set, the result is
  // persisted to that case's scan history under tool "tester" (see
  // CaseScan above) instead of only ever existing in this tab.
  caseId?: string
}

export interface TesterResponse {
  statusCode: number
  status: string
  headers: Record<string, string>
  body: string
  bodyEncoding: 'utf8' | 'base64'
  contentLength: number
  durationMs: number
  raw: string
  error?: string
}

// --- Breach check (mirrors internal/breach + internal/api's breach-check
// handler) ---

// Breach is one breach an email address appeared in, per HaveIBeenPwned.
export interface Breach {
  name: string
  title: string
  domain?: string
  breachDate?: string
  pwnCount?: number
  dataClasses?: string[]
  isVerified: boolean
  isSensitive: boolean
}

export interface BreachEmailResult {
  email: string
  breaches: Breach[]
  error?: string
}

export interface BreachCheckRequest {
  emails: string[]
  caseId?: string
}

export interface BreachCheckResponse {
  results: BreachEmailResult[]
}

// BreachCrawlRequest/Response mirror SecretScanRequest/SecretScanResponse
// -- the crawl-for-emails endpoint runs the very same crawl (see
// internal/breach.CrawlForEmails), one target per request.
export interface BreachCrawlRequest {
  // requestsPerSecond is the scan speed (Slow/Normal/Fast/Custom); omitted means the server default.
  requestsPerSecond?: number
  url: string
  recursionDepth?: number
  headers?: Record<string, string>
  credentialId?: string
  caseId?: string
}

export interface BreachCrawlResponse {
  pagesScanned: string[]
  scriptsScanned: string[]
  emails: string[]
  emailSources: Record<string, string[]>
}

// --- 403 bypass engine (mirrors internal/bypass403) ---

export interface Bypass403Request {
  // requestsPerSecond is the scan speed (Slow/Normal/Fast/Custom); omitted means the server default.
  requestsPerSecond?: number
  url: string
  headers?: Record<string, string>
  credentialId?: string
  // allowWriteMethods opts into the PUT, PATCH and DELETE method attempts, which
  // can change or delete data on the target. Off by default.
  allowWriteMethods?: boolean
  caseId?: string
}

export interface Bypass403Baseline {
  url: string
  statusCode: number
  contentLength: number
  blocked: boolean
  reason?: string
}

export interface Bypass403Attempt {
  id: string
  category: 'path' | 'header' | 'method' | 'protocol' | 'archive'
  description: string
  method: string
  target: string
  headers?: Record<string, string>
  statusCode: number
  contentLength: number
  bodySnippet?: string
  bypassed: boolean
  error?: string
}

export interface Bypass403Response {
  baseline: Bypass403Baseline
  attempts: Bypass403Attempt[]
  bypassCount: number
}

// --- Git dump (mirrors internal/gitdump and internal/api/handlers_gitdump.go) ---

export interface GitDumpRequest {
  // requestsPerSecond is the scan speed (Slow/Normal/Fast/Custom); omitted means the server default.
  requestsPerSecond?: number
  // targets are URLs or bare hosts. Each is checked for an exposed .git and dumped if one is found.
  targets: string[]
  credentialId?: string
  caseId?: string
}

// GitDumpTarget is one target's outcome. bucketId is set only when the target
// was exposed and its zip exists, and is what the download link is built from.
export interface GitDumpTarget {
  input: string
  baseUrl: string
  // gitPath is the .git spelling that matched. Absent or ".git/" is the standard one.
  gitPath?: string
  host: string
  exposed: boolean
  headRef?: string
  refs: number
  packs: number
  objects: number
  missingObjects: number
  files: number
  restoredFrom?: 'HEAD' | 'index' | ''
  warnings?: string[]
  bucketId?: string
  zipBytes?: number
  error?: string
}

export interface GitDumpResponse {
  targets: GitDumpTarget[]
}

// --- Forgot-password scanner (mirrors internal/pwreset) ---

export interface PwResetRequest {
  // requestsPerSecond is the scan speed (Slow/Normal/Fast/Custom); omitted means the server default.
  requestsPerSecond?: number
  url: string
  method?: 'POST' | 'GET'
  contentType?: 'form' | 'json'
  identifierField?: string
  knownIdentifier?: string
  unknownIdentifier?: string
  extraFields?: Record<string, string>
  formUrl?: string
  credentialId?: string
  headers?: Record<string, string>
  caseId?: string
}

export interface PwResetBaseline {
  url: string
  method: string
  statusCode: number
  contentLength: number
}

// CapturedRequest is the exact request a scanner's check sent, mirrored
// field-for-field from each Go scanner's own CapturedRequest type
// (corsscan/ssrf/openredirect/pwreset/graphqlenum/csrf) -- attached to a
// finding so "Send to Tester" (see testerHandoff.ts) can replay precisely
// what triggered it, rather than just the module's target URL with a bare
// GET.
export interface CapturedRequest {
  method?: string
  url: string
  headers?: Record<string, string>
  body?: string
}

// PwResetFinding/PwResetModuleResult are structurally identical to
// ProbeFinding/ProbeModuleResult (see internal/pwreset.Finding's doc
// comment for why the Go types aren't shared) -- kept as their own named
// types anyway so PwReset.tsx's imports read as what they are.
export interface PwResetFinding {
  label: string
  detail?: string
  evidence?: string
  method?: string
  statusCode?: number
  request?: CapturedRequest
  // confidence is "confirmed" when the behavior was reproduced, "likely" or
  // "heuristic" otherwise (empty on findings saved before it was recorded).
  confidence?: Confidence
}

export interface PwResetModuleResult {
  id: string
  name: string
  severity: ProbeSeverity
  findings: PwResetFinding[]
}

export interface PwResetResponse {
  baseline: PwResetBaseline
  modules: PwResetModuleResult[]
}

// --- GraphQL enumeration scanner (mirrors internal/graphqlenum) ---

export interface GraphqlEnumRequest {
  // requestsPerSecond is the scan speed (Slow/Normal/Fast/Custom); omitted means the server default.
  requestsPerSecond?: number
  url: string
  credentialId?: string
  headers?: Record<string, string>
  caseId?: string
}

export interface GraphqlEnumBaseline {
  url: string
  statusCode: number
  confirmed: boolean
  typeName?: string
  // resolvedUrl is set only when the checks ran against a different path than url
  // (the requested URL did not answer as GraphQL and an alternate did).
  resolvedUrl?: string
  // detectedVia says how the endpoint was confirmed: "typename" when the
  // universal query returned a typed data object, or "error-signature" when it
  // refused that query but answered with a GraphQL-shaped error (a
  // persisted-query-only, auth-gated, or introspection-disabled endpoint).
  detectedVia?: 'typename' | 'error-signature'
  // evidence is the error message the "error-signature" detection matched on.
  evidence?: string
}

export interface GraphqlFieldSummary {
  name: string
  description?: string
  args?: string[]
  returnType?: string
  isDeprecated?: boolean
}

export interface GraphqlTypeSummary {
  name: string
  kind: string
  description?: string
  fieldCount: number
}

export interface GraphqlSchema {
  via: string
  queryType?: string
  mutationType?: string
  subscriptionType?: string
  typeCount: number
  queries?: GraphqlFieldSummary[]
  mutations?: GraphqlFieldSummary[]
  subscriptions?: GraphqlFieldSummary[]
  types?: GraphqlTypeSummary[]
  truncated?: boolean
}

// GraphqlEnumFinding/GraphqlEnumModuleResult are structurally identical to
// PwResetFinding/PwResetModuleResult (see internal/graphqlenum.Finding's
// doc comment for why the Go types aren't shared) -- kept as their own
// named types anyway so GraphqlEnum.tsx's imports read as what they are.
export interface GraphqlEnumFinding {
  label: string
  detail?: string
  evidence?: string
  method?: string
  statusCode?: number
  request?: CapturedRequest
  // confidence is "confirmed" when the behavior was reproduced, "likely" or
  // "heuristic" otherwise (empty on findings saved before it was recorded).
  confidence?: Confidence
}

export interface GraphqlEnumModuleResult {
  id: string
  name: string
  severity: ProbeSeverity
  findings: GraphqlEnumFinding[]
  // skipped, when set, says why this module was deliberately not run at all.
  skipped?: string
}

export interface GraphqlEnumResponse {
  baseline: GraphqlEnumBaseline
  schema?: GraphqlSchema
  modules: GraphqlEnumModuleResult[]
}

// --- API Enumerator (mirrors internal/apienum): finds API endpoints
// through an exposed OpenAPI/Swagger spec, GraphQL introspection, a
// same-origin crawl, JS bundle mining, and a wordlist brute force, then
// characterizes each one (methods accepted, auth requirement, content-type
// negotiation, a response-shape fingerprint) and flags parameters worth a
// closer look into a staged, never-auto-attacked injection-point list. ---

export type ApiParamLocation = 'query' | 'body' | 'header' | 'path'

export interface ApiParam {
  name: string
  location: ApiParamLocation
  typeGuess: string
  sample?: string
  flagged: boolean
  reason?: string
}

export interface ApiMethodProbe {
  method: string
  allowed: boolean
  statusCode: number
  contentType?: string
  bodyShape?: string
  responseBytes: number
}

// ApiAuthVerdict mirrors internal/apienum.AuthProbe.Verdict's documented values.
export type ApiAuthVerdict =
  | 'public'
  | 'requires-auth'
  | 'forbidden'
  | 'login-redirect'
  | 'site-wide-gate'
  | 'not-found'
  | 'unreachable'
  | 'other'

export interface ApiAuthProbe {
  unauthenticatedStatus: number
  authenticatedStatus?: number
  requiresAuth: boolean
  // verdict names what the unauthenticated answer means (see internal/apienum.AuthProbe).
  verdict?: ApiAuthVerdict
  // challenge is the WWW-Authenticate header, when the server sent one.
  challenge?: string
}

// ApiRouteSource is where a route was first discovered -- drives both the
// tree's grouping and the confirmed/uncertain split (see ApiRoute.confirmed).
export type ApiRouteSource = 'spec' | 'graphql' | 'crawl' | 'js' | 'bruteforce'

export interface ApiRoute {
  id: string
  path: string
  group: string
  source: ApiRouteSource
  confirmed: boolean
  methods: ApiMethodProbe[]
  auth: ApiAuthProbe
  params: ApiParam[]
  contentTypesAccepted?: string[]
  rateLimitHeaders?: Record<string, string>
  paginated?: boolean
}

export interface ApiInjectionPoint {
  endpoint: string
  method: string
  param: string
  location: ApiParamLocation
  typeGuess: string
  sample?: string
  reason: string
}

export interface ApiSchemaInfo {
  found: boolean
  kind?: string
  url?: string
  routeCount?: number
}

export interface ApiGraphqlSummary {
  found: boolean
  url?: string
  introspectionOn?: boolean
  typeCount?: number
  queries?: string[]
  mutations?: string[]
}

export interface ApiEnumStats {
  routesFound: number
  confirmedRoutes: number
  uncertainRoutes: number
  requestsSent: number
  injectionPoints: number
}

export interface ApiEnumTarget {
  raw: string
  url: string
  hostname: string
  ip?: string
  port: number
}

export interface ApiEnumResponse {
  target: ApiEnumTarget
  schema?: ApiSchemaInfo
  graphql?: ApiGraphqlSummary
  routes: ApiRoute[]
  injectionPoints: ApiInjectionPoint[]
  stats: ApiEnumStats
}

export interface ApiEnumRequest {
  // requestsPerSecond is the scan speed (Slow/Normal/Fast/Custom); omitted means the server default.
  requestsPerSecond?: number
  target: string
  credentialId?: string
  crawlDepth?: number
  maxPages?: number
  extraWordlist?: string[]
  // allowWriteMethods opts into sending PUT, PATCH and DELETE to each route.
  // Off by default because those requests can change or delete data on the target.
  allowWriteMethods?: boolean
  // caseId -- see JwtScanRequest.caseId's doc comment.
  caseId?: string
}

// ApiEnumPhaseEvent mirrors apienum.PhaseEvent -- one coarse progress
// update streamed over the run's WebSocket (see RunEvent.apiEnumPhase).
export interface ApiEnumPhaseEvent {
  phase: 'spec' | 'graphql' | 'crawl' | 'bruteforce' | 'characterize'
  done: number
  total: number
}

// ApiEnumStartResult is the response to starting an async API enum run --
// see watchApiEnumScan in api.ts for how scanId is then used to stream
// live phase/route progress.
export interface ApiEnumStartResult {
  scanId: string
}

// --- CORS misconfiguration scanner (mirrors internal/corsscan) ---

export interface CorsScanRequest {
  // requestsPerSecond is the scan speed (Slow/Normal/Fast/Custom); omitted means the server default.
  requestsPerSecond?: number
  url: string
  method?: string
  credentialId?: string
  headers?: Record<string, string>
  caseId?: string
}

export interface CorsScanBaseline {
  url: string
  method: string
  statusCode: number
  allowOriginPresent: boolean
  allowOrigin?: string
}

// CorsScanFinding/CorsScanModuleResult are structurally identical to
// PwResetFinding/PwResetModuleResult -- kept as their own named types for
// the same reason (see internal/corsscan.Finding's doc comment).
export interface CorsScanFinding {
  label: string
  detail?: string
  evidence?: string
  method?: string
  statusCode?: number
  request?: CapturedRequest
  // confidence is "confirmed" when the behavior was reproduced, "likely" or
  // "heuristic" otherwise (empty on findings saved before it was recorded).
  confidence?: Confidence
  // exploitation says how an attacker would use the misconfiguration (see
  // internal/corsscan.Finding.Exploitation).
  exploitation?: string
}

export interface CorsScanModuleResult {
  id: string
  name: string
  severity: ProbeSeverity
  findings: CorsScanFinding[]
}

export interface CorsScanResponse {
  baseline: CorsScanBaseline
  modules: CorsScanModuleResult[]
}

// --- Open redirect scanner (mirrors internal/openredirect) ---

export interface OpenRedirectRequest {
  // requestsPerSecond is the scan speed (Slow/Normal/Fast/Custom); omitted means the server default.
  requestsPerSecond?: number
  url: string
  params?: string[]
  // mineParams runs parameter mining against the URL and tests whatever it finds.
  mineParams?: boolean
  // discover also scans redirect-shaped URLs Common Crawl has seen under the
  // same host. It sends a query about the host to a third party, so it is opt-in.
  discover?: boolean
  credentialId?: string
  headers?: Record<string, string>
  caseId?: string
  // callback optionally names a callback server picked from the Callback
  // button above the form -- when set, every payload module also tries a
  // live, pollable poison host instead of just the scanner's own static
  // placeholder.
  callback?: CallbackSelection
  // followRedirects walks each redirect chain (up to a fixed hop limit) when
  // looking for the callback. Omitted means on, matching the server default.
  followRedirects?: boolean
}

export interface OpenRedirectBaseline {
  url: string
  statusCode: number
  location?: string
  // error is set when every baseline attempt failed; the run still went on.
  error?: string
}

// ChainHop is one request on the path from an open-redirect probe to its
// callback (mirrors openredirect.ChainHop). kind is "probe", "redirect" or
// "callback"; offsetMs is when the request went out relative to the probe's
// first request, and durationMs is how long it took on the wire.
export interface ChainHop {
  step: number
  kind: 'probe' | 'redirect' | 'callback'
  method: string
  url: string
  statusCode?: number
  location?: string
  offsetMs: number
  durationMs: number
  headers?: Record<string, string>
  error?: string
}

export interface OpenRedirectFinding {
  label: string
  detail?: string
  evidence?: string
  method?: string
  statusCode?: number
  request?: CapturedRequest
  // chain is every request from the probe to the callback. Absent on scans
  // saved before it was recorded.
  chain?: ChainHop[]
  // confidence is "confirmed" when the behavior was reproduced, "likely" or
  // "heuristic" otherwise (empty on findings saved before it was recorded).
  confidence?: Confidence
}

export interface OpenRedirectModuleResult {
  id: string
  name: string
  severity: ProbeSeverity
  findings: OpenRedirectFinding[]
}

export interface OpenRedirectResponse {
  baseline: OpenRedirectBaseline
  modules: OpenRedirectModuleResult[]
  paramsTested: string[]
  // probesSent is every distinct request the run fired (baseline excluded).
  // Optional: scans saved before this field existed won't have it.
  probesSent?: number
  // requests is every request the run sent (baseline attempts, probes and
  // callback confirmations); timedOut is how many ran out of their time
  // budget. Together they show how responsive the host was.
  requests?: number
  timedOut?: number
  followRedirects?: boolean
}

// --- SSRF scanner (mirrors internal/ssrf) ---

export interface SsrfRequest {
  // requestsPerSecond is the scan speed (Slow/Normal/Fast/Custom); omitted means the server default.
  requestsPerSecond?: number
  url: string
  params?: string[]
  // mineParams runs parameter mining against the URL and tests whatever it finds.
  mineParams?: boolean
  credentialId?: string
  headers?: Record<string, string>
  caseId?: string
  autoDiscover?: boolean
  recursionDepth?: number
  maxPages?: number
  // callback optionally names a callback server picked from the Callback
  // button above the form -- when set, the OOB-callback module points every
  // parameter at that one shared, long-lived server (with a per-parameter
  // identifier) instead of minting a fresh throwaway token per parameter.
  callback?: CallbackSelection
  // noKnownEndpoints turns off the product-specific endpoint probes (on by default).
  noKnownEndpoints?: boolean
}

export interface SsrfBaseline {
  url: string
  statusCode: number
}

export interface SsrfFinding {
  label: string
  detail?: string
  evidence?: string
  method?: string
  statusCode?: number
  request?: CapturedRequest
  // confidence is "confirmed" when the behavior was reproduced, "likely" or
  // "heuristic" otherwise (empty on findings saved before it was recorded).
  confidence?: Confidence
}

export interface SsrfModuleResult {
  id: string
  name: string
  severity: ProbeSeverity
  findings: SsrfFinding[]
}

export interface SsrfResponse {
  baseline: SsrfBaseline
  modules: SsrfModuleResult[]
  paramsTested: string[]
}

// --- XXE scanner (mirrors internal/xxe) ---

export interface XxeRequest {
  // requestsPerSecond is the scan speed (Slow/Normal/Fast/Custom); omitted means the server default.
  requestsPerSecond?: number
  url: string
  // method is POST or PUT; omitted means POST.
  method?: 'POST' | 'PUT'
  // body is an optional XML part supplied by the operator. Every text value in
  // it is tested. Omitted means a built-in probe document is used.
  body?: string
  contentType?: string
  headers?: Record<string, string>
  credentialId?: string
  caseId?: string
  autoDiscover?: boolean
  recursionDepth?: number
  maxPages?: number
  // callback optionally names a shared callback server picked from the Callback picker; omitted means the
  // scanner mints its own per-point tokens.
  callback?: CallbackSelection
}

export interface XxeBaseline {
  url: string
  statusCode: number
}

// confirmed: the parser's behavior was proven (a file's contents came back, or an
// out-of-band callback arrived). likely: a parser error named the path it tried
// to open, which proves resolution but not a read.
export type XxeConfidence = 'confirmed' | 'likely'

export interface XxeFinding {
  label: string
  detail?: string
  evidence?: string
  method?: string
  statusCode?: number
  confidence?: XxeConfidence
  request?: CapturedRequest
}

export interface XxeModuleResult {
  id: string
  name: string
  severity: ProbeSeverity
  findings: XxeFinding[]
}

export interface XxeEndpoint {
  url: string
  method: string
  // source is where the endpoint came from: seed, form action, script reference, or common path.
  source: string
  // evidence says why an auto-discovered endpoint counts as XML-capable. Empty for a manual seed.
  evidence?: string
  pointsTested: number
}

export interface XxeResponse {
  baseline: XxeBaseline
  modules: XxeModuleResult[]
  endpoints: XxeEndpoint[]
  pointsTested: number
  // oobEnabled is false when no callback listener is configured, so the blind module ran nothing.
  oobEnabled: boolean
}

// --- XSS scanner (mirrors internal/xss) ---

export interface XssRequest {
  // requestsPerSecond is the scan speed (Slow/Normal/Fast/Custom); omitted means the server default.
  requestsPerSecond?: number
  url: string
  params?: string[]
  // mineParams runs parameter mining against the URL and tests whatever it finds.
  mineParams?: boolean
  credentialId?: string
  headers?: Record<string, string>
  caseId?: string
  recursionDepth?: number
  maxPages?: number
  // callback names a shared callback server for blind XSS. Omitted means the
  // blind module mints one token per injection point on this instance.
  callback?: CallbackSelection
  // payloadBudget caps the payloads tried per injection point; omitted means the server default.
  payloadBudget?: number
}

export interface XssBaseline {
  url: string
  statusCode: number
}

export interface XssFinding {
  label: string
  detail?: string
  evidence?: string
  method?: string
  statusCode?: number
  request?: CapturedRequest
  // confidence is "confirmed" when the behavior was reproduced, "likely" or
  // "heuristic" otherwise (empty on findings saved before it was recorded).
  confidence?: Confidence
}

export interface XssModuleResult {
  id: string
  name: string
  severity: ProbeSeverity
  findings: XssFinding[]
}

export interface XssResponse {
  baseline: XssBaseline
  modules: XssModuleResult[]
  pagesScanned: string[]
  pointsTested: number
}

// --- CSRF sweep (mirrors internal/csrf) ---

// CsrfTokenProbeRequest mirrors internal/api's csrfTokenProbeRequest. The
// server only runs the check when confirm is true, and it refuses the scan
// when the probe is incomplete rather than dropping it.
export interface CsrfTokenProbeRequest {
  url: string
  method?: 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  // body is the complete form-encoded submission, token field included.
  body: string
  // field names the token field inside body.
  field: string
  confirm: boolean
}

export interface CsrfScanRequest {
  // requestsPerSecond is the scan speed (Slow/Normal/Fast/Custom); omitted means the server default.
  requestsPerSecond?: number
  url: string
  recursionDepth?: number
  maxPages?: number
  credentialId?: string
  headers?: Record<string, string>
  caseId?: string
  // apiUrl/apiMethod/apiBody opt into the one active check this scanner has
  // (see internal/csrf.Request's doc comment): replays apiBody against
  // apiUrl under application/json and then again, unchanged, under
  // text/plain, to check whether a JSON-only Content-Type requirement is
  // actually enforced server-side. Skipped entirely when apiUrl/apiBody is
  // blank.
  apiUrl?: string
  apiMethod?: string
  apiBody?: string
  // tokenProbe opts into the token-enforcement check. It replays one named form
  // submission with its token removed, emptied and tampered, so it sends
  // state-changing requests. The server refuses it unless confirm is true.
  tokenProbe?: CsrfTokenProbeRequest
}

// CsrfFinding carries no method/statusCode -- unlike every other scanner's
// Finding, most of internal/csrf never issues a check-specific request
// (every crawl-derived module is pure post-processing of the one crawl
// pass); request there is only ever a plain GET on the page/cookie a
// finding was seen on. The one exception is the content-type-csrf-bypass
// module's finding, whose request is the actual text/plain replay that
// triggered it (method/headers/body all populated).
export interface CsrfFinding {
  label: string
  detail?: string
  evidence?: string
  request?: CapturedRequest
  // confidence is "confirmed" when the behavior was reproduced, "likely" or
  // "heuristic" otherwise (empty on findings saved before it was recorded).
  confidence?: Confidence
}

export interface CsrfModuleResult {
  id: string
  name: string
  severity: ProbeSeverity
  findings: CsrfFinding[]
}

export interface CsrfScanResponse {
  pagesScanned: string[]
  formsFound: number
  modules: CsrfModuleResult[]
}

// --- SSTI scanner (mirrors internal/sstiscan) ---

export interface SstiScanRequest {
  // requestsPerSecond is the scan speed (Slow/Normal/Fast/Custom); omitted means the server default.
  requestsPerSecond?: number
  url: string
  params?: string[]
  // mineParams runs parameter mining against the URL and tests whatever it finds.
  mineParams?: boolean
  credentialId?: string
  headers?: Record<string, string>
  caseId?: string
  recursionDepth?: number
  maxPages?: number
  // callback optionally names a callback server picked from the Callback
  // button above the form -- when set, the out-of-band RCE module points
  // every injection point at that one shared, long-lived server (with a
  // per-point identifier) instead of minting a fresh throwaway token per
  // point.
  callback?: CallbackSelection
}

export interface SstiScanBaseline {
  url: string
  statusCode: number
}

export interface SstiScanFinding {
  label: string
  detail?: string
  evidence?: string
  method?: string
  statusCode?: number
  request?: CapturedRequest
  // confidence is "confirmed" when the behavior was reproduced, "likely" or
  // "heuristic" otherwise (empty on findings saved before it was recorded).
  confidence?: Confidence
}

export interface SstiScanModuleResult {
  id: string
  name: string
  severity: ProbeSeverity
  findings: SstiScanFinding[]
}

export interface SstiScanResponse {
  baseline: SstiScanBaseline
  modules: SstiScanModuleResult[]
  pagesScanned: string[]
  pointsTested: number
}

// --- Path traversal scanner (mirrors internal/pathtraversal) ---

export interface PathTraversalRequest {
  // requestsPerSecond is the scan speed (Slow/Normal/Fast/Custom); omitted means the server default.
  requestsPerSecond?: number
  url: string
  // method is GET or POST; omitted means POST when a body is set, GET otherwise.
  method?: string
  // body is an optional request body, tested per JSON string or per form field.
  body?: string
  contentType?: string
  params?: string[]
  // mineParams runs parameter mining against the URL and tests whatever it finds.
  mineParams?: boolean
  credentialId?: string
  headers?: Record<string, string>
  caseId?: string
  recursionDepth?: number
  maxPages?: number
  // callback optionally names a shared callback server picked from the Callback picker; omitted means the
  // scanner mints its own per-point tokens.
  callback?: CallbackSelection
}

export interface PathTraversalBaseline {
  url: string
  statusCode: number
}

export interface PathTraversalFinding {
  label: string
  detail?: string
  evidence?: string
  payload?: string
  method?: string
  statusCode?: number
  // confidence is "confirmed" (strong file signature) or "likely" (weak signature).
  confidence?: 'confirmed' | 'likely'
  request?: CapturedRequest
}

export interface PathTraversalModuleResult {
  id: string
  name: string
  severity: ProbeSeverity
  findings: PathTraversalFinding[]
}

export interface PathTraversalResponse {
  baseline: PathTraversalBaseline
  modules: PathTraversalModuleResult[]
  pagesScanned: string[]
  pointsTested: number
}

// --- IDOR / broken object-level authorization (mirrors internal/idor) ---

export interface IdorRequest {
  // requestsPerSecond is the scan speed (Slow/Normal/Fast/Custom); omitted means the server default.
  requestsPerSecond?: number
  url: string
  // method is GET or POST; omitted means POST when a body is set, GET otherwise.
  method?: string
  // body is an optional request body, mined for JSON/form reference fields.
  body?: string
  contentType?: string
  // params are extra query-parameter names tried on the URL as id candidates.
  params?: string[]
  // mineParams runs parameter mining against the URL and tests whatever it finds.
  mineParams?: boolean
  // credentialId is the owner identity whose objects form the baseline.
  credentialId?: string
  // attackerCredentialId is an optional second identity; when set the cross-identity module replays under it.
  attackerCredentialId?: string
  headers?: Record<string, string>
  // attackerHeaders are extra headers (e.g. a Cookie) for the second identity.
  attackerHeaders?: Record<string, string>
  caseId?: string
}

export interface IdorBaseline {
  url: string
  statusCode: number
}

export interface IdorFinding {
  label: string
  detail?: string
  evidence?: string
  payload?: string
  method?: string
  statusCode?: number
  // confidence is "confirmed" (cross-identity proof), "likely" (distinct object), or "heuristic" (a lead).
  confidence?: Confidence
  request?: CapturedRequest
}

export interface IdorModuleResult {
  id: string
  name: string
  severity: ProbeSeverity
  findings: IdorFinding[]
}

export interface IdorResponse {
  baseline: IdorBaseline
  modules: IdorModuleResult[]
  // pointsTested is how many distinct reference-bearing points were found.
  pointsTested: number
  // testsRun is the total number of individual probes sent to the host.
  testsRun: number
  // identities names the alternate identities the cross-identity modules ran under.
  identities: string[]
}

// --- Out-of-band collaborator listener (mirrors internal/collaborator +
// internal/api/handlers_collaborator.go) ---

export interface CollaboratorConfig {
  domain: string
  answerIp: string
  dnsAddr: string
  // Externally reachable base URL callbacks are sent to (e.g. http://203.0.113.7:8338).
  // Empty falls back to the address the Aperture UI was opened on.
  callbackBase: string
}

export interface CollaboratorConfigResponse extends CollaboratorConfig {
  dnsActive: boolean
  dnsError?: string
}

// Callback addresses detected by the server (LAN from network interfaces,
// public from an external lookup service). Empty fields mean not detected.
export interface CollaboratorAddresses {
  localIp?: string
  localBase?: string
  publicIp?: string
  publicBase?: string
  collabPort: string
  publicError?: string
}

export interface CollaboratorInteraction {
  id: string
  protocol: 'http' | 'dns'
  timestamp: string
  remoteAddr: string
  method?: string
  path?: string
  query?: string
  headers?: Record<string, string>
  body?: string
  queryName?: string
  queryType?: string
  // identifier is the caller-chosen label that precedes the token itself in
  // whatever address was hit (e.g. "ssrf-webhook_url") -- lets one shared,
  // long-lived token be reused across many concurrent tests while each hit
  // still says which one caused it. Empty for a bare "/collab/<token>" hit.
  identifier?: string
}

export interface CollaboratorNewTokenResponse {
  token: string
  httpCallback: string
  dnsHostname?: string
  dnsAvailable: boolean
}

// WebhookSiteToken mirrors collaborator.WebhookSiteToken -- webhook.site as
// an alternative callback provider alongside Aperture's own listener above,
// for a quick link (plus webhook.site's own hosted view of it) with zero
// configuration.
export interface WebhookSiteToken {
  uuid: string
  url: string
  viewUrl: string
}

// ActiveCallbackServer mirrors collaborator.Session -- one entry in a
// scanner's Callback picker dropdown (see CallbackPicker.tsx), minted from
// either the Collaborator tab or the picker's own "+ New" action.
export interface ActiveCallbackServer {
  token: string
  provider: 'aperture' | 'webhooksite'
  label: string
  httpCallback: string
  dnsHostname?: string
  viewUrl?: string
  // One callback URL per network path; each field is absent when that path
  // wasn't detected (see collaborator.Links).
  links?: CallbackLinks
  createdAt: string
}

export interface CallbackLinks {
  localhost?: string
  private?: string
  public?: string
  localhostTls?: string
  privateTls?: string
  publicTls?: string
}

// CollabTLSStatus is the callback listener's HTTPS side: whether it accepts
// TLS, and the stored self-signed certificate's details when one exists.
export interface CollabTLSStatus {
  enabled: boolean
  hasCert: boolean
  cert?: {
    fingerprint: string
    notBefore: string
    notAfter: string
    subjects: string[]
  }
}

// CallbackSelection mirrors collaborator.Ref -- which ActiveCallbackServer a
// scanner's request opted into (see CallbackPicker.tsx), included verbatim
// as a scan request's own "callback" field.
export interface CallbackSelection {
  provider: 'aperture' | 'webhooksite'
  token: string
}

// RequestRecord mirrors internal/store.RequestRecord: one HTTP exchange a
// native scanner made during a node. The list endpoint leaves requestRaw and
// responseRaw empty; the detail endpoint fills them in.
export interface RequestRecord {
  id: number
  method: string
  url: string
  host: string
  statusCode: number
  size: number
  ttfbMs: number
  error?: string
  requestRaw?: string
  responseRaw?: string
  timestamp: string
  // ref names this exchange; fromRef names the 3xx exchange whose redirect led
  // to it. Empty for a request that wasn't reached by a redirect.
  ref?: string
  fromRef?: string
  // hit is true when a finding the scan reported captured this request.
  hit?: boolean
  // location is the Location header of a 3xx response.
  location?: string
  // callbackCount is how many collaborator hits this redirect's Location led to.
  // It is set on list rows.
  callbackCount?: number
  // callbacks lists those hits in full. It is set on the detail record only.
  callbacks?: CallbackHit[]
}

// CallbackHit is one interaction the collaborator recorded on a token that a
// redirect's Location named.
export interface CallbackHit {
  id: string
  protocol: string
  timestamp: string
  remoteAddr: string
  method?: string
  path?: string
  query?: string
  identifier?: string
}

// NodeRequestLog mirrors api.requestLogResponse: one node's request log plus
// the cap that log is held to (see engine.MaxRecordedExchangesPerNode).
export interface NodeRequestLog {
  requests: RequestRecord[]
  limit: number
}
