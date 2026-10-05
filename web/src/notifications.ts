import { setNotificationTap, watchEvents } from './api'
import type { RunEvent } from './types'
import { showToast } from './toast'

// This module is Aperture's notification engine: it taps the single
// WebSocket chokepoint every scanner streams through (see setNotificationTap
// in api.ts) plus the global events socket, folds each event into a small
// per-scan fact table, and evaluates the operator's own notification rules
// against it. A rule is a set of conditions combined with a boolean operator
// (AND/OR/XOR/XAND/NOR/NAND); when its combined value goes from false to true
// the rule fires, producing a toast, a notification-center entry, and
// optionally a desktop notification and/or a sound.
//
// Everything here is per-browser (persisted in localStorage, like the theme
// picker) -- it never touches the backend, because the events it reacts to
// already arrive in the browser and the rules are a display preference, not
// account state.

// --- Rule model -------------------------------------------------------------

// NotifSeverity is the finding-severity ladder the engine understands, worst
// last (see SEVERITY_RANK).
export type NotifSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical'

// ConditionType is one testable fact about a scan (or the host it targets).
// Each maps to a field accumulated on ScanState as events stream in.
export type ConditionType =
  | 'severity' // a finding at/above (or exactly) a given severity appeared
  | 'callback' // the target proved a finding by calling back
  | 'scanStarted' // a scan began streaming
  | 'scanFinished' // a scan reached its terminal "done" event
  | 'findingCount' // the running finding total reached a threshold
  | 'throttled' // the host throttled our requests
  | 'drift' // the host's responses drifted (results now suspect)
  | 'hostBlocked' // the host blocked us / the circuit breaker opened
  | 'recovered' // the host recovered after throttling/blocking
  | 'tool' // guard: the scan was run by a given tool bucket

// SEVERITY_RANK orders severities so "at least X" is a single comparison.
const SEVERITY_RANK: Record<NotifSeverity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }

// Combinator is how a rule folds its conditions' individual truth values into
// one. AND/OR/NAND/NOR are the usual gates; XOR is odd-parity (an odd number
// of conditions true) and XAND is its complement, XNOR (an even number true,
// including zero). The exotic gates are included because the user asked for
// them; per-condition `negate` (below) is usually the cleaner tool for
// everyday rules.
export type Combinator = 'AND' | 'OR' | 'XOR' | 'XAND' | 'NOR' | 'NAND'

export const COMBINATORS: { value: Combinator; label: string; help: string }[] = [
  { value: 'AND', label: 'AND', help: 'Fires only when every condition is true.' },
  { value: 'OR', label: 'OR', help: 'Fires when at least one condition is true.' },
  { value: 'XOR', label: 'XOR', help: 'Fires when an odd number of conditions are true.' },
  { value: 'XAND', label: 'XAND (XNOR)', help: 'Fires when an even number of conditions are true (including none).' },
  { value: 'NOR', label: 'NOR', help: 'Fires when no condition is true.' },
  { value: 'NAND', label: 'NAND', help: 'Fires unless every condition is true.' },
]

// Condition is one row in a rule. Only the fields its `type` uses are read;
// `negate` inverts that single condition before the combinator sees it.
export interface Condition {
  id: string
  type: ConditionType
  severity?: NotifSeverity // for type === 'severity'
  severityMode?: 'atLeast' | 'exactly' // for type === 'severity'
  count?: number // for type === 'findingCount'
  tool?: string // for type === 'tool'
  negate?: boolean
}

// NotifChannel is one way a fired notification can reach the operator. A rule
// can use any combination.
export interface Channels {
  toast: boolean
  center: boolean
  desktop: boolean
  sound: boolean
}

// NotificationRule is one user-configured alert. messageMode/colorMode pick
// between the engine's sensible default (derived from the matched conditions)
// and the operator's own override.
export interface NotificationRule {
  id: string
  name: string
  enabled: boolean
  conditions: Condition[]
  combinator: Combinator
  messageMode: 'default' | 'custom'
  message: string
  colorMode: 'default' | 'custom'
  color: string
  channels: Channels
}

// --- Default colors ---------------------------------------------------------

// SEVERITY_COLOR mirrors INDICATOR_COLOR in scanIndicator.ts so a
// notification's default accent matches the case-nav border for the same
// severity. HOST_COLOR/FINISHED_COLOR/INFO_COLOR cover the non-finding facts.
export const SEVERITY_COLOR: Record<NotifSeverity | 'callback', string> = {
  info: '#38bdf8',
  low: '#facc15',
  medium: '#fb923c',
  high: '#ef4444',
  critical: '#b91c1c',
  callback: '#d946ef',
}
const HOST_COLOR = '#f59e0b' // amber: a host pushing back on us
const FINISHED_COLOR = '#22c55e' // green: a scan completed
const NEUTRAL_COLOR = '#64748b' // slate: nothing more specific

// --- Scan fact table --------------------------------------------------------

// ScanState is everything the engine has learned about one scan stream (keyed
// by scanId), or about the session as a whole (key 'session', used for host
// events that arrive with no scan in flight). Conditions are evaluated against
// one of these.
interface ScanState {
  key: string
  tool: string
  severities: Set<NotifSeverity>
  callback: boolean
  findingCount: number
  started: boolean
  finished: boolean
  throttled: boolean
  drift: boolean
  blocked: boolean
  recovered: boolean
}

function newScanState(key: string, tool: string): ScanState {
  // A fresh state has seen nothing; every fact starts false/empty.
  return {
    key,
    tool,
    severities: new Set(),
    callback: false,
    findingCount: 0,
    started: false,
    finished: false,
    throttled: false,
    drift: false,
    blocked: false,
    recovered: false,
  }
}

// --- Fired notifications (the notification center's feed) --------------------

// FiredNotification is one alert that actually went off, kept for the
// notification center. `read` drives the unread badge.
export interface FiredNotification {
  id: number
  ruleId: string
  ruleName: string
  message: string
  color: string
  at: number
  read: boolean
}

// --- Persistence -------------------------------------------------------------

const RULES_KEY = 'aperture.notificationRules'
const MAX_CENTER = 100 // cap the stored feed so it can't grow without bound

// uid returns a short unique id for a rule or condition.
function uid(): string {
  return Math.random().toString(36).slice(2, 10)
}

// defaultChannels is what a new rule alerts through until the user says
// otherwise: an on-screen toast and a center entry, but nothing intrusive.
function defaultChannels(): Channels {
  return { toast: true, center: true, desktop: false, sound: false }
}

// SEED_RULES are the examples a fresh install starts with -- each one
// demonstrates a different corner of the system (a severity trigger, a
// callback trigger, a chained AND rule, and a host-health trigger) so the
// settings page is never an empty void.
function seedRules(): NotificationRule[] {
  return [
    {
      id: uid(),
      name: 'Critical or high finding',
      enabled: true,
      conditions: [{ id: uid(), type: 'severity', severity: 'high', severityMode: 'atLeast' }],
      combinator: 'OR',
      messageMode: 'default',
      message: '',
      colorMode: 'default',
      color: SEVERITY_COLOR.high,
      channels: { toast: true, center: true, desktop: true, sound: false },
    },
    {
      id: uid(),
      name: 'Callback received',
      enabled: true,
      conditions: [{ id: uid(), type: 'callback' }],
      combinator: 'OR',
      messageMode: 'default',
      message: '',
      colorMode: 'default',
      color: SEVERITY_COLOR.callback,
      channels: { toast: true, center: true, desktop: true, sound: true },
    },
    {
      id: uid(),
      name: 'Scan finished clean',
      enabled: false,
      // scanFinished AND NOT (anything medium or worse) -- a quiet "all done,
      // nothing serious" ping. Shows off per-condition negate + AND.
      conditions: [
        { id: uid(), type: 'scanFinished' },
        { id: uid(), type: 'severity', severity: 'medium', severityMode: 'atLeast', negate: true },
      ],
      combinator: 'AND',
      messageMode: 'default',
      message: '',
      colorMode: 'default',
      color: FINISHED_COLOR,
      channels: defaultChannels(),
    },
    {
      id: uid(),
      name: 'Host throttling us',
      enabled: true,
      conditions: [{ id: uid(), type: 'throttled' }],
      combinator: 'OR',
      messageMode: 'default',
      message: '',
      colorMode: 'default',
      color: HOST_COLOR,
      channels: { toast: true, center: true, desktop: false, sound: false },
    },
  ]
}

let rules: NotificationRule[] = loadRules()

// loadRules reads the saved rules, falling back to the seed set on a fresh
// install or any parse failure (a corrupt blob should never wedge the app).
function loadRules(): NotificationRule[] {
  try {
    const raw = localStorage.getItem(RULES_KEY)
    if (!raw) return seedRules()
    const parsed = JSON.parse(raw)
    if (!Array.isArray(parsed)) return seedRules()
    return parsed as NotificationRule[]
  } catch {
    return seedRules()
  }
}

// getRules returns the current rule set (a copy, so callers can't mutate the
// engine's array in place).
export function getRules(): NotificationRule[] {
  return rules.map((r) => ({ ...r, conditions: r.conditions.map((c) => ({ ...c })), channels: { ...r.channels } }))
}

// saveRules replaces the rule set, persists it, and notifies subscribers.
// Writing is wrapped because localStorage can throw (private mode, quota).
export function saveRules(next: NotificationRule[]): void {
  rules = next
  try {
    localStorage.setItem(RULES_KEY, JSON.stringify(next))
  } catch {
    // a failed persist still updates the in-memory rules for this session
  }
  for (const fn of ruleListeners) fn(getRules())
}

// newRule builds a blank rule for the "add rule" button.
export function newRule(): NotificationRule {
  return {
    id: uid(),
    name: 'New notification',
    enabled: true,
    conditions: [{ id: uid(), type: 'severity', severity: 'critical', severityMode: 'atLeast' }],
    combinator: 'OR',
    messageMode: 'default',
    message: '',
    colorMode: 'default',
    color: SEVERITY_COLOR.critical,
    channels: defaultChannels(),
  }
}

// newCondition builds a blank condition of a given type for the "add
// condition" button, seeding the fields that type needs.
export function newCondition(type: ConditionType = 'severity'): Condition {
  return { id: uid(), type, severity: 'high', severityMode: 'atLeast', count: 1, tool: 'probe' }
}

// --- Subscriptions -----------------------------------------------------------

let ruleListeners: ((rules: NotificationRule[]) => void)[] = []
let feedListeners: ((feed: FiredNotification[]) => void)[] = []

// subscribeRules lets a component (the settings editor) react to rule changes
// made elsewhere. Returns an unsubscribe function.
export function subscribeRules(fn: (rules: NotificationRule[]) => void): () => void {
  ruleListeners.push(fn)
  return () => {
    ruleListeners = ruleListeners.filter((l) => l !== fn)
  }
}

// subscribeFeed lets the notification center react to fired notifications and
// read/clear changes. Returns an unsubscribe function.
export function subscribeFeed(fn: (feed: FiredNotification[]) => void): () => void {
  feedListeners.push(fn)
  return () => {
    feedListeners = feedListeners.filter((l) => l !== fn)
  }
}

// --- Notification center feed ------------------------------------------------

let feed: FiredNotification[] = []
let nextFeedId = 1

function emitFeed() {
  for (const fn of feedListeners) fn(getFeed())
}

export function getFeed(): FiredNotification[] {
  return feed.map((n) => ({ ...n }))
}

export function unreadCount(): number {
  // Count entries the operator hasn't opened the center on yet.
  return feed.filter((n) => !n.read).length
}

export function markAllRead(): void {
  feed = feed.map((n) => ({ ...n, read: true }))
  emitFeed()
}

export function clearFeed(): void {
  feed = []
  emitFeed()
}

export function dismissNotification(id: number): void {
  feed = feed.filter((n) => n.id !== id)
  emitFeed()
}

// --- Condition evaluation ----------------------------------------------------

// evalCondition returns one condition's truth value against a scan state,
// after applying its own negate flag.
function evalCondition(c: Condition, st: ScanState): boolean {
  let v = false
  switch (c.type) {
    case 'severity': {
      // Either "exactly this severity" or "this severity or worse" appeared.
      const want = c.severity ?? 'critical'
      if (c.severityMode === 'exactly') {
        v = st.severities.has(want)
      } else {
        const threshold = SEVERITY_RANK[want]
        for (const s of st.severities) {
          if (SEVERITY_RANK[s] >= threshold) {
            v = true
            break
          }
        }
      }
      break
    }
    case 'callback':
      v = st.callback
      break
    case 'scanStarted':
      v = st.started
      break
    case 'scanFinished':
      v = st.finished
      break
    case 'findingCount':
      v = st.findingCount >= (c.count ?? 1)
      break
    case 'throttled':
      v = st.throttled
      break
    case 'drift':
      v = st.drift
      break
    case 'hostBlocked':
      v = st.blocked
      break
    case 'recovered':
      v = st.recovered
      break
    case 'tool':
      v = !!c.tool && st.tool === c.tool
      break
  }
  return c.negate ? !v : v
}

// combine folds a rule's per-condition truth values into its final value per
// the chosen combinator. An empty rule never fires.
function combine(combinator: Combinator, bools: boolean[]): boolean {
  if (bools.length === 0) return false
  const trueCount = bools.filter(Boolean).length
  switch (combinator) {
    case 'AND':
      return trueCount === bools.length
    case 'OR':
      return trueCount > 0
    case 'NAND':
      return trueCount !== bools.length
    case 'NOR':
      return trueCount === 0
    case 'XOR':
      return trueCount % 2 === 1
    case 'XAND':
      return trueCount % 2 === 0
  }
}

// --- Default message/color ---------------------------------------------------

const SEVERITY_LABEL: Record<NotifSeverity, string> = {
  info: 'Info',
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
}

// describeCondition renders one condition as a short human phrase, used to
// build a rule's default message.
function describeCondition(c: Condition): string {
  const not = c.negate ? 'no ' : ''
  switch (c.type) {
    case 'severity': {
      const sev = SEVERITY_LABEL[c.severity ?? 'critical'].toLowerCase()
      return `${not}${sev}${c.severityMode === 'exactly' ? '' : '+'} finding`
    }
    case 'callback':
      return `${not}callback received`
    case 'scanStarted':
      return `${not}scan started`
    case 'scanFinished':
      return `${not}scan finished`
    case 'findingCount':
      return `${not}≥${c.count ?? 1} findings`
    case 'throttled':
      return `${not}host throttling`
    case 'drift':
      return `${not}response drift`
    case 'hostBlocked':
      return `${not}host blocked us`
    case 'recovered':
      return `${not}host recovered`
    case 'tool':
      return `${not}tool is ${c.tool ?? '?'}`
  }
}

// defaultMessage builds the text shown when a rule is on messageMode
// 'default': its conditions joined by the combinator, plus the host if a host
// event drove it.
export function defaultMessage(rule: NotificationRule, st: ScanState, host?: string): string {
  const joiner = ` ${rule.combinator} `
  const parts = rule.conditions.map(describeCondition)
  let text = parts.join(joiner)
  // Name the host for host-health rules, and the tool otherwise, so the
  // message says *where* as well as *what*.
  if (host) {
    text += ` — ${host}`
  } else if (st.tool && st.tool !== 'session') {
    text += ` — ${st.tool}`
  }
  return text
}

// defaultColorForRule picks a rule's default accent from its conditions: the
// worst severity it references, else a callback/host/finished hint, else
// neutral. Used both when colorMode is 'default' and as the starting color
// for the custom picker.
export function defaultColorForRule(rule: NotificationRule): string {
  let worst: NotifSeverity | null = null
  let hasCallback = false
  let hasHost = false
  let hasFinished = false
  for (const c of rule.conditions) {
    if (c.type === 'severity' && c.severity && !c.negate) {
      if (worst === null || SEVERITY_RANK[c.severity] > SEVERITY_RANK[worst]) worst = c.severity
    }
    if (c.type === 'callback') hasCallback = true
    if (c.type === 'throttled' || c.type === 'drift' || c.type === 'hostBlocked') hasHost = true
    if (c.type === 'scanFinished') hasFinished = true
  }
  if (hasCallback) return SEVERITY_COLOR.callback
  if (worst) return SEVERITY_COLOR[worst]
  if (hasHost) return HOST_COLOR
  if (hasFinished) return FINISHED_COLOR
  return NEUTRAL_COLOR
}

// --- Rising-edge firing ------------------------------------------------------

// lastValue remembers each (ruleId:stateKey) pair's last combined truth value
// so a rule fires once on the false->true edge, not on every event while it
// stays true.
const lastValue = new Map<string, boolean>()

function edgeKey(ruleId: string, stateKey: string): string {
  return ruleId + '\u0000' + stateKey
}

// evaluate runs every enabled rule against one scan state and fires the ones
// that just transitioned to true. host is set only when a host event drove
// this evaluation, so the default message can name it.
function evaluate(st: ScanState, host?: string): void {
  // Each rule is edge-detected independently against this state.
  for (const rule of rules) {
    if (!rule.enabled) continue
    const value = combine(rule.combinator, rule.conditions.map((c) => evalCondition(c, st)))
    const key = edgeKey(rule.id, st.key)
    const was = lastValue.get(key) ?? false
    lastValue.set(key, value)
    // Fire only on the rising edge.
    if (value && !was) fire(rule, st, host)
  }
}

// fire delivers one rule's notification across its enabled channels.
function fire(rule: NotificationRule, st: ScanState, host?: string): void {
  const message = rule.messageMode === 'custom' && rule.message.trim() !== '' ? rule.message : defaultMessage(rule, st, host)
  const color = rule.colorMode === 'custom' ? rule.color : defaultColorForRule(rule)

  // Notification center: prepend, cap the backlog.
  if (rule.channels.center) {
    feed = [{ id: nextFeedId++, ruleId: rule.id, ruleName: rule.name, message, color, at: Date.now(), read: false }, ...feed].slice(0, MAX_CENTER)
    emitFeed()
  }
  // Toast: reuse the app's toast host, tinted to the rule's color.
  if (rule.channels.toast) {
    showToast(message, 'info', { color, title: rule.name })
  }
  // Desktop: only if the operator has already granted permission.
  if (rule.channels.desktop) showDesktop(rule.name, message)
  // Sound: a short synthesized chime, no asset to ship.
  if (rule.channels.sound) playChime()
}

// showDesktop posts an OS notification when permission is granted. It never
// prompts here -- the settings page asks for permission explicitly so a scan
// finishing doesn't trigger a surprise browser prompt.
function showDesktop(title: string, body: string): void {
  try {
    if (typeof Notification !== 'undefined' && Notification.permission === 'granted') {
      new Notification(title, { body })
    }
  } catch {
    // some browsers throw constructing Notification outside a user gesture
  }
}

// requestDesktopPermission asks the browser for notification permission, from
// a user click in settings. Returns the resulting permission string.
export async function requestDesktopPermission(): Promise<string> {
  try {
    if (typeof Notification === 'undefined') return 'denied'
    return await Notification.requestPermission()
  } catch {
    return 'denied'
  }
}

// desktopPermission reports the current permission so the UI can show whether
// desktop notifications will actually appear.
export function desktopPermission(): string {
  try {
    return typeof Notification === 'undefined' ? 'unsupported' : Notification.permission
  } catch {
    return 'unsupported'
  }
}

// playChime synthesizes a brief two-tone chime with the Web Audio API so the
// sound channel needs no bundled audio file.
function playChime(): void {
  try {
    const Ctx = window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext
    const ctx = new Ctx()
    const now = ctx.currentTime
    // Two short descending notes.
    for (const [i, freq] of [880, 660].entries()) {
      const osc = ctx.createOscillator()
      const gain = ctx.createGain()
      osc.frequency.value = freq
      osc.type = 'sine'
      const start = now + i * 0.12
      gain.gain.setValueAtTime(0.0001, start)
      gain.gain.exponentialRampToValueAtTime(0.2, start + 0.01)
      gain.gain.exponentialRampToValueAtTime(0.0001, start + 0.11)
      osc.connect(gain).connect(ctx.destination)
      osc.start(start)
      osc.stop(start + 0.12)
    }
    // Release the context shortly after the sound finishes.
    setTimeout(() => ctx.close().catch(() => {}), 500)
  } catch {
    // audio is a nicety; never let it throw into the engine
  }
}

// --- Event ingestion ---------------------------------------------------------

// scans holds the live fact table, keyed by scanId (plus the 'session' row).
const scans = new Map<string, ScanState>()

// SESSION_KEY is the fact row host events fall back to when no scan is active,
// so a throttling rule can still fire outside any scan.
const SESSION_KEY = 'session'

// scanKeyFromPath pulls (bucket, id) out of a socket path like
// "/ws/probe/<uuid>" -- bucket names the tool, id keys the fact row. Returns
// null for the global events socket, which carries no per-scan id.
function scanKeyFromPath(path: string): { tool: string; id: string } | null {
  const parts = path.split('/').filter(Boolean) // ["ws", bucket, id]
  if (parts.length < 3 || parts[0] !== 'ws') return null
  if (parts[1] === 'events') return null
  return { tool: parts[1], id: parts[2] }
}

// stateFor returns the fact row for a scan, creating it (and firing any
// scan-start edge) on first contact.
function stateFor(tool: string, id: string): ScanState {
  let st = scans.get(id)
  // First event for this scan: create the row and mark it started.
  if (!st) {
    st = newScanState(id, tool)
    scans.set(id, st)
  }
  return st
}

// addSeverity records a severity on a state and bumps the running count. info
// is recorded too (SEVERITY_RANK ranks it lowest), so an "at least info" rule
// can match while "at least low" still ignores it.
function addSeverity(st: ScanState, sev: NotifSeverity | undefined, n: number): void {
  if (sev) st.severities.add(sev)
  st.findingCount += n
}

// normSeverity maps an arbitrary severity string onto NotifSeverity, or
// undefined if it isn't one of the five.
function normSeverity(s: string | undefined): NotifSeverity | undefined {
  switch (s) {
    case 'info':
    case 'low':
    case 'medium':
    case 'high':
    case 'critical':
      return s
    default:
      return undefined
  }
}

// moduleShape is the common {severity, findings:[{callback?}]} shape every
// per-module scanner result shares (ProbeModuleResult, DomainScanModuleResult,
// and the modules array inside a streamed scan's final result).
interface ModuleShape {
  severity?: string
  findings?: { callback?: boolean }[]
}

// foldModule folds one module result into a scan state: its severity, its
// finding count, and whether any finding is callback-confirmed.
function foldModule(st: ScanState, m: ModuleShape): void {
  const findings = m.findings ?? []
  if (findings.length === 0) return
  addSeverity(st, normSeverity(m.severity), findings.length)
  // A callback on any finding promotes the whole module to "proven".
  if (findings.some((f) => f && f.callback === true)) st.callback = true
}

// extractModules best-effort pulls a modules array out of a streamed scan's
// terminal result payload, so scanners that only stream per-check counts (not
// per-module results) still contribute severities/callbacks when they finish.
function extractModules(result: unknown): ModuleShape[] {
  if (result && typeof result === 'object' && Array.isArray((result as { modules?: unknown[] }).modules)) {
    return (result as { modules: ModuleShape[] }).modules
  }
  return []
}

// applyHostEvent folds one host event into every state it should touch: every
// still-running scan (so "critical AND throttled" works within a scan) and the
// session row (so a throttling-only rule fires even with no scan tracked).
function applyHostEvent(kind: string, host: string): void {
  // Pick the flag this netgov kind sets.
  const apply = (st: ScanState) => {
    switch (kind) {
      case 'throttled':
        st.throttled = true
        break
      case 'drift':
        st.drift = true
        break
      case 'host-blocked':
      case 'breaker-open':
        st.blocked = true
        break
      case 'recovered':
        st.recovered = true
        break
      default:
        return // rebaselined and anything unknown carry no rule-visible fact
    }
  }

  // The session row always gets it.
  const session = scans.get(SESSION_KEY) ?? newScanState(SESSION_KEY, 'session')
  scans.set(SESSION_KEY, session)
  apply(session)
  evaluate(session, host)

  // Every unfinished scan row gets it too.
  for (const st of scans.values()) {
    if (st.key === SESSION_KEY || st.finished) continue
    apply(st)
    evaluate(st, host)
  }
}

// ingest is the tap: one streamed event, folded into the fact table, with any
// rule edges it triggers fired. Set as the notification tap in init().
function ingest(path: string, ev: RunEvent): void {
  // Host events arrive on the global socket with no scan id.
  if (ev.type === 'hostEvent') {
    applyHostEvent(ev.hostKind ?? '', ev.host ?? '')
    return
  }

  const loc = scanKeyFromPath(path)
  if (!loc) return
  const st = stateFor(loc.tool, loc.id)

  // The first event for a scan is also its "started" edge.
  if (!st.started) {
    st.started = true
    evaluate(st)
  }

  switch (ev.type) {
    case 'module':
      if (ev.module) foldModule(st, ev.module as ModuleShape)
      evaluate(st)
      break
    case 'domainModule':
      if (ev.domainModule) foldModule(st, ev.domainModule as ModuleShape)
      evaluate(st)
      break
    case 'finding':
      // Engine-backed jobs stream individual findings with a severity string.
      if (ev.finding) addSeverity(st, normSeverity(ev.finding.severity), 1)
      evaluate(st)
      break
    case 'checkDone':
      // Streamed scanners report only a per-check finding count mid-run; the
      // severities arrive with the terminal result below.
      if (ev.findings) st.findingCount += ev.findings
      evaluate(st)
      break
    case 'done': {
      // Fold any modules carried in the final result so severity/callback
      // facts are complete before the scanFinished edge is evaluated.
      for (const m of extractModules(ev.result)) foldModule(st, m)
      st.finished = true
      evaluate(st)
      // Drop the row on the next tick so a re-run starts fresh and its edges
      // re-arm (also clears the edge-detector entries for this state).
      const key = st.key
      setTimeout(() => {
        scans.delete(key)
        for (const r of rules) lastValue.delete(edgeKey(r.id, key))
      }, 0)
      break
    }
  }
}

// --- Wiring ------------------------------------------------------------------

let started = false
let closeEvents: (() => void) | null = null

// initNotifications wires the engine up once: it registers the socket tap and
// opens the global events socket. Call it once the operator is authenticated
// (the events socket needs the session cookie). Safe to call repeatedly.
export function initNotifications(): void {
  if (started) return
  started = true
  setNotificationTap(ingest)
  openEventsSocket()
}

// openEventsSocket keeps a single /ws/events connection alive, reconnecting a
// few seconds after a drop so host-event notifications keep working across a
// transient blip (a backend restart, say).
function openEventsSocket(): void {
  closeEvents = watchEvents(
    () => {
      // Host events are handled through the tap (ingest sees them with the
      // "/ws/events" path), so nothing to do here.
    },
    () => {
      closeEvents = null
      setTimeout(openEventsSocket, 4000)
    },
  )
}

// stopNotifications tears the engine down (used when the operator logs out).
export function stopNotifications(): void {
  started = false
  setNotificationTap(null)
  if (closeEvents) {
    closeEvents()
    closeEvents = null
  }
}
