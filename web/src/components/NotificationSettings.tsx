import { useEffect, useState } from 'react'
import { inputBase } from '../formStyles'
import {
  COMBINATORS,
  defaultColorForRule,
  defaultMessage,
  desktopPermission,
  getRules,
  newCondition,
  newRule,
  requestDesktopPermission,
  saveRules,
  subscribeRules,
  type Combinator,
  type Condition,
  type ConditionType,
  type NotificationRule,
  type NotifSeverity,
} from '../notifications'

// CONDITION_TYPES lists every testable fact a condition can be, with a label
// for the dropdown. Order is roughly most-common first.
const CONDITION_TYPES: { value: ConditionType; label: string }[] = [
  { value: 'severity', label: 'Finding severity' },
  { value: 'callback', label: 'Callback received' },
  { value: 'scanFinished', label: 'Scan finished' },
  { value: 'scanStarted', label: 'Scan started' },
  { value: 'findingCount', label: 'Finding count' },
  { value: 'throttled', label: 'Host throttling us' },
  { value: 'drift', label: 'Response drift' },
  { value: 'hostBlocked', label: 'Host blocked us' },
  { value: 'recovered', label: 'Host recovered' },
  { value: 'tool', label: 'Tool is…' },
]

const SEVERITIES: NotifSeverity[] = ['info', 'low', 'medium', 'high', 'critical']

// TOOL_BUCKETS are the socket buckets a 'tool' condition can match -- they
// mirror the /ws/<bucket>/<id> paths the engine keys scans by (see
// scanKeyFromPath in notifications.ts).
const TOOL_BUCKETS = ['probe', 'domainscan', 'apienum', 'scans', 'jobs']

// NotificationSettings is the Notifications tab of the settings page: the full
// rule editor. It reads/writes the engine's rule set directly (localStorage,
// per browser) so changes take effect on the next streamed event without a
// save button.
export function NotificationSettings() {
  const [rules, setRules] = useState<NotificationRule[]>(() => getRules())
  const [perm, setPerm] = useState<string>(() => desktopPermission())

  // Stay in sync if rules change elsewhere (unlikely, but cheap).
  useEffect(() => subscribeRules(setRules), [])

  // commit writes the whole set back to the engine (and localStorage).
  const commit = (next: NotificationRule[]) => {
    saveRules(next)
    setRules(next)
  }

  // updateRule replaces one rule by id.
  const updateRule = (id: string, patch: Partial<NotificationRule>) => {
    commit(rules.map((r) => (r.id === id ? { ...r, ...patch } : r)))
  }

  const addRule = () => commit([...rules, newRule()])
  const deleteRule = (id: string) => commit(rules.filter((r) => r.id !== id))

  const askDesktop = async () => {
    const result = await requestDesktopPermission()
    setPerm(result)
  }

  // Whether any rule routes to the desktop, so the permission prompt is only
  // offered when it is actually needed.
  const usesDesktop = rules.some((r) => r.channels.desktop)

  return (
    <div className="space-y-4">
      <div className="space-y-2 rounded-lg border border-neutral-800 bg-neutral-900 p-4">
        <h2 className="text-sm font-medium text-neutral-100">Notification rules</h2>
        <p className="text-xs text-neutral-500">
          Each rule watches the scans you run in this browser and fires when its conditions combine to true. Chain several conditions with a boolean
          operator, write your own message and color or keep the defaults, and pick where the alert shows up. Rules are stored in this browser only.
        </p>
        {usesDesktop && perm !== 'granted' && (
          <div className="flex items-center gap-2 rounded border border-amber-800/60 bg-amber-950/30 px-3 py-2 text-xs text-amber-300">
            <span className="flex-1">
              {perm === 'denied'
                ? 'Desktop notifications are blocked in your browser settings — rules set to “Desktop” will fall back to toasts.'
                : 'One or more rules want desktop notifications. Your browser needs permission first.'}
            </span>
            {perm !== 'denied' && (
              <button onClick={askDesktop} className="rounded bg-amber-600 px-2.5 py-1 font-medium text-white hover:bg-amber-500">
                Enable
              </button>
            )}
          </div>
        )}
      </div>

      {rules.map((rule) => (
        <RuleCard key={rule.id} rule={rule} onChange={(patch) => updateRule(rule.id, patch)} onDelete={() => deleteRule(rule.id)} />
      ))}

      <button onClick={addRule} className="w-full rounded-lg border border-dashed border-neutral-700 py-2.5 text-xs font-medium text-neutral-400 hover:border-sky-600 hover:text-sky-400">
        + Add rule
      </button>
    </div>
  )
}

// RuleCard edits one rule: its name/enabled toggle, its conditions and the
// combinator joining them, the message and color (default or custom), and its
// channels.
function RuleCard({ rule, onChange, onDelete }: { rule: NotificationRule; onChange: (patch: Partial<NotificationRule>) => void; onDelete: () => void }) {
  // The default message is previewed live so the operator sees what they'd get
  // before switching to a custom one. A throwaway session state drives it.
  const previewMessage = defaultMessage(rule, { key: '', tool: rule.conditions.find((c) => c.type === 'tool')?.tool ?? '', severities: new Set(), callback: false, findingCount: 0, started: false, finished: false, throttled: false, drift: false, blocked: false, recovered: false })
  const defaultColor = defaultColorForRule(rule)
  const effectiveColor = rule.colorMode === 'custom' ? rule.color : defaultColor

  // updateCondition replaces one condition within this rule.
  const updateCondition = (id: string, patch: Partial<Condition>) => {
    onChange({ conditions: rule.conditions.map((c) => (c.id === id ? { ...c, ...patch } : c)) })
  }
  const addCondition = () => onChange({ conditions: [...rule.conditions, newCondition()] })
  const removeCondition = (id: string) => onChange({ conditions: rule.conditions.filter((c) => c.id !== id) })

  return (
    <div className={`space-y-3 rounded-lg border bg-neutral-900 p-4 ${rule.enabled ? 'border-neutral-800' : 'border-neutral-800/50 opacity-70'}`} style={{ borderLeft: `3px solid ${effectiveColor}` }}>
      {/* Header: enable toggle, name, delete. */}
      <div className="flex items-center gap-2">
        <input type="checkbox" checked={rule.enabled} onChange={(e) => onChange({ enabled: e.target.checked })} className="h-4 w-4 accent-sky-500" title={rule.enabled ? 'Enabled' : 'Disabled'} />
        <input value={rule.name} onChange={(e) => onChange({ name: e.target.value })} className="flex-1 rounded border border-transparent bg-transparent px-1 py-0.5 text-sm font-medium text-neutral-100 hover:border-neutral-700 focus:border-sky-500 focus:bg-neutral-950 focus:outline-none" />
        <button onClick={onDelete} className="rounded border border-neutral-700 px-2 py-1 text-xs text-neutral-400 hover:border-red-500 hover:text-red-400" title="Delete rule">
          Delete
        </button>
      </div>

      {/* Conditions. */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-semibold uppercase tracking-wide text-neutral-500">When…</span>
          {rule.conditions.length > 1 && <CombinatorPicker value={rule.combinator} onChange={(combinator) => onChange({ combinator })} />}
        </div>
        {rule.conditions.map((c, i) => (
          <div key={c.id}>
            {/* The combinator word appears between consecutive conditions. */}
            {i > 0 && <div className="py-0.5 pl-1 text-[10px] font-semibold uppercase tracking-wider text-sky-500/80">{rule.combinator}</div>}
            <ConditionRow c={c} onChange={(patch) => updateCondition(c.id, patch)} onRemove={rule.conditions.length > 1 ? () => removeCondition(c.id) : undefined} />
          </div>
        ))}
        <button onClick={addCondition} className="text-[11px] text-neutral-500 hover:text-sky-400">
          + Add condition
        </button>
      </div>

      {/* Message. */}
      <div className="space-y-1.5">
        <div className="flex items-center gap-3">
          <span className="text-[11px] font-semibold uppercase tracking-wide text-neutral-500">Message</span>
          <Segmented value={rule.messageMode} options={[{ v: 'default', l: 'Default' }, { v: 'custom', l: 'Custom' }]} onChange={(messageMode) => onChange({ messageMode: messageMode as 'default' | 'custom' })} />
        </div>
        {rule.messageMode === 'default' ? (
          <p className="rounded border border-neutral-800 bg-neutral-950 px-2.5 py-1.5 text-xs text-neutral-400">{previewMessage}</p>
        ) : (
          <input value={rule.message} onChange={(e) => onChange({ message: e.target.value })} placeholder={previewMessage} className={inputBase} />
        )}
      </div>

      {/* Color. */}
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-[11px] font-semibold uppercase tracking-wide text-neutral-500">Color</span>
        <Segmented value={rule.colorMode} options={[{ v: 'default', l: 'Default' }, { v: 'custom', l: 'Custom' }]} onChange={(colorMode) => onChange({ colorMode: colorMode as 'default' | 'custom' })} />
        {rule.colorMode === 'custom' ? (
          <input type="color" value={rule.color || defaultColor} onChange={(e) => onChange({ color: e.target.value })} className="h-7 w-10 cursor-pointer rounded border border-neutral-700 bg-neutral-950" />
        ) : (
          <span className="inline-flex items-center gap-1.5 text-xs text-neutral-500">
            <span className="h-3.5 w-3.5 rounded-full" style={{ background: defaultColor }} />
            {defaultColor}
          </span>
        )}
      </div>

      {/* Channels. */}
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-[11px] font-semibold uppercase tracking-wide text-neutral-500">Notify via</span>
        {(['toast', 'center', 'desktop', 'sound'] as const).map((ch) => (
          <label key={ch} className="flex items-center gap-1.5 text-xs text-neutral-300">
            <input type="checkbox" checked={rule.channels[ch]} onChange={(e) => onChange({ channels: { ...rule.channels, [ch]: e.target.checked } })} className="h-3.5 w-3.5 accent-sky-500" />
            <span className="capitalize">{ch === 'center' ? 'Center' : ch}</span>
          </label>
        ))}
      </div>
    </div>
  )
}

// ConditionRow renders one condition: its type plus whatever extra inputs that
// type needs, and a negate toggle.
function ConditionRow({ c, onChange, onRemove }: { c: Condition; onChange: (patch: Partial<Condition>) => void; onRemove?: () => void }) {
  return (
    <div className="flex flex-wrap items-center gap-2 rounded border border-neutral-800 bg-neutral-950 p-2">
      {/* Negate flips this one condition before the combinator sees it. */}
      <label className="flex items-center gap-1 text-[11px] text-neutral-400" title="Invert this condition">
        <input type="checkbox" checked={!!c.negate} onChange={(e) => onChange({ negate: e.target.checked })} className="h-3.5 w-3.5 accent-fuchsia-500" />
        NOT
      </label>
      <select value={c.type} onChange={(e) => onChange({ type: e.target.value as ConditionType })} className="rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs text-neutral-100 outline-none focus:border-sky-500">
        {CONDITION_TYPES.map((t) => (
          <option key={t.value} value={t.value}>
            {t.label}
          </option>
        ))}
      </select>

      {/* Per-type extra inputs. */}
      {c.type === 'severity' && (
        <>
          <select value={c.severityMode ?? 'atLeast'} onChange={(e) => onChange({ severityMode: e.target.value as 'atLeast' | 'exactly' })} className="rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs text-neutral-100 outline-none focus:border-sky-500">
            <option value="atLeast">at least</option>
            <option value="exactly">exactly</option>
          </select>
          <select value={c.severity ?? 'high'} onChange={(e) => onChange({ severity: e.target.value as NotifSeverity })} className="rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs capitalize text-neutral-100 outline-none focus:border-sky-500">
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </>
      )}
      {c.type === 'findingCount' && (
        <input type="number" min={1} value={c.count ?? 1} onChange={(e) => onChange({ count: Math.max(1, Number(e.target.value) || 1) })} className="w-20 rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs text-neutral-100 outline-none focus:border-sky-500" />
      )}
      {c.type === 'tool' && (
        <select value={c.tool ?? 'probe'} onChange={(e) => onChange({ tool: e.target.value })} className="rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs text-neutral-100 outline-none focus:border-sky-500">
          {TOOL_BUCKETS.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
      )}

      <span className="flex-1" />
      {onRemove && (
        <button onClick={onRemove} className="text-neutral-600 hover:text-red-400" title="Remove condition">
          ×
        </button>
      )}
    </div>
  )
}

// CombinatorPicker is the boolean operator select shown once a rule has more
// than one condition. Its tooltip explains the chosen gate's semantics.
function CombinatorPicker({ value, onChange }: { value: Combinator; onChange: (v: Combinator) => void }) {
  const help = COMBINATORS.find((c) => c.value === value)?.help
  return (
    <select value={value} onChange={(e) => onChange(e.target.value as Combinator)} title={help} className="rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-[11px] font-semibold uppercase tracking-wide text-sky-300 outline-none focus:border-sky-500">
      {COMBINATORS.map((c) => (
        <option key={c.value} value={c.value}>
          {c.label}
        </option>
      ))}
    </select>
  )
}

// Segmented is a tiny two-or-more option pill switch, reused for the
// message/color default-vs-custom toggles.
function Segmented({ value, options, onChange }: { value: string; options: { v: string; l: string }[]; onChange: (v: string) => void }) {
  return (
    <div className="inline-flex overflow-hidden rounded border border-neutral-700">
      {options.map((o) => (
        <button
          key={o.v}
          onClick={() => onChange(o.v)}
          className={`px-2.5 py-1 text-[11px] font-medium ${value === o.v ? 'bg-sky-600 text-white' : 'bg-neutral-950 text-neutral-400 hover:text-neutral-200'}`}
        >
          {o.l}
        </button>
      ))}
    </div>
  )
}
