import { useEffect, useState, type ReactNode } from 'react'
import { api } from '../api'
import type { FlowNodeData, WordlistInfo } from '../types'

interface Props {
  node: FlowNodeData
  onChange: (config: Record<string, unknown>) => void
  onLabelChange: (label: string) => void
  onDelete: () => void
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-neutral-400">{label}</span>
      {children}
    </label>
  )
}

const inputClass =
  'w-full rounded border border-neutral-700 bg-neutral-800 px-2 py-1.5 text-sm text-neutral-100 outline-none focus:border-sky-500'

function TextInput({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <input
      className={inputClass}
      value={value}
      placeholder={placeholder}
      onChange={(e) => onChange(e.target.value)}
    />
  )
}

function NumberInput({ value, onChange, placeholder }: { value: number | undefined; onChange: (v: number | undefined) => void; placeholder?: string }) {
  return (
    <input
      type="number"
      className={inputClass}
      value={value ?? ''}
      placeholder={placeholder}
      onChange={(e) => onChange(e.target.value === '' ? undefined : Number(e.target.value))}
    />
  )
}

function IntListInput({ value, onChange, placeholder }: { value: number[] | undefined; onChange: (v: number[] | undefined) => void; placeholder?: string }) {
  return (
    <input
      className={inputClass}
      placeholder={placeholder}
      defaultValue={value?.join(', ') ?? ''}
      onBlur={(e) => {
        const nums = e.target.value
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean)
          .map(Number)
          .filter((n) => !Number.isNaN(n))
        onChange(nums.length ? nums : undefined)
      }}
    />
  )
}

// WordlistField offers a dropdown of wordlists installed on the server
// (see the Wordlists section) plus a "custom path…" escape hatch for
// anything not managed there, so hand-built flows can point at whatever
// was downloaded without the user re-typing an absolute path.
function WordlistField({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const [installed, setInstalled] = useState<WordlistInfo[]>([])
  const [customMode, setCustomMode] = useState(false)

  useEffect(() => {
    api.listWordlists().then(setInstalled)
  }, [])

  const knownPaths = new Set(installed.map((w) => w.path))
  const isCustom = customMode || (value !== '' && !knownPaths.has(value))

  if (isCustom) {
    return (
      <div className="flex gap-1">
        <TextInput value={value} onChange={onChange} placeholder="/path/to/wordlist.txt" />
        {installed.length > 0 && (
          <button
            type="button"
            onClick={() => setCustomMode(false)}
            className="shrink-0 rounded border border-neutral-700 px-2 text-xs text-neutral-400 hover:border-neutral-500"
          >
            List
          </button>
        )}
      </div>
    )
  }

  return (
    <select
      className={inputClass}
      value={value}
      onChange={(e) => (e.target.value === '__custom__' ? setCustomMode(true) : onChange(e.target.value))}
    >
      <option value="">Select a wordlist…</option>
      {installed.map((w) => (
        <option key={w.name} value={w.path}>
          {w.name} ({w.lines.toLocaleString()} lines){w.builtin ? ' — built-in' : ''}
        </option>
      ))}
      <option value="__custom__">Custom path…</option>
    </select>
  )
}

function CheckboxField({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-center gap-2 text-sm text-neutral-300">
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      {label}
    </label>
  )
}

function HeadersField({ value, onChange }: { value: Record<string, string> | undefined; onChange: (v: Record<string, string> | undefined) => void }) {
  const text = Object.entries(value ?? {})
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n')
  return (
    <textarea
      className={`${inputClass} h-16 font-mono`}
      placeholder={'Header: value\nOne per line'}
      defaultValue={text}
      onBlur={(e) => {
        const out: Record<string, string> = {}
        for (const line of e.target.value.split('\n')) {
          const idx = line.indexOf(':')
          if (idx === -1) continue
          out[line.slice(0, idx).trim()] = line.slice(idx + 1).trim()
        }
        onChange(Object.keys(out).length ? out : undefined)
      }}
    />
  )
}

export function Inspector({ node, onChange, onLabelChange, onDelete }: Props) {
  const cfg = node.config
  const set = (key: string, value: unknown) => {
    const next = { ...cfg }
    if (value === undefined || value === '') delete next[key]
    else next[key] = value
    onChange(next)
  }

  return (
    <div className="flex h-full flex-col gap-3 overflow-y-auto p-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">{node.kind} node</h2>
        <button onClick={onDelete} className="text-xs text-red-400 hover:text-red-300">
          Delete
        </button>
      </div>

      <Field label="Label">
        <TextInput value={node.label ?? ''} onChange={onLabelChange} placeholder={node.kind} />
      </Field>

      {(node.kind === 'ffuf' || node.kind === 'feroxbuster') && (
        <>
          <Field label={node.kind === 'ffuf' ? 'Target URL (must contain FUZZ)' : 'Target URL'}>
            <TextInput
              value={(cfg.url as string) ?? ''}
              onChange={(v) => set('url', v)}
              placeholder={node.kind === 'ffuf' ? 'https://target/FUZZ' : 'https://target/'}
            />
          </Field>
          <Field label="Wordlist">
            <WordlistField value={(cfg.wordlist as string) ?? ''} onChange={(v) => set('wordlist', v)} />
          </Field>
          <Field label="Method">
            <TextInput value={(cfg.method as string) ?? ''} onChange={(v) => set('method', v)} placeholder="GET" />
          </Field>
          <Field label="Threads">
            <NumberInput value={cfg.threads as number} onChange={(v) => set('threads', v)} placeholder="40" />
          </Field>
          <Field label="Extensions (comma separated)">
            <TextInput
              value={Array.isArray(cfg.extensions) ? (cfg.extensions as string[]).join(',') : ''}
              onChange={(v) => set('extensions', v ? v.split(',').map((s) => s.trim()).filter(Boolean) : undefined)}
              placeholder=".php,.html"
            />
          </Field>
          <Field label="Headers">
            <HeadersField value={cfg.headers as Record<string, string>} onChange={(v) => set('headers', v)} />
          </Field>
          {node.kind === 'ffuf' && (
            <>
              <Field label="Match codes (-mc)">
                <TextInput value={(cfg.matchCodes as string) ?? ''} onChange={(v) => set('matchCodes', v)} placeholder="all" />
              </Field>
              <Field label="Timeout (seconds)">
                <NumberInput value={cfg.timeoutSeconds as number} onChange={(v) => set('timeoutSeconds', v)} />
              </Field>
            </>
          )}
          {node.kind === 'feroxbuster' && (
            <>
              <Field label="Recursion depth">
                <NumberInput value={cfg.depth as number} onChange={(v) => set('depth', v)} placeholder="4" />
              </Field>
              <CheckboxField label="Disable recursion" checked={!!cfg.noRecursion} onChange={(v) => set('noRecursion', v || undefined)} />
            </>
          )}
        </>
      )}

      {node.kind === 'filter' && (
        <>
          <Field label="Match status codes (comma separated)">
            <IntListInput value={cfg.statusCodes as number[]} onChange={(v) => set('statusCodes', v)} placeholder="200, 301, 302" />
          </Field>
          <Field label="Exclude status codes">
            <IntListInput value={cfg.statusExclude as number[]} onChange={(v) => set('statusExclude', v)} placeholder="404" />
          </Field>
          <div className="grid grid-cols-2 gap-2">
            <Field label="Min content length">
              <NumberInput value={cfg.minContentLength as number} onChange={(v) => set('minContentLength', v)} />
            </Field>
            <Field label="Max content length">
              <NumberInput value={cfg.maxContentLength as number} onChange={(v) => set('maxContentLength', v)} />
            </Field>
            <Field label="Min words">
              <NumberInput value={cfg.minWords as number} onChange={(v) => set('minWords', v)} />
            </Field>
            <Field label="Max words">
              <NumberInput value={cfg.maxWords as number} onChange={(v) => set('maxWords', v)} />
            </Field>
            <Field label="Min lines">
              <NumberInput value={cfg.minLines as number} onChange={(v) => set('minLines', v)} />
            </Field>
            <Field label="Max lines">
              <NumberInput value={cfg.maxLines as number} onChange={(v) => set('maxLines', v)} />
            </Field>
          </div>
          <Field label="URL regex">
            <TextInput value={(cfg.urlRegex as string) ?? ''} onChange={(v) => set('urlRegex', v)} placeholder="/admin/.*" />
          </Field>
        </>
      )}

      {node.kind === 'merge' && <CheckboxField label="Dedup by URL + status code" checked={!!cfg.dedup} onChange={(v) => set('dedup', v || undefined)} />}

      {node.kind === 'table' && <p className="text-xs text-neutral-500">No configuration — reflects live results from upstream nodes.</p>}

      {node.kind === 'export' && (
        <>
          <Field label="Format">
            <select
              className={inputClass}
              value={(cfg.format as string) ?? 'json'}
              onChange={(e) => set('format', e.target.value)}
            >
              <option value="json">JSON</option>
              <option value="csv">CSV</option>
            </select>
          </Field>
          <Field label="Output path">
            <TextInput value={(cfg.path as string) ?? ''} onChange={(v) => set('path', v)} placeholder="/path/to/results.json" />
          </Field>
        </>
      )}
    </div>
  )
}
