import { useState, type ReactNode } from 'react'
import { inputBase } from '../formStyles'

// SpeedPreset names how fast a scan sends requests to each target: one of the
// three fixed speeds, or Custom, where the operator types the rate in.
export type SpeedPreset = 'slow' | 'normal' | 'fast' | 'custom'

// SPEED_RPS is the requests-per-second each fixed speed sends. Normal matches
// the server's defaultScanRPS, which applies when a request names no rate.
export const SPEED_RPS: Record<Exclude<SpeedPreset, 'custom'>, number> = {
  slow: 10,
  normal: 50,
  fast: 200,
}

// MAX_CUSTOM_RPS mirrors the server's maxScanRPS cap, so a custom rate the
// form accepts is one the backend won't reject.
export const MAX_CUSTOM_RPS = 1000

// SPEED_OPTIONS is the button row, in the order the operator reads it.
const SPEED_OPTIONS: { id: SpeedPreset; label: string; description: string }[] = [
  { id: 'slow', label: 'Slow', description: `${SPEED_RPS.slow} requests per second to each target` },
  { id: 'normal', label: 'Normal', description: `${SPEED_RPS.normal} requests per second to each target` },
  { id: 'fast', label: 'Fast', description: `${SPEED_RPS.fast} requests per second to each target` },
  { id: 'custom', label: 'Custom (req/s)', description: `Type your own rate, from 0 up to ${MAX_CUSTOM_RPS} requests per second` },
]

// resolveRps turns the chosen speed into the rate a scan sends. A fixed speed
// is its table value; a custom rate must parse to a number above zero and no
// more than MAX_CUSTOM_RPS, otherwise the result is null and the scan can't run.
export function resolveRps(preset: SpeedPreset, customText: string): number | null {
  if (preset !== 'custom') return SPEED_RPS[preset]
  // Number('') is 0, so an empty field is caught by the range check below.
  const value = Number(customText.trim())
  if (!Number.isFinite(value) || value <= 0 || value > MAX_CUSTOM_RPS) return null
  return value
}

// ScanSpeedState is what a scanner gets from useScanSpeed: rps is the rate to
// send (null while a custom rate is unusable), and control is the row of
// buttons to render in the scanner's form.
export interface ScanSpeedState {
  rps: number | null
  control: ReactNode
}

// useScanSpeed holds one scanner's speed choice and returns its resolved rate
// along with the control that changes it. Every scanner starts on Normal.
export function useScanSpeed(): ScanSpeedState {
  const [preset, setPreset] = useState<SpeedPreset>('normal')
  const [customText, setCustomText] = useState('25')
  const rps = resolveRps(preset, customText)

  return {
    rps,
    control: (
      <ScanSpeedControl
        preset={preset}
        onPreset={setPreset}
        customText={customText}
        onCustomText={setCustomText}
        rps={rps}
      />
    ),
  }
}

// ScanSpeedControl is the Slow/Normal/Fast/Custom row. The custom field only
// appears while Custom is selected, and a status line shows the rate in effect
// so the operator sees what a run will send before starting it.
function ScanSpeedControl({
  preset,
  onPreset,
  customText,
  onCustomText,
  rps,
}: {
  preset: SpeedPreset
  onPreset: (p: SpeedPreset) => void
  customText: string
  onCustomText: (text: string) => void
  rps: number | null
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="text-xs font-medium text-neutral-300">Speed</span>
      {SPEED_OPTIONS.map((opt) => (
        <button
          key={opt.id}
          type="button"
          aria-pressed={preset === opt.id}
          title={opt.description}
          onClick={() => onPreset(opt.id)}
          className={`rounded border px-2 py-0.5 text-xs ${
            preset === opt.id ? 'border-sky-500 bg-sky-950/40 text-sky-300' : 'border-neutral-700 bg-neutral-900 text-neutral-400 hover:border-sky-600'
          }`}
        >
          {opt.label}
        </button>
      ))}
      {preset === 'custom' && (
        <input
          type="number"
          inputMode="decimal"
          min={0}
          max={MAX_CUSTOM_RPS}
          step="any"
          value={customText}
          onChange={(e) => onCustomText(e.target.value)}
          aria-label="Requests per second"
          placeholder="req/s"
          className={`${inputBase} w-24 text-xs ${rps === null ? 'border-red-700' : ''}`}
        />
      )}
      <span className={`text-[11px] ${rps === null ? 'text-red-400' : 'text-neutral-600'}`}>
        {rps === null ? `Enter a rate between 0 and ${MAX_CUSTOM_RPS} req/s` : `${rps} req/s per target`}
      </span>
    </div>
  )
}
