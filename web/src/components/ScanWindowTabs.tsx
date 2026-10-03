// ScanWindowTabs is the "Scan" / "History" switch every standalone scan
// tool tab (Probe, SecretScan, BreachCheck, …) shows above its results
// pane -- Scan is the live/current-session view, History is every run
// persisted for this case (see ScanHistoryPanel).
export function ScanWindowTabs({ view, onChange }: { view: 'scan' | 'history'; onChange: (v: 'scan' | 'history') => void }) {
  return (
    <div className="flex items-center gap-1 border-b border-neutral-800 pb-2">
      {(['scan', 'history'] as const).map((v) => (
        <button
          key={v}
          type="button"
          onClick={() => onChange(v)}
          className={`rounded px-2.5 py-1 text-xs font-medium ${
            view === v ? 'bg-neutral-800 text-neutral-100' : 'text-neutral-500 hover:bg-neutral-900 hover:text-neutral-300'
          }`}
        >
          {v === 'scan' ? 'Scan' : 'Scan history'}
        </button>
      ))}
    </div>
  )
}
