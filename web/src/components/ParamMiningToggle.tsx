// ParamMiningToggle is the "Mine hidden parameters" checkbox shared by every
// injection scanner that takes a parameter list. Off by default: when on, the
// server sends a bounded set of probes to find undocumented parameters before
// the scan runs, which costs extra requests the operator should opt into.
export function ParamMiningToggle({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label
      className="flex items-center gap-1.5 text-xs text-neutral-400"
      title="Probes the endpoint's GET query with a few hundred common parameter names (fetch targets, redirects, file and template selectors, debug switches) and adds every name that changes the response, or is reflected back, to the test set. Costs roughly one request per dozen names when nothing responds. Off by default."
    >
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} className="accent-sky-500" />
      Mine hidden parameters (probe for undocumented names)
    </label>
  )
}
