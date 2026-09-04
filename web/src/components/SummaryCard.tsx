// Small stat card shared by the app-wide Dashboard and each scan's Overview
// tab -- same "big number, small label" shape for both.
export function SummaryCard({ label, value, accent }: { label: string; value: number; accent?: boolean }) {
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-3">
      <p className={`text-2xl font-semibold ${accent ? 'text-amber-400' : 'text-neutral-100'}`}>{value.toLocaleString()}</p>
      <p className="text-xs text-neutral-500">{label}</p>
    </div>
  )
}
