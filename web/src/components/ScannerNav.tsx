import { useEffect, useState, type CSSProperties } from 'react'
import { BADGE_LABEL, INDICATOR_COLOR, type IndicatorSeverity, type ScanIndicator } from '../scanIndicator'
import { NAV_GROUPS, PINNED_TABS, TAB_META, type NavGroup, type Tab } from '../scannerNavData'
import { useScannerNavStyle } from '../scannerNavStyle'
import { useAutoExpandOnce, useCollapsible } from '../collapsible'

// ScannerNav is the case view's left sidebar -- the one switching between
// Targets, Identify, and every scanner tab (see scannerNavData.ts for what
// tabs/groups exist). It picks which of the four saved layouts to render
// (see scannerNavStyle.ts) and hands every variant the same props, so
// switching styles never changes what the sidebar can do, only how it looks.
// CaseView.tsx owns the surrounding chrome (the collapse-to-icon-rail
// toggle, which stays one shared minimal rail regardless of style -- it's a
// width-saving utility, not a "look") and renders this inside it.
export interface ScannerNavProps {
  activeTab: Tab
  indicators: Record<string, ScanIndicator>
  unseen: Record<string, true>
  counts: Record<Tab, number | null>
  onSelect: (tab: Tab) => void
}

export function ScannerNav(props: ScannerNavProps) {
  const style = useScannerNavStyle()
  switch (style) {
    case 'list':
      return <ListNav {...props} />
    case 'compact':
      return <CompactNav {...props} />
    case 'accordion':
      return <AccordionNav {...props} />
    case 'tiles':
    default:
      return <TilesNav {...props} />
  }
}

// --- shared scan-state helpers ---
//
// Every design shows the same three states (never run / running / finished)
// through the same CSS (see index.css's "Case nav scanner tiles" block) --
// scanBorderProps drives a colored ring/comet around a bordered box (Tiles,
// Compact), indicatorDot drives a small colored dot for the row-shaped
// designs (List, Accordion) that have no tile border to glow around.

export interface ScanBorderProps {
  className: string
  style: CSSProperties
  ownBorder: boolean
}

// scanBorderProps turns a tab's indicator into how its bordered tile looks. A
// running tab gets a comet sweeping its border and a soft pulse. When the run
// finishes the comet closes into a ring and flashes out, and the border
// settles into a solid outline in the result's color, which breathes until
// the user opens the tab. A tab that never ran keeps its plain look. Exported
// so CaseView.tsx's collapsed icon-rail (the width-saving mode every style
// shares) can show the same scan state without duplicating this logic.
export function scanBorderProps(indicator: ScanIndicator | undefined, unseen: boolean): ScanBorderProps {
  if (!indicator || indicator.phase === 'idle') return { className: '', style: {}, ownBorder: false }
  if (indicator.phase === 'running') {
    return { className: 'scan-live', style: { '--scan-color': INDICATOR_COLOR.running } as CSSProperties, ownBorder: false }
  }
  const color = INDICATOR_COLOR[indicator.severity ?? 'clean']
  return {
    className: unseen ? 'scan-done scan-breathe' : 'scan-done scan-outline',
    style: { '--scan-color': color, borderColor: color } as CSSProperties,
    ownBorder: true,
  }
}

interface DotProps {
  color: string
  pulse: boolean
}

// indicatorDot is scanBorderProps' row-shaped counterpart: a small solid dot
// instead of a border, since a full-width list row has no tile edge for the
// comet/ring to run around. Pulses (via Tailwind's animate-pulse) while
// running or while a finished result is still unseen.
function indicatorDot(indicator: ScanIndicator | undefined, unseen: boolean): DotProps | null {
  if (!indicator || indicator.phase === 'idle') return null
  if (indicator.phase === 'running') return { color: INDICATOR_COLOR.running, pulse: true }
  return { color: INDICATOR_COLOR[indicator.severity ?? 'clean'], pulse: unseen }
}

// ResultBadge is the labelled pill on a finished tile's top-right corner --
// used by the two designs roomy enough for it (Tiles, Accordion's header has
// its own dot instead).
function ResultBadge({ severity }: { severity: IndicatorSeverity | null }) {
  const color = INDICATOR_COLOR[severity ?? 'clean']
  return (
    <span
      className="scan-badge absolute -right-1.5 -top-1.5 rounded-full border bg-neutral-950 px-1.5 py-px text-[9px] font-bold uppercase leading-tight tracking-wide"
      style={{ color, borderColor: color } as CSSProperties}
    >
      {BADGE_LABEL[severity ?? 'clean']}
    </span>
  )
}

// =======================================================================
// Tiles -- the sidebar's original shape: a two-column grid of icon tiles,
// each group independently collapsible under its own sky-accented header.
// =======================================================================

function TilesNav({ activeTab, indicators, unseen, counts, onSelect }: ScannerNavProps) {
  return (
    <div className="w-56">
      <div className="grid grid-cols-2 gap-1.5">
        {PINNED_TABS.map((id) => (
          <TileButton key={id} id={id} active={activeTab === id} indicator={indicators[id]} unseen={!!unseen[id]} count={counts[id]} onSelect={() => onSelect(id)} />
        ))}
      </div>
      <div className="my-2 border-t border-neutral-900" />
      <div className="space-y-3">
        {NAV_GROUPS.map((group) => (
          <TilesGroup key={group.id} group={group} activeTab={activeTab} indicators={indicators} unseen={unseen} counts={counts} onSelect={onSelect} />
        ))}
      </div>
    </div>
  )
}

// TileButton is one rectangular tile -- either pinned at the top or inside a
// TilesGroup. The icon and label fill the tile, the item count sits in the
// top-left, and a scanner tab's border shows its scan state.
function TileButton({
  id,
  active,
  indicator,
  unseen,
  count,
  onSelect,
}: {
  id: Tab
  active: boolean
  indicator: ScanIndicator | undefined
  unseen: boolean
  count: number | null
  onSelect: () => void
}) {
  const { label, icon: Icon } = TAB_META[id]
  const scan = scanBorderProps(indicator, unseen)
  // The border color comes from the scan when there is one, so the active
  // tab only gets its sky border when no scan color is shown.
  const borderClass = scan.ownBorder ? '' : active ? 'border-sky-500' : 'border-neutral-800 hover:border-neutral-600'
  return (
    <button
      onClick={onSelect}
      title={`${label}${count !== null ? ` (${count})` : ''}`}
      style={scan.style}
      className={`relative flex h-16 flex-col items-center justify-center gap-1.5 rounded-md border px-1.5 text-center text-[11px] leading-tight ${scan.className} ${borderClass} ${
        active ? 'bg-sky-950/40 text-sky-300' : 'bg-neutral-900 text-neutral-400 hover:text-neutral-200'
      }`}
    >
      <Icon className="h-4 w-4 shrink-0" />
      <span className="line-clamp-2">{label}</span>
      {count !== null && <span className="absolute left-1.5 top-1 text-[10px] text-neutral-500">{count}</span>}
      {indicator?.phase === 'done' && <ResultBadge severity={indicator.severity} />}
    </button>
  )
}

// TilesGroup renders one collapsible group (Recon/Vulnerabilities/
// Utilities) as a header plus its tiles in a 2-column grid. Each group
// remembers its own open/closed state under its own key so collapsing
// "Utilities" doesn't affect "Recon" -- and it starts open, expanding to
// reveal the active tab if a saved-collapsed group later becomes active
// (e.g. via a "Send to X" handoff from elsewhere in the case).
function TilesGroup({
  group,
  activeTab,
  indicators,
  unseen,
  counts,
  onSelect,
}: {
  group: NavGroup
  activeTab: Tab
  indicators: Record<string, ScanIndicator>
  unseen: Record<string, true>
  counts: Record<Tab, number | null>
  onSelect: (tab: Tab) => void
}) {
  const [open, setOpen] = useCollapsible(`caseNav.group.${group.id}`, true)
  const hasActive = group.tabs.includes(activeTab)
  useAutoExpandOnce(hasActive, setOpen)
  const Icon = group.icon
  return (
    <div>
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-1.5 border-l-2 border-sky-700/70 py-1.5 pl-2 pr-1 text-left text-[11px] font-bold uppercase tracking-wider text-sky-400 hover:border-sky-500 hover:text-sky-300"
      >
        <Icon className="h-3.5 w-3.5 shrink-0 text-sky-500" />
        <span className="flex-1">{group.label}</span>
        <span className="text-sky-700">{open ? '▾' : '▸'}</span>
      </button>
      {open && (
        <div className="grid grid-cols-2 gap-1.5 pt-1.5">
          {group.tabs.map((id) => (
            <TileButton key={id} id={id} active={activeTab === id} indicator={indicators[id]} unseen={!!unseen[id]} count={counts[id]} onSelect={() => onSelect(id)} />
          ))}
        </div>
      )}
    </div>
  )
}

// =======================================================================
// List -- a flat single-column list (file-tree style) rather than a grid of
// tiles: each row is icon + label + count, the active row shown with a left
// accent bar instead of a border, and scan state shown as a small colored
// dot rather than a glowing tile edge.
// =======================================================================

function ListNav({ activeTab, indicators, unseen, counts, onSelect }: ScannerNavProps) {
  return (
    <div className="w-60 space-y-0.5">
      {PINNED_TABS.map((id) => (
        <ListRow key={id} id={id} active={activeTab === id} indicator={indicators[id]} unseen={!!unseen[id]} count={counts[id]} onSelect={() => onSelect(id)} />
      ))}
      <div className="my-1.5 border-t border-neutral-900" />
      <div className="space-y-2.5">
        {NAV_GROUPS.map((group) => (
          <ListGroup key={group.id} group={group} activeTab={activeTab} indicators={indicators} unseen={unseen} counts={counts} onSelect={onSelect} />
        ))}
      </div>
    </div>
  )
}

function ListGroup({
  group,
  activeTab,
  indicators,
  unseen,
  counts,
  onSelect,
}: {
  group: NavGroup
  activeTab: Tab
  indicators: Record<string, ScanIndicator>
  unseen: Record<string, true>
  counts: Record<Tab, number | null>
  onSelect: (tab: Tab) => void
}) {
  // Own storage key (distinct from Tiles') so each layout remembers its own
  // collapse choices independently -- switching styles never reshuffles the
  // other style's state.
  const [open, setOpen] = useCollapsible(`caseNav.list.group.${group.id}`, true)
  const hasActive = group.tabs.includes(activeTab)
  useAutoExpandOnce(hasActive, setOpen)
  return (
    <div>
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-1.5 px-1.5 py-1 text-left text-[10px] font-bold uppercase tracking-wider text-neutral-500 hover:text-neutral-300"
      >
        <span className="flex-1">{group.label}</span>
        <span>{open ? '▾' : '▸'}</span>
      </button>
      {open && (
        <div className="space-y-0.5 pl-1">
          {group.tabs.map((id) => (
            <ListRow key={id} id={id} active={activeTab === id} indicator={indicators[id]} unseen={!!unseen[id]} count={counts[id]} onSelect={() => onSelect(id)} />
          ))}
        </div>
      )}
    </div>
  )
}

function ListRow({
  id,
  active,
  indicator,
  unseen,
  count,
  onSelect,
}: {
  id: Tab
  active: boolean
  indicator: ScanIndicator | undefined
  unseen: boolean
  count: number | null
  onSelect: () => void
}) {
  const { label, icon: Icon } = TAB_META[id]
  const dot = indicatorDot(indicator, unseen)
  return (
    <button
      onClick={onSelect}
      title={`${label}${count !== null ? ` (${count})` : ''}`}
      className={`flex w-full items-center gap-2 border-l-2 py-1.5 pl-2 pr-2 text-left text-xs ${
        active ? 'border-l-neutral-100 bg-neutral-900 text-neutral-100' : 'border-l-transparent text-neutral-400 hover:bg-neutral-900/60 hover:text-neutral-200'
      }`}
    >
      <Icon className="h-3.5 w-3.5 shrink-0" />
      <span className="flex-1 truncate">{label}</span>
      {count !== null && <span className="text-[10px] text-neutral-600">{count}</span>}
      {dot && <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${dot.pulse ? 'animate-pulse' : ''}`} style={{ background: dot.color }} />}
    </button>
  )
}

// =======================================================================
// Compact -- a dense icon-only grid with no collapsible groups at all (the
// point of this layout is seeing every scanner at once); each group is just
// a small label dividing the grid, and labels only ever show as a tooltip.
// =======================================================================

function CompactNav({ activeTab, indicators, unseen, counts, onSelect }: ScannerNavProps) {
  return (
    <div className="w-40 space-y-2.5">
      <div className="grid grid-cols-4 gap-1">
        {PINNED_TABS.map((id) => (
          <CompactTile key={id} id={id} active={activeTab === id} indicator={indicators[id]} unseen={!!unseen[id]} count={counts[id]} onSelect={() => onSelect(id)} />
        ))}
      </div>
      {NAV_GROUPS.map((group) => (
        <div key={group.id}>
          <div className="px-0.5 pb-1 text-[9px] font-bold uppercase tracking-wider text-neutral-600">{group.label}</div>
          <div className="grid grid-cols-4 gap-1">
            {group.tabs.map((id) => (
              <CompactTile key={id} id={id} active={activeTab === id} indicator={indicators[id]} unseen={!!unseen[id]} count={counts[id]} onSelect={() => onSelect(id)} />
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}

function CompactTile({
  id,
  active,
  indicator,
  unseen,
  count,
  onSelect,
}: {
  id: Tab
  active: boolean
  indicator: ScanIndicator | undefined
  unseen: boolean
  count: number | null
  onSelect: () => void
}) {
  const { label, icon: Icon } = TAB_META[id]
  const scan = scanBorderProps(indicator, unseen)
  const borderClass = scan.ownBorder ? '' : active ? 'border-neutral-100' : 'border-neutral-800 hover:border-neutral-600'
  return (
    <button
      onClick={onSelect}
      title={`${label}${count !== null ? ` (${count})` : ''}`}
      style={scan.style}
      className={`relative flex h-8 w-8 items-center justify-center rounded border ${scan.className} ${borderClass} ${
        active ? 'bg-neutral-800 text-neutral-100' : 'text-neutral-500 hover:bg-neutral-900 hover:text-neutral-300'
      }`}
    >
      <Icon className="h-3.5 w-3.5" />
      {indicator?.phase === 'done' && (
        <span className="absolute -right-0.5 -top-0.5 h-1.5 w-1.5 rounded-full" style={{ background: INDICATOR_COLOR[indicator.severity ?? 'clean'] }} />
      )}
    </button>
  )
}

// =======================================================================
// Accordion -- groups behave as a strict accordion (opening one closes any
// other), full-width rows highlighted with a background fill rather than a
// border or accent bar. Pinned tabs sit above the accordion, always visible.
// =======================================================================

function AccordionNav({ activeTab, indicators, unseen, counts, onSelect }: ScannerNavProps) {
  const [openGroup, setOpenGroup] = useState<string | null>(() => NAV_GROUPS.find((g) => g.tabs.includes(activeTab))?.id ?? NAV_GROUPS[0]?.id ?? null)

  // Keep whichever group holds the active tab open if navigation lands on a
  // tab inside a currently-closed group -- e.g. a "Send to X" handoff from
  // elsewhere in the case.
  useEffect(() => {
    const owner = NAV_GROUPS.find((g) => g.tabs.includes(activeTab))
    if (owner) setOpenGroup(owner.id)
  }, [activeTab])

  return (
    <div className="w-60 space-y-1">
      <div className="space-y-0.5">
        {PINNED_TABS.map((id) => (
          <AccordionRow key={id} id={id} active={activeTab === id} indicator={indicators[id]} unseen={!!unseen[id]} count={counts[id]} onSelect={() => onSelect(id)} />
        ))}
      </div>
      <div className="my-1.5 border-t border-neutral-900" />
      <div className="space-y-1">
        {NAV_GROUPS.map((group) => {
          const Icon = group.icon
          const open = openGroup === group.id
          return (
            <div key={group.id} className="overflow-hidden rounded-md border border-neutral-800">
              <button
                onClick={() => setOpenGroup(open ? null : group.id)}
                className={`flex w-full items-center gap-2 px-2.5 py-2 text-left text-xs font-medium ${
                  open ? 'bg-neutral-800 text-neutral-100' : 'bg-neutral-900 text-neutral-400 hover:text-neutral-200'
                }`}
              >
                <Icon className="h-3.5 w-3.5 shrink-0" />
                <span className="flex-1">{group.label}</span>
                <span className="text-neutral-600">{open ? '▾' : '▸'}</span>
              </button>
              {open && (
                <div className="space-y-0.5 bg-neutral-950 p-1">
                  {group.tabs.map((id) => (
                    <AccordionRow key={id} id={id} active={activeTab === id} indicator={indicators[id]} unseen={!!unseen[id]} count={counts[id]} onSelect={() => onSelect(id)} />
                  ))}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

function AccordionRow({
  id,
  active,
  indicator,
  unseen,
  count,
  onSelect,
}: {
  id: Tab
  active: boolean
  indicator: ScanIndicator | undefined
  unseen: boolean
  count: number | null
  onSelect: () => void
}) {
  const { label, icon: Icon } = TAB_META[id]
  const dot = indicatorDot(indicator, unseen)
  return (
    <button
      onClick={onSelect}
      title={`${label}${count !== null ? ` (${count})` : ''}`}
      className={`flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-xs ${
        active ? 'bg-sky-950/50 text-sky-300' : 'text-neutral-400 hover:bg-neutral-900 hover:text-neutral-200'
      }`}
    >
      <Icon className="h-3.5 w-3.5 shrink-0" />
      <span className="flex-1 truncate">{label}</span>
      {count !== null && <span className="text-[10px] text-neutral-600">{count}</span>}
      {dot && <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${dot.pulse ? 'animate-pulse' : ''}`} style={{ background: dot.color }} />}
    </button>
  )
}
