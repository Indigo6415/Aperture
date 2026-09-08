import { useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../api'
import type { EstateCluster, EstateHostModel } from '../useEstateModel'
import type { PageGroup } from '../useScanGraph'
import type { ClusterId } from '../estate'
import { statusHexColor } from '../statusColor'
import { ProgressBar } from './ProgressBar'

// Board geometry -- lifted verbatim from the Estate Hierarchy design spec's
// "Layout — exact geometry" section (design_handoff_estate_hierarchy/README.md).
// The five tiers are positioned arithmetically rather than force-simulated,
// so these numbers ARE the layout; changing them changes the design.
const BOARD_W = 1400
const BOARD_H = 648
const GRID_X = [206, 456, 830]
const APEX_Y = 324
const APEX_BOX = { x: 16, w: 190, h: 76 }
const CLUSTER_BOX = { x: 230, w: 216, h: 76, gap: 18 }
const HOST_BOX = { x: 500, w: 300, h: 32, gap: 6 }
const PANEL = { x: 880, w: 490, top: 44, headerH: 34, rowH: 26, gapBetweenPanels: 40 }

// Keyed by internal/techfp/signatures.go's actual Category values, not the
// design mock's simplified server/framework/cdn names.
const CAT_COLOR: Record<string, string> = {
  'web-server': '#5980a6',
  language: '#a78bfa',
  'js-framework': '#38bdf8',
  cms: '#fbbf24',
  'cdn-proxy': '#34d399',
}
const CAT_COLOR_DEFAULT = '#5980a6'

type Tier = 'site' | 'cluster' | 'subdomain' | 'technology' | 'pagegroup'
const TIERS: { id: Tier; label: string }[] = [
  { id: 'site', label: 'Site' },
  { id: 'cluster', label: 'Cluster' },
  { id: 'subdomain', label: 'Subdomain' },
  { id: 'technology', label: 'Technology' },
  { id: 'pagegroup', label: 'Page group' },
]

// truncate is a cheap character-count heuristic (not exact glyph
// measurement) for keeping SVG <text> inside its box -- every row in this
// view has a fixed pixel width and no CSS text-overflow to fall back on.
function truncate(text: string, maxWidthPx: number, fontSizePx: number, monospace: boolean): string {
  const avgCharWidth = fontSizePx * (monospace ? 0.6 : 0.56)
  const maxChars = Math.max(1, Math.floor(maxWidthPx / avgCharWidth))
  if (text.length <= maxChars) return text
  return text.slice(0, Math.max(1, maxChars - 1)) + '…'
}

function cveTotal(h: EstateHostModel): number {
  return h.technologies.reduce((s, t) => s + (t.cves?.length ?? 0), 0)
}

// hostMatches backs both the search box and the risk-only toggle -- a host
// that fails either keeps its row (filtering dims, it never removes; see
// the README's "Interactions" section) but stops counting toward a
// cluster's "N/M hosts" and the toolbar's shown-page total.
function hostMatches(h: EstateHostModel, q: string, riskOnly: boolean): boolean {
  if (riskOnly && h.exposedFiles === 0 && cveTotal(h) === 0) return false
  const needle = q.trim().toLowerCase()
  if (!needle) return true
  if (h.hostname.toLowerCase().includes(needle)) return true
  return h.technologies.some((t) => t.name.toLowerCase().includes(needle))
}

// HierarchyView is the Estate Hierarchy board: site → cluster → subdomain →
// technology → page group, positioned by the fixed geometry above rather
// than a force simulation (see design_handoff_estate_hierarchy/README.md --
// a force layout can't stay legible at 36 hosts × 3,090 pages). Rendered
// entirely as SVG (rects/paths/text) with a transparent <button> overlay
// for the two interactive tiers (cluster, host) so tab order and
// :focus-visible work without duplicating the visual design into HTML.
export function HierarchyView({
  scanId,
  domain,
  apex,
  clusters,
  pageGroupsByHost,
  progress,
}: {
  scanId: string
  domain: string
  apex: { hostname: string; hostCount: number; pageCount: number; technologies: EstateHostModel['technologies'] }
  clusters: EstateCluster[]
  pageGroupsByHost: Map<string, PageGroup[]>
  progress: { done: number; total: number } | null
}) {
  const [expanded, setExpanded] = useState<ClusterId | null>(null)
  const [selHost, setSelHost] = useState<string | null>(null)
  const [hover, setHover] = useState<string | null>(null)
  const [hoverTech, setHoverTech] = useState<string | null>(null)
  const [q, setQ] = useState('')
  const [riskOnly, setRiskOnly] = useState(false)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [tierVisible, setTierVisible] = useState<Record<Tier, boolean>>({
    site: true,
    cluster: true,
    subdomain: true,
    technology: true,
    pagegroup: true,
  })
  const [scanning, setScanning] = useState(false)
  const [scanMessage, setScanMessage] = useState('')

  // Opens the riskiest cluster (clusters are already sorted worst-first) the
  // first time real data arrives, so the view isn't a bare apex box on
  // first paint -- guarded by a ref, not `expanded`, so a user who
  // deliberately collapses everything doesn't get snapped back open by a
  // later live update (a new subdomain, say) changing `clusters`.
  const autoExpandedRef = useRef(false)
  useEffect(() => {
    if (autoExpandedRef.current || clusters.length === 0) return
    autoExpandedRef.current = true
    setExpanded(clusters[0].id)
    setSelHost(clusters[0].hosts[0]?.hostname ?? null)
  }, [clusters])

  // sel drives both right-hand panels. Usually one of a cluster's hosts,
  // but the apex itself can carry its own detected technologies too (an
  // apex-only scan with no subdomains would otherwise have no way to ever
  // show them) -- selHost === apex.hostname synthesizes an equivalent
  // shape for it, using pageGroupsByHost's apex-keyed entry the same way a
  // real host's would be looked up.
  const sel = useMemo((): Pick<EstateHostModel, 'hostname' | 'technologies' | 'pageCount'> | undefined => {
    if (!selHost) return undefined
    if (selHost === apex.hostname) return { hostname: apex.hostname, technologies: apex.technologies, pageCount: apex.pageCount }
    for (const c of clusters) {
      const h = c.hosts.find((h) => h.hostname === selHost)
      if (h) return h
    }
    return undefined
  }, [clusters, selHost, apex])

  const toggleTier = (t: Tier) => setTierVisible((prev) => ({ ...prev, [t]: !prev[t] }))

  const toggleHost = (h: EstateHostModel) => {
    setSelHost(h.hostname)
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(h.hostname)) next.delete(h.hostname)
      else next.add(h.hostname)
      return next
    })
  }

  const scanSelected = async () => {
    setScanning(true)
    setScanMessage('')
    try {
      const res = await api.runContentDiscovery(scanId, [domain, ...selected])
      setScanMessage(res.skipped ? (res.message ?? 'Nothing new to scan') : 'Started — see Content Discovery tab')
    } catch (err) {
      setScanMessage(err instanceof Error ? err.message : String(err))
    } finally {
      setScanning(false)
    }
  }

  // --- geometry ---

  const clusterTotal = clusters.length * (CLUSTER_BOX.h + CLUSTER_BOX.gap) - CLUSTER_BOX.gap
  const clusterY0 = (BOARD_H - clusterTotal) / 2 + 10
  const clusterLayout = clusters.map((c, i) => ({ cluster: c, y: clusterY0 + i * (CLUSTER_BOX.h + CLUSTER_BOX.gap) }))
  const clusterCyById = new Map(clusterLayout.map(({ cluster, y }) => [cluster.id, y + CLUSTER_BOX.h / 2]))

  const openCluster = clusters.find((c) => c.id === expanded)
  const openHosts = openCluster?.hosts ?? []
  const hostTotal = openHosts.length * (HOST_BOX.h + HOST_BOX.gap) - HOST_BOX.gap
  const hostY0 = 330 - hostTotal / 2
  const hostLayout = openHosts.map((h, i) => ({ host: h, y: hostY0 + i * (HOST_BOX.h + HOST_BOX.gap) }))
  const hostCyByName = new Map(hostLayout.map(({ host, y }) => [host.hostname, y + HOST_BOX.h / 2]))

  const techRows = sel?.technologies ?? []
  const techPanelH = PANEL.headerH + techRows.length * PANEL.rowH
  const pagePanelTop = PANEL.top + techPanelH + PANEL.gapBetweenPanels
  const pageGroups = sel ? (pageGroupsByHost.get(sel.hostname) ?? []) : []
  const maxGroupCount = Math.max(1, ...pageGroups.map((g) => g.count), 0)
  const selCy = sel ? (hostCyByName.get(sel.hostname) ?? 330) : 330

  // --- filtered counts for the toolbar / cluster subtitles ---

  let shownPages = 0
  let shownHosts = 0
  for (const c of clusters) {
    for (const h of c.hosts) {
      if (hostMatches(h, q, riskOnly)) {
        shownPages += h.pageCount
        shownHosts++
      }
    }
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-3 border-b border-neutral-800 px-3 py-2">
        <span className="text-[9.5px] font-semibold uppercase tracking-[.16em] text-neutral-500">Tiers</span>
        <div className="flex gap-1">
          {TIERS.map((t) => (
            <button
              key={t.id}
              onClick={() => toggleTier(t.id)}
              className={`rounded border px-1.5 py-0.5 text-xs transition-colors ${
                tierVisible[t.id] ? 'border-neutral-600 bg-neutral-800 text-neutral-100' : 'border-neutral-800 bg-transparent text-neutral-600 line-through'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
        <button
          onClick={() => setRiskOnly((v) => !v)}
          className={`rounded border px-2 py-0.5 text-xs transition-colors ${
            riskOnly ? 'border-red-500 bg-red-950/50 text-red-300' : 'border-red-900 bg-transparent text-red-400 hover:border-red-700'
          }`}
        >
          ⚠ exposed files &amp; CVEs only
        </button>
        <div className="ml-auto flex items-center gap-3">
          {progress && <ProgressBar done={progress.done} total={progress.total} />}
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search hostname / tech…"
            className="w-[200px] rounded border border-neutral-700 bg-neutral-900 px-2 py-1 font-mono text-xs text-neutral-100 outline-none focus:border-sky-500"
          />
          <span className="whitespace-nowrap font-mono text-[11.5px] text-neutral-500">
            {shownPages.toLocaleString()} of {apex.pageCount.toLocaleString()} pages · {shownHosts}/{apex.hostCount} hosts
          </span>
          <button
            onClick={scanSelected}
            disabled={scanning || selected.size === 0}
            className="rounded bg-sky-600 px-3 py-1 text-xs font-medium text-white hover:bg-sky-500 disabled:opacity-50"
          >
            {scanning ? 'Starting…' : `Scan selected (${selected.size})`}
          </button>
          {scanMessage && <span className="text-xs text-neutral-500">{scanMessage}</span>}
        </div>
      </div>

      <div className="flex-1 overflow-auto bg-neutral-950 p-3">
        {!domain ? (
          <p className="px-3 py-6 text-center text-xs text-neutral-600">Loading…</p>
        ) : (
          <div className="relative border border-neutral-800" style={{ width: BOARD_W, height: BOARD_H }}>
          <svg viewBox={`0 0 ${BOARD_W} ${BOARD_H}`} width={BOARD_W} height={BOARD_H} className="block" style={{ background: '#0a0a0a' }}>
            {/* tier hairlines */}
            <g stroke="#1c1c20" strokeWidth={1}>
              {GRID_X.map((x) => (
                <line key={x} x1={x} y1={0} x2={x} y2={BOARD_H} />
              ))}
            </g>

            {/* tier column labels */}
            <g fontFamily="ui-monospace, monospace" fontWeight={600} fontSize={9.5} letterSpacing="0.18em" fill="#3f3f46">
              <text x={24} y={20} opacity={tierVisible.site ? 1 : 0.3}>
                SITE
              </text>
              <text x={230} y={20} opacity={tierVisible.cluster ? 1 : 0.3}>
                CLUSTER
              </text>
              <text x={500} y={20} opacity={tierVisible.subdomain ? 1 : 0.3}>
                SUBDOMAIN
              </text>
              <text x={880} y={20} opacity={tierVisible.technology || tierVisible.pagegroup ? 1 : 0.3}>
                TECHNOLOGY  /  PAGES
              </text>
            </g>

            {/* apex -> cluster links */}
            <g fill="none" opacity={tierVisible.cluster ? 1 : 0.3}>
              {clusterLayout.map(({ cluster, y }) => {
                const cy = y + CLUSTER_BOX.h / 2
                const open = expanded === cluster.id
                const visCount = cluster.hosts.filter((h) => hostMatches(h, q, riskOnly)).length
                return (
                  <path
                    key={cluster.id}
                    d={`M206,${APEX_Y} C 214,${APEX_Y} 216,${cy} 230,${cy}`}
                    stroke={open ? cluster.color : '#2f2f35'}
                    strokeWidth={open ? 1.6 : 1}
                    opacity={visCount ? 1 : 0.3}
                  />
                )
              })}
            </g>

            {/* apex box */}
            <g opacity={tierVisible.site ? 1 : 0.3}>
              <rect x={APEX_BOX.x} y={APEX_Y - APEX_BOX.h / 2} width={APEX_BOX.w} height={APEX_BOX.h} fill="#101014" stroke="#38bdf8" strokeWidth={1} />
              <rect x={APEX_BOX.x} y={APEX_Y - APEX_BOX.h / 2} width={3} height={APEX_BOX.h} fill="#38bdf8" />
              <text x={APEX_BOX.x + 14} y={APEX_Y - 6} fontFamily="ui-monospace, monospace" fontSize={12.5} fill="#f5f5f5">
                {truncate(apex.hostname, APEX_BOX.w - 26, 12.5, true)}
              </text>
              <text x={APEX_BOX.x + 14} y={APEX_Y + 11} fontFamily="ui-sans-serif, system-ui" fontSize={11} fill="#71717a">
                {truncate(`apex · ${apex.hostCount} hosts · ${apex.pageCount.toLocaleString()} pages`, APEX_BOX.w - 26, 11, false)}
              </text>
            </g>

            {/* cluster boxes */}
            <g opacity={tierVisible.cluster ? 1 : 0.3}>
              {clusterLayout.map(({ cluster, y }) => {
                const open = expanded === cluster.id
                const visCount = cluster.hosts.filter((h) => hostMatches(h, q, riskOnly)).length
                const titleColor = visCount ? '#f5f5f5' : '#52525b'
                const sub = `${visCount}/${cluster.hosts.length} hosts · ${cluster.pageCount.toLocaleString()} pages · ${cluster.techCount} tech`
                const meta = cluster.exposedFiles > 0 ? `⚠ ${cluster.exposedFiles}` : ''
                return (
                  <g key={cluster.id}>
                    <rect
                      x={CLUSTER_BOX.x}
                      y={y}
                      width={CLUSTER_BOX.w}
                      height={CLUSTER_BOX.h}
                      fill={open ? '#131318' : '#0d0d10'}
                      stroke={open ? cluster.color : '#2b2b2f'}
                      strokeWidth={open ? 1.5 : 1}
                    />
                    <rect x={CLUSTER_BOX.x} y={y} width={3} height={CLUSTER_BOX.h} fill={cluster.color} />
                    <text x={CLUSTER_BOX.x + 14} y={y + CLUSTER_BOX.h / 2 - 6} fontWeight={600} fontSize={12.5} letterSpacing="0.05em" fill={titleColor}>
                      {truncate((open ? '−  ' : '+  ') + cluster.label.toUpperCase(), CLUSTER_BOX.w - 26 - (meta.length + 1) * 7, 12.5, false)}
                    </text>
                    <text x={CLUSTER_BOX.x + 14} y={y + CLUSTER_BOX.h / 2 + 10} fontSize={11} fill="#71717a">
                      {truncate(sub, CLUSTER_BOX.w - 26, 11, false)}
                    </text>
                    {meta && (
                      <text x={CLUSTER_BOX.x + CLUSTER_BOX.w - 12} y={y + CLUSTER_BOX.h / 2 - 6} textAnchor="end" fontFamily="ui-monospace, monospace" fontSize={11} fill="#f87171">
                        {meta}
                      </text>
                    )}
                  </g>
                )
              })}
            </g>

            {/* cluster -> host links */}
            {expanded && (
              <g fill="none" opacity={tierVisible.subdomain ? 1 : 0.3}>
                {hostLayout.map(({ host, y }) => {
                  const clusterCy = clusterCyById.get(host.clusterId) ?? APEX_Y
                  const hostCy = y + HOST_BOX.h / 2
                  const on = hostMatches(host, q, riskOnly)
                  const lit = selHost === host.hostname || hover === host.hostname
                  return (
                    <path
                      key={host.hostname}
                      d={`M446,${clusterCy} C 470,${clusterCy} 474,${hostCy} 500,${hostCy}`}
                      stroke={lit ? '#38bdf8' : openCluster?.color ?? '#2f2f35'}
                      strokeWidth={lit ? 2 : 1}
                      opacity={on ? (lit ? 1 : 0.45) : 0.14}
                    />
                  )
                })}
              </g>
            )}

            {/* host rows */}
            {expanded && (
              <g opacity={tierVisible.subdomain ? 1 : 0.3}>
                {hostLayout.map(({ host, y }) => {
                  const on = hostMatches(host, q, riskOnly)
                  const isSelected = selHost === host.hostname
                  const isHovered = hover === host.hostname
                  const accent = host.exposedFiles > 0 ? '#f87171' : statusHexColor(host.statusCode ?? 0)
                  const titleColor = on ? '#f5f5f5' : '#3f3f46'
                  const meta = `${host.statusCode ?? '—'}  ·  ${host.pageCount}p  ·  ${host.technologies.length}t${host.exposedFiles ? '  ·  ⚠' + host.exposedFiles : ''}`
                  const metaColor = on ? (host.exposedFiles ? '#f87171' : '#8a8a92') : '#3f3f46'
                  return (
                    <g key={host.hostname}>
                      <rect
                        x={HOST_BOX.x}
                        y={y}
                        width={HOST_BOX.w}
                        height={HOST_BOX.h}
                        fill={isSelected ? '#12181f' : isHovered ? '#131317' : '#0c0c0e'}
                        stroke={isSelected ? '#38bdf8' : on ? '#2b2b2f' : '#1c1c20'}
                        strokeWidth={isSelected ? 1.5 : 1}
                      />
                      <rect x={HOST_BOX.x} y={y} width={3} height={HOST_BOX.h} fill={accent} />
                      <text x={HOST_BOX.x + 14} y={y + HOST_BOX.h / 2 + 4} fontFamily="ui-monospace, monospace" fontSize={12.5} fill={titleColor}>
                        {truncate(host.hostname, HOST_BOX.w - 26 - (meta.length + 1) * 6, 12.5, true)}
                      </text>
                      <text x={HOST_BOX.x + HOST_BOX.w - 12} y={y + HOST_BOX.h / 2 + 4} textAnchor="end" fontFamily="ui-monospace, monospace" fontSize={11} fill={metaColor}>
                        {meta}
                      </text>
                    </g>
                  )
                })}
              </g>
            )}

            {/* selected host -> panel links */}
            {sel && (
              <g fill="none">
                {tierVisible.technology && <path d={`M800,${selCy} C 840,${selCy} 840,72 880,72`} stroke="#38bdf8" strokeWidth={2} />}
                {tierVisible.pagegroup && (
                  <path d={`M800,${selCy} C 840,${selCy} 840,${pagePanelTop + 28} 880,${pagePanelTop + 28}`} stroke="#38bdf8" strokeWidth={2} />
                )}
              </g>
            )}

            {/* technology panel */}
            {sel && tierVisible.technology && (
              <g>
                <rect x={PANEL.x} y={PANEL.top} width={PANEL.w} height={techPanelH} fill="#0c0c0e" stroke="#2b2b2f" strokeWidth={1} />
                <line x1={PANEL.x} y1={PANEL.top + PANEL.headerH} x2={PANEL.x + PANEL.w} y2={PANEL.top + PANEL.headerH} stroke="#232327" />
                <text x={PANEL.x + 12} y={PANEL.top + 21} fontWeight={600} fontFamily="ui-monospace, monospace" fontSize={9.5} letterSpacing="0.16em" fill="#8a8a92">
                  {truncate(`TECHNOLOGIES ON ${sel.hostname}`.toUpperCase(), PANEL.w - 24 - 80, 9.5, true)}
                </text>
                <text x={PANEL.x + PANEL.w - 12} y={PANEL.top + 21} textAnchor="end" fontFamily="ui-monospace, monospace" fontSize={11} fill="#52525b">
                  {techRows.length} detected
                </text>
                {techRows.length === 0 && (
                  <text x={PANEL.x + 12} y={PANEL.top + PANEL.headerH + 18} fontSize={11.5} fill="#52525b">
                    Nothing fingerprinted on this host yet.
                  </text>
                )}
                {techRows.map((t, i) => {
                  const rowY = PANEL.top + PANEL.headerH + i * PANEL.rowH
                  const category = t.category || 'web-server'
                  const color = CAT_COLOR[category] ?? CAT_COLOR_DEFAULT
                  const cveN = t.cves?.length ?? 0
                  const meta = `${category}${cveN ? '  ·  ' + cveN + ' CVE' : ''}`
                  return (
                    <g key={t.name} onMouseEnter={() => setHoverTech(t.name)} onMouseLeave={() => setHoverTech(null)}>
                      <rect x={PANEL.x} y={rowY} width={PANEL.w} height={PANEL.rowH} fill={hoverTech === t.name ? '#16161b' : 'transparent'} />
                      <line x1={PANEL.x} y1={rowY + PANEL.rowH} x2={PANEL.x + PANEL.w} y2={rowY + PANEL.rowH} stroke="#131316" />
                      <rect x={PANEL.x} y={rowY} width={3} height={PANEL.rowH} fill={color} />
                      <text x={PANEL.x + 14} y={rowY + PANEL.rowH / 2 + 4} fontFamily="ui-monospace, monospace" fontSize={12} fill="#e5e5e5">
                        {truncate(t.name, PANEL.w - 26 - (meta.length + 1) * 6, 12, true)}
                      </text>
                      <text x={PANEL.x + PANEL.w - 12} y={rowY + PANEL.rowH / 2 + 4} textAnchor="end" fontFamily="ui-monospace, monospace" fontSize={11} fill={cveN ? '#f87171' : '#71717a'}>
                        {meta}
                      </text>
                    </g>
                  )
                })}
              </g>
            )}

            {/* page-group panel */}
            {sel && tierVisible.pagegroup && (
              <g>
                <rect x={PANEL.x} y={pagePanelTop} width={PANEL.w} height={PANEL.headerH + pageGroups.length * PANEL.rowH} fill="#0c0c0e" stroke="#2b2b2f" strokeWidth={1} />
                <line x1={PANEL.x} y1={pagePanelTop + PANEL.headerH} x2={PANEL.x + PANEL.w} y2={pagePanelTop + PANEL.headerH} stroke="#232327" />
                <text x={PANEL.x + 12} y={pagePanelTop + 21} fontWeight={600} fontFamily="ui-monospace, monospace" fontSize={9.5} letterSpacing="0.16em" fill="#8a8a92">
                  {truncate(`PAGE GROUPS ON ${sel.hostname}`.toUpperCase(), PANEL.w - 24 - 80, 9.5, true)}
                </text>
                <text x={PANEL.x + PANEL.w - 12} y={pagePanelTop + 21} textAnchor="end" fontFamily="ui-monospace, monospace" fontSize={11} fill="#52525b">
                  {sel.pageCount.toLocaleString()} pages
                </text>
                {pageGroups.length === 0 && (
                  <text x={PANEL.x + 12} y={pagePanelTop + PANEL.headerH + 18} fontSize={11.5} fill="#52525b">
                    No pages discovered on this host yet.
                  </text>
                )}
                {pageGroups.map((g, i) => {
                  const rowY = pagePanelTop + PANEL.headerH + i * PANEL.rowH
                  const barW = Math.max(2, (g.count / maxGroupCount) * 120)
                  const meta = `${g.statusCode}  ·  ${g.count}`
                  return (
                    <g key={g.key}>
                      <rect x={PANEL.x} y={rowY} width={PANEL.w} height={PANEL.rowH} fill={g.dangerous ? '#1a0d0d' : 'transparent'} />
                      <line x1={PANEL.x} y1={rowY + PANEL.rowH} x2={PANEL.x + PANEL.w} y2={rowY + PANEL.rowH} stroke="#131316" />
                      <rect x={PANEL.x} y={rowY} width={3} height={PANEL.rowH} fill={g.dangerous ? '#f87171' : statusHexColor(g.statusCode)} />
                      <text x={PANEL.x + 14} y={rowY + PANEL.rowH / 2 + 4} fontFamily="ui-monospace, monospace" fontSize={12} fill={g.dangerous ? '#fca5a5' : '#d4d4d8'}>
                        {truncate((g.dangerous ? '⚠ ' : '') + g.label, 250, 12, true)}
                      </text>
                      <rect x={PANEL.x + PANEL.w - 12 - 74 - 10 - 120} y={rowY + PANEL.rowH / 2 - 2} width={120} height={4} fill="#1c1c20" />
                      <rect
                        x={PANEL.x + PANEL.w - 12 - 74 - 10 - 120}
                        y={rowY + PANEL.rowH / 2 - 2}
                        width={barW}
                        height={4}
                        fill={g.dangerous ? '#f87171' : '#5980a6'}
                      />
                      <text
                        x={PANEL.x + PANEL.w - 12}
                        y={rowY + PANEL.rowH / 2 + 4}
                        textAnchor="end"
                        fontFamily="ui-monospace, monospace"
                        fontSize={11}
                        fill={g.dangerous ? '#f87171' : '#71717a'}
                      >
                        {meta}
                      </text>
                    </g>
                  )
                })}
              </g>
            )}
          </svg>

          {/* Interactive overlay -- real <button>s at the same coordinates
              as the cluster/host rects above, so tab order and
              :focus-visible work. Purely transparent: every pixel a viewer
              sees is the SVG underneath, this layer only owns
              click/focus/hover semantics. */}
          <button
            onClick={() => setSelHost(apex.hostname)}
            aria-label={`${apex.hostname} apex`}
            className="absolute border-0 bg-transparent p-0 outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-sky-400"
            style={{ left: APEX_BOX.x, top: APEX_Y - APEX_BOX.h / 2, width: APEX_BOX.w, height: APEX_BOX.h }}
          />
          {clusterLayout.map(({ cluster, y }) => (
            <button
              key={cluster.id}
              onClick={() => {
                const opening = expanded !== cluster.id
                setExpanded(opening ? cluster.id : null)
                if (opening) setSelHost(cluster.hosts[0]?.hostname ?? null)
              }}
              aria-expanded={expanded === cluster.id}
              aria-label={`${cluster.label} cluster`}
              className="absolute border-0 bg-transparent p-0 outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-sky-400"
              style={{ left: CLUSTER_BOX.x, top: y, width: CLUSTER_BOX.w, height: CLUSTER_BOX.h }}
            />
          ))}
          {expanded &&
            hostLayout.map(({ host, y }) => (
              <button
                key={host.hostname}
                onClick={() => toggleHost(host)}
                onMouseEnter={() => setHover(host.hostname)}
                onMouseLeave={() => setHover(null)}
                onFocus={() => setHover(host.hostname)}
                onBlur={() => setHover(null)}
                aria-pressed={selected.has(host.hostname)}
                aria-label={`${host.hostname}${selected.has(host.hostname) ? ' (selected for scan)' : ''}`}
                className="absolute border-0 bg-transparent p-0 outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-sky-400"
                style={{ left: HOST_BOX.x, top: y, width: HOST_BOX.w, height: HOST_BOX.h }}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
