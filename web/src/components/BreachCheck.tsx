import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import { toAbsoluteUrl } from '../url'
import type { Breach, BreachCheckResponse, BreachCrawlResponse, CaseScan, Credential, Target } from '../types'
import { CollapsibleFormPanel } from './CollapsibleFormPanel'
import { TargetPicker } from './TargetPicker'
import { CredentialPicker } from './CredentialPicker'
import { useAutoCollapseOnce, useCollapsible } from '../collapsible'
import { inputBase } from '../formStyles'
import { CopyButton } from './CopyButton'
import { BatchResultsPanel, type BatchResultSummary } from './BatchResultsPanel'
import { ScanTargetCard } from './ScanTargetCard'
import { emptyProgress, runTrackedScan, type TrackedScan } from '../scanProgress'
import { ScanHistoryPanel } from './ScanHistoryPanel'
import { ScanWindowTabs } from './ScanWindowTabs'
import { latestByTarget, loadCaseScans } from '../scanHistory'

// CrawlTargetState is one target's place in a (possibly multi-target) email
// crawl -- same shape/reasoning as Probe.tsx's TargetScanState, since this
// runs the very same crawl (see internal/breach.CrawlForEmails, ported from
// internal/secretscan.Run).
import { ScanErrorNotice } from './ScanErrorNotice'

type CrawlTargetState = TrackedScan<BreachCrawlResponse>

// EmailCheckState is one address's place in the breach check -- 'idle'
// until the user (or "Check selected") asks for it specifically, since an
// address just found by the crawler hasn't been looked up yet.
interface EmailCheckState {
  status: 'idle' | 'running' | 'done' | 'error'
  breaches?: Breach[]
  error?: string
}

const CRAWL_DEPTHS = [0, 1, 2, 3] as const

// EMAIL_FILTER_THRESHOLD is when EmailListPanel adds a filter box and caps
// its own scroll height -- a crawl across 100s of targets can turn up
// hundreds of addresses, which used to just make the whole tab's page
// scroll longer with no way to jump to one address.
const EMAIL_FILTER_THRESHOLD = 10

// hostnameOf resolves a (possibly scheme-less) crawl target to the hostname
// the crawl actually ran against, for use as a default domain filter --
// same normalization runOneCrawl applies before calling the API.
function hostnameOf(target: string): string | null {
  try {
    return new URL(toAbsoluteUrl(target)).hostname.toLowerCase()
  } catch {
    return null
  }
}

// emailMatchesDomains reports whether email's domain is exactly one of
// domains, or a subdomain of one -- mail@staff.target.htb matches a
// target.htb filter, mail@target.htb.evil.com does not.
function emailMatchesDomains(email: string, domains: string[]): boolean {
  const at = email.lastIndexOf('@')
  if (at < 0) return false
  const domain = email.slice(at + 1).toLowerCase()
  return domains.some((d) => domain === d || domain.endsWith(`.${d}`))
}

// BreachCheck is a single two-step flow, laid out the same way Probe.tsx
// is (one input panel that collapses once it's running, one results column
// below that fills in on its own): crawl one or more targets for email
// addresses (internal/breach.CrawlForEmails), then pick which of the
// addresses that turned up to check against HaveIBeenPwned. Those are the
// only two decisions this makes the user own -- which sites to crawl, and
// which emails to check -- everything else (running the crawl per target,
// deduping addresses, pacing HIBP lookups) happens on its own once asked.
export function BreachCheck({ caseId, targets, credentials }: { caseId: string; targets: Target[]; credentials: Credential[] }) {
  // --- Step 1: crawl targets for emails ---
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [manualTarget, setManualTarget] = useState('')
  const [recursionDepth, setRecursionDepth] = useState<(typeof CRAWL_DEPTHS)[number]>(0)
  const [credentialId, setCredentialId] = useState<string | undefined>()
  const [scans, setScans] = useState<Record<string, CrawlTargetState>>({})

  const hasScans = Object.keys(scans).length > 0
  const [formOpen, setFormOpen] = useCollapsible('breach.form', true)
  useAutoCollapseOnce(hasScans, setFormOpen)
  const [view, setView] = useState<'scan' | 'history'>('scan')

  // Restores this case's most recent email crawl per target on
  // mount/reload -- see saveCaseScan in internal/api/handlers_breach.go
  // (the crawl-emails handler, persisted under its own "breach-crawl" tool
  // name -- see that file's comment). Every past crawl is also browsable
  // via the "Scan history" tab below.
  useEffect(() => {
    let cancelled = false
    loadCaseScans<BreachCrawlResponse>(caseId, 'breach-crawl').then((list) => {
      if (cancelled) return
      const restored = latestByTarget(list)
      if (restored.length === 0) return
      setScans((prev) => {
        const next = { ...prev }
        for (const r of restored) if (!next[r.scan.target]) next[r.scan.target] = { status: 'done', result: r.data }
        return next
      })
    })
    return () => {
      cancelled = true
    }
  }, [caseId])

  // manualTargets/runTargets: same "case targets + one-off paste" merge as
  // Probe.tsx/SecretScan.tsx.
  const manualTargets = useMemo(() => manualTarget.split(/[,\n]+/).map((s) => s.trim()).filter(Boolean), [manualTarget])
  const runTargets = useMemo(() => [...new Set([...selected, ...manualTargets])], [selected, manualTargets])
  const crawling = Object.values(scans).some((s) => s.status === 'running')
  const canCrawl = runTargets.length > 0 && !crawling

  // runCrawl kicks off one independent crawl per target in runTargets --
  // each resolves on its own schedule, same batch pattern as Probe.tsx.
  const runCrawl = () => {
    if (!canCrawl) return
    const list = runTargets
    setScans(Object.fromEntries(list.map((t) => [t, { status: 'running' as const, progress: emptyProgress() }])))
    for (const t of list) runOneCrawl(t)
  }

  // runOneCrawl streams this target's crawl into its card, and lands the
  // addresses it found once the crawl finishes.
  const runOneCrawl = (targetValue: string) =>
    runTrackedScan<BreachCrawlResponse>(
      // A target picked from the case list (or typed bare) has no scheme --
      // breach.CrawlForEmails rejects that outright, same as secretscan.Run.
      () => api.crawlEmails({ url: toAbsoluteUrl(targetValue), recursionDepth, credentialId, caseId }),
      (update) => setScans((prev) => (prev[targetValue] ? { ...prev, [targetValue]: update(prev[targetValue]) } : prev)),
    )

  const crawlLabel = runTargets.length > 1 ? `Crawl (${runTargets.length})` : 'Crawl'

  // --- Step 2: select + check emails ---
  // manualEmails covers the original "paste an address recon already
  // turned up elsewhere" case -- folded into the same list the crawler
  // fills, rather than a second competing panel.
  const [manualEmails, setManualEmails] = useState<string[]>([])
  const [addEmailInput, setAddEmailInput] = useState('')
  const [selectedEmails, setSelectedEmails] = useState<Set<string>>(new Set())
  const [checks, setChecks] = useState<Record<string, EmailCheckState>>({})
  // checkRun is the live batch behind the email lookups, shown as one card with a square per address.
  const [checkRun, setCheckRun] = useState<TrackedScan<BreachCheckResponse> | null>(null)

  // Restores this case's most recent breach-check result per email on
  // mount/reload -- see saveCaseScan in internal/api/handlers_breach.go
  // (the breach-check handler, persisted under "breach"). Each saved row
  // covers a whole batch of emails checked together (its target is the
  // joined address list), so unlike the single-target tools this flattens
  // every row's own per-email results instead of deduping by row target --
  // first occurrence per email wins, and loadCaseScans is already
  // most-recent-first.
  useEffect(() => {
    let cancelled = false
    loadCaseScans<BreachCheckResponse>(caseId, 'breach').then((list) => {
      if (cancelled || list.length === 0) return
      const restored: Record<string, EmailCheckState> = {}
      for (const r of list) {
        for (const er of r.data.results ?? []) {
          if (restored[er.email]) continue
          restored[er.email] = er.error ? { status: 'error', error: er.error } : { status: 'done', breaches: er.breaches }
        }
      }
      setChecks((prev) => ({ ...restored, ...prev }))
    })
    return () => {
      cancelled = true
    }
  }, [caseId])

  // Domain filter: crawling a site's pages/scripts turns up plenty of
  // addresses that have nothing to do with the target (support@vendor.com in
  // a footer widget, noreply@analytics-tool.io in a tracking script). By
  // default only addresses on one of the crawled targets' own domains (or a
  // subdomain of one) are shown; extraDomains lets you widen that to related
  // domains the crawl didn't hit directly. Manually-added addresses always
  // show regardless -- you typed them in for a reason.
  const [domainFilterEnabled, setDomainFilterEnabled] = useState(true)
  const [extraDomains, setExtraDomains] = useState('')

  const crawledEmails = useMemo(() => [...new Set(Object.values(scans).flatMap((s) => s.result?.emails ?? []))], [scans])

  const crawledHostnames = useMemo(
    () => [...new Set(Object.keys(scans).map(hostnameOf).filter((h): h is string => !!h))],
    [scans],
  )
  const extraDomainList = useMemo(
    () => [...new Set(extraDomains.split(/[,\n]+/).map((s) => s.trim().toLowerCase()).filter(Boolean))],
    [extraDomains],
  )
  const filterDomains = useMemo(
    () => (domainFilterEnabled ? [...new Set([...crawledHostnames, ...extraDomainList])] : []),
    [domainFilterEnabled, crawledHostnames, extraDomainList],
  )

  const filteredCrawledEmails = useMemo(
    () => (filterDomains.length === 0 ? crawledEmails : crawledEmails.filter((e) => emailMatchesDomains(e, filterDomains))),
    [crawledEmails, filterDomains],
  )
  const allEmails = useMemo(() => [...new Set([...filteredCrawledEmails, ...manualEmails])], [filteredCrawledEmails, manualEmails])
  const hiddenByFilterCount = crawledEmails.length - filteredCrawledEmails.length

  const addEmails = () => {
    const additions = addEmailInput.split(/[,\n]+/).map((s) => s.trim().toLowerCase()).filter(Boolean)
    if (additions.length === 0) return
    setManualEmails((prev) => [...new Set([...prev, ...additions])])
    setAddEmailInput('')
  }

  const toggleEmail = (e: string) => {
    setSelectedEmails((prev) => {
      const next = new Set(prev)
      if (next.has(e)) next.delete(e)
      else next.add(e)
      return next
    })
  }
  const allEmailsSelected = allEmails.length > 0 && allEmails.every((e) => selectedEmails.has(e))
  const toggleAllEmails = () => setSelectedEmails(allEmailsSelected ? new Set() : new Set(allEmails))

  const checking = Object.values(checks).some((c) => c.status === 'running')

  // checkEmails runs one HIBP batch lookup (handleBreachCheck already
  // paces requests to HIBP's shared rate limit server-side) for whichever
  // addresses it's given -- a single row's own "Check" button, or "Check
  // selected" for however many are ticked. Every address's own status
  // persists in `checks`, so checking more emails later never loses an
  // earlier result.
  const checkEmails = async (list: string[]) => {
    const unique = [...new Set(list)]
    if (unique.length === 0 || checking) return
    setChecks((prev) => ({ ...prev, ...Object.fromEntries(unique.map((e) => [e, { status: 'running' as const }])) }))
    setCheckRun({ status: 'running', progress: emptyProgress() })
    const outcome = await runTrackedScan<BreachCheckResponse>(
      () => api.breachCheck({ emails: unique, caseId }),
      (update) => setCheckRun((prev) => update(prev ?? { status: 'running', progress: emptyProgress() })),
    )
    if (outcome.result) {
      const resp = outcome.result
      setChecks((prev) => {
        const next = { ...prev }
        for (const r of resp.results) {
          next[r.email] = r.error ? { status: 'error', error: r.error } : { status: 'done', breaches: r.breaches }
        }
        return next
      })
      return
    }
    const message = outcome.error ?? 'Breach check failed'
    setChecks((prev) => {
      const next = { ...prev }
      for (const e of unique) next[e] = { status: 'error', error: message }
      return next
    })
  }

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto p-6">
      <CollapsibleFormPanel
        title="Breach Check"
        open={formOpen}
        onToggle={() => setFormOpen(!formOpen)}
        summary={runTargets.length > 0 ? `${runTargets.length} target${runTargets.length === 1 ? '' : 's'} queued` : 'No targets selected'}
        onRun={runCrawl}
        canRun={canCrawl}
        loading={crawling}
        runLabel={crawlLabel}
      >
        <div>
          <h1 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">Breach Check</h1>
          <p className="mt-1 text-xs text-neutral-500">
            Crawls a target for email addresses (same-origin pages + scripts, optionally following same-origin links), then
            checks whichever ones you pick against HaveIBeenPwned's breach database. Runs against as many targets at once as
            you select. Authorized testing only.
          </p>
        </div>

        <div>
          <span className="text-xs font-medium text-neutral-300">Targets in this case</span>
          <div className="mt-1">
            <TargetPicker targets={targets} selected={selected} onChange={setSelected} />
          </div>
        </div>

        <label className="block">
          <span className="text-xs font-medium text-neutral-300">Additional targets</span>
          <span className="mt-0.5 block text-[11px] text-neutral-600">
            One-off URLs/hosts not saved to the case -- comma- or newline-separated for a batch.
          </span>
          <textarea
            value={manualTarget}
            onChange={(e) => setManualTarget(e.target.value)}
            placeholder="target.htb, https://staff.target.htb"
            rows={2}
            className={`mt-1 ${inputBase}`}
          />
        </label>

        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-medium text-neutral-300">Crawl depth</span>
          {CRAWL_DEPTHS.map((d) => (
            <button
              key={d}
              type="button"
              title={d === 0 ? 'Just the homepage and its scripts' : `Also follow same-origin links ${d} hop${d === 1 ? '' : 's'} deep`}
              onClick={() => setRecursionDepth(d)}
              className={`rounded border px-2 py-0.5 text-xs ${
                recursionDepth === d ? 'border-sky-500 bg-sky-950/40 text-sky-300' : 'border-neutral-700 bg-neutral-900 text-neutral-400 hover:border-sky-600'
              }`}
            >
              {d === 0 ? 'Homepage only' : `+${d} hop${d === 1 ? '' : 's'}`}
            </button>
          ))}
        </div>

        <CredentialPicker credentials={credentials} selected={credentialId} onSelect={setCredentialId} />

        <button
          onClick={runCrawl}
          disabled={!canCrawl}
          className="w-full rounded bg-sky-600 px-3 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {crawling ? 'Crawling…' : crawlLabel}
        </button>
      </CollapsibleFormPanel>

      <div className="min-w-0 flex-1 space-y-4">
        <ScanWindowTabs view={view} onChange={setView} />

        {view === 'history' ? (
          <BreachHistoryTab caseId={caseId} />
        ) : (
          <>
            {!hasScans && allEmails.length === 0 && (
              <div className="flex h-64 items-center justify-center rounded-lg border border-dashed border-neutral-800 text-sm text-neutral-600">
                Select or type one or more targets above, then crawl.
              </div>
            )}

            {hasScans && (
              <BatchResultsPanel
                entries={Object.entries(scans)}
                getSummary={crawlSummary}
                getProgress={(scan) => scan.progress}
                renderCard={(t, scan) => <CrawlTargetCard target={t} scan={scan} />}
              />
            )}

            {checkRun && (
              <div className="max-w-md">
                <ScanTargetCard
                  target={`Breach check · ${checkRun.progress?.checks.length ?? 0} email${checkRun.progress?.checks.length === 1 ? '' : 's'}`}
                  summary={checkSummary(checkRun)}
                  progress={checkRun.progress}
                  selected={false}
                  onSelect={() => {}}
                />
              </div>
            )}

            {(hasScans || allEmails.length > 0) && (
              <EmailListPanel
                emails={allEmails}
                selected={selectedEmails}
                allSelected={allEmailsSelected}
                checks={checks}
                checking={checking}
                addEmailInput={addEmailInput}
                onAddEmailInputChange={setAddEmailInput}
                onAddEmail={addEmails}
                onToggle={toggleEmail}
                onToggleAll={toggleAllEmails}
                onCheck={checkEmails}
                domainFilterEnabled={domainFilterEnabled}
                onToggleDomainFilter={() => setDomainFilterEnabled((v) => !v)}
                filterDomains={filterDomains}
                extraDomains={extraDomains}
                onExtraDomainsChange={setExtraDomains}
                hiddenByFilterCount={hiddenByFilterCount}
              />
            )}
          </>
        )}
      </div>
    </div>
  )
}

// BreachHistoryTab is this tool's "Scan history" view, covering both halves
// of the flow: every email crawl persisted for this case (reusing the same
// crawlSummary/CrawlTargetCard the live view uses, via ScanHistoryPanel),
// and every breach-check batch, each opened to show its own per-email
// results with EmailRow -- same row component the live Emails list uses,
// just without the checkbox/recheck controls a past, immutable result has
// no use for.
function BreachHistoryTab({ caseId }: { caseId: string }) {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="mb-2 text-xs font-semibold uppercase tracking-wide text-neutral-400">Email crawls</h2>
        <ScanHistoryPanel
          caseId={caseId}
          tool="breach-crawl"
          toState={(data: BreachCrawlResponse) => ({ status: 'done' as const, result: data })}
          getSummary={crawlSummary}
          renderCard={(t, scan) => <CrawlTargetCard target={t} scan={scan} />}
        />
      </div>
      <div>
        <h2 className="mb-2 text-xs font-semibold uppercase tracking-wide text-neutral-400">Breach checks</h2>
        <BreachCheckHistoryList caseId={caseId} />
      </div>
    </div>
  )
}

function BreachCheckHistoryList({ caseId }: { caseId: string }) {
  const [loading, setLoading] = useState(true)
  const [scans, setScans] = useState<CaseScan[]>([])
  const [openId, setOpenId] = useState<string | null>(null)
  const [openResult, setOpenResult] = useState<BreachCheckResponse | null>(null)
  const [loadingDetail, setLoadingDetail] = useState(false)

  useEffect(() => {
    let cancelled = false
    api.listCaseScans(caseId, 'breach').then((list) => {
      if (cancelled) return
      setScans(list)
      setLoading(false)
    })
    return () => {
      cancelled = true
    }
  }, [caseId])

  const toggle = async (id: string) => {
    if (openId === id) {
      setOpenId(null)
      return
    }
    setOpenId(id)
    setOpenResult(null)
    setLoadingDetail(true)
    try {
      const full = await api.getCaseScan(id)
      setOpenResult(full.data ? (JSON.parse(full.data) as BreachCheckResponse) : null)
    } finally {
      setLoadingDetail(false)
    }
  }

  if (loading) return <div className="flex h-32 items-center justify-center text-sm text-neutral-600">Loading…</div>
  if (scans.length === 0) {
    return (
      <div className="flex h-32 items-center justify-center rounded-lg border border-dashed border-neutral-800 text-sm text-neutral-600">
        No saved breach checks yet.
      </div>
    )
  }

  return (
    <div className="divide-y divide-neutral-900 rounded-lg border border-neutral-800 bg-neutral-950/40">
      {scans.map((s) => (
        <div key={s.id}>
          <button
            type="button"
            onClick={() => toggle(s.id)}
            className="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-neutral-900/60"
          >
            <span className="shrink-0 text-xs text-neutral-600">{openId === s.id ? '▾' : '▸'}</span>
            <span className="min-w-0 flex-1 truncate font-mono text-xs text-neutral-200">{s.target}</span>
            <span className="shrink-0 text-[11px] text-neutral-500">{s.summary}</span>
            <span className="shrink-0 text-[11px] text-neutral-600">{new Date(s.createdAt).toLocaleString()}</span>
          </button>
          {openId === s.id && (
            <div className="border-t border-neutral-800 p-3">
              {loadingDetail && <p className="text-xs text-neutral-600">Loading…</p>}
              {openResult && (
                <div className="divide-y divide-neutral-900">
                  {openResult.results.map((r) => (
                    <EmailRow
                      key={r.email}
                      email={r.email}
                      selected={false}
                      state={r.error ? { status: 'error', error: r.error } : { status: 'done', breaches: r.breaches }}
                      onToggle={() => {}}
                      onCheck={() => {}}
                    />
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

// crawlSummary is one crawled target's one-line compact-view badge once a
// batch covers more than BatchResultsPanel's threshold -- an email crawl
// finding addresses isn't itself bad (tone: warn, "worth a look") the way a
// Probe/SecretScan finding is, since the actual risk signal is which of
// those addresses turns up breached, decided later in the email list below.
function crawlSummary(scan: CrawlTargetState): BatchResultSummary {
  if (scan.status === 'running') return { label: 'Running…', tone: 'neutral', running: true }
  if (scan.status === 'error') return { label: 'Error', tone: 'danger' }
  const n = scan.result?.emails.length ?? 0
  return n === 0 ? { label: 'No emails', tone: 'clean' } : { label: `${n} email${n === 1 ? '' : 's'}`, tone: 'warn' }
}

const CRAWL_STATUS_STYLES: Record<CrawlTargetState['status'], { label: string; cls: string }> = {
  running: { label: 'Running…', cls: 'border-amber-700 bg-amber-950/40 text-amber-300' },
  done: { label: 'Done', cls: 'border-emerald-700 bg-emerald-950/40 text-emerald-300' },
  error: { label: 'Failed', cls: 'border-red-700 bg-red-950/40 text-red-300' },
}

function CrawlTargetCard({ target, scan }: { target: string; scan: CrawlTargetState }) {
  const [expanded, setExpanded] = useState(false)
  const meta = CRAWL_STATUS_STYLES[scan.status]
  const emails = scan.result?.emails ?? []
  const canExpand = scan.status === 'done' && emails.length > 0

  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-3">
      <div
        onClick={() => canExpand && setExpanded((v) => !v)}
        className={`flex items-center gap-2 ${canExpand ? 'cursor-pointer' : ''}`}
      >
        <span className="min-w-0 flex-1 truncate font-mono text-xs text-neutral-200">{target}</span>
        <span className={`shrink-0 rounded border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${meta.cls}`}>{meta.label}</span>
        {canExpand && <span className="shrink-0 text-xs text-neutral-600">{expanded ? '▾' : '▸'}</span>}
      </div>
      {scan.status === 'error' && <ScanErrorNotice message={scan.error} />}
      {scan.status === 'done' && scan.result && (
        <p
          onClick={() => canExpand && setExpanded((v) => !v)}
          className={`mt-2 text-[11px] text-neutral-500 ${canExpand ? 'cursor-pointer' : ''}`}
        >
          {scan.result.pagesScanned.length} page{scan.result.pagesScanned.length === 1 ? '' : 's'} ·{' '}
          {scan.result.scriptsScanned.length} script{scan.result.scriptsScanned.length === 1 ? '' : 's'} scanned ·{' '}
          <span className={scan.result.emails.length ? 'font-semibold text-neutral-300' : ''}>
            {scan.result.emails.length} email{scan.result.emails.length === 1 ? '' : 's'} found
          </span>
        </p>
      )}
      {expanded && scan.result && (
        <ul className="mt-2 divide-y divide-neutral-800 border-t border-neutral-800">
          {emails.map((e) => (
            <li key={e} className="py-1.5">
              <div className="flex items-center gap-2">
                <span className="min-w-0 flex-1 truncate font-mono text-xs text-neutral-200">{e}</span>
                <CopyButton text={e} />
              </div>
              <ul className="mt-0.5 space-y-0.5">
                {(scan.result!.emailSources[e] ?? []).map((url) => (
                  <li key={url} className="truncate pl-3 text-[11px] text-neutral-600">
                    {url}
                  </li>
                ))}
              </ul>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

// EmailListPanel is step 2 of the flow: every address the crawl(s) above
// turned up, plus any added by hand, in one list -- a checkbox per row,
// "Select all"/"Check selected" above it, and each row's own breach-check
// status/result once it's been checked. This is the only place a breach
// check is ever triggered from; there's no separate check form to open.
function EmailListPanel({
  emails,
  selected,
  allSelected,
  checks,
  checking,
  addEmailInput,
  onAddEmailInputChange,
  onAddEmail,
  onToggle,
  onToggleAll,
  onCheck,
  domainFilterEnabled,
  onToggleDomainFilter,
  filterDomains,
  extraDomains,
  onExtraDomainsChange,
  hiddenByFilterCount,
}: {
  emails: string[]
  selected: Set<string>
  allSelected: boolean
  checks: Record<string, EmailCheckState>
  checking: boolean
  addEmailInput: string
  onAddEmailInputChange: (v: string) => void
  onAddEmail: () => void
  onToggle: (e: string) => void
  onToggleAll: () => void
  onCheck: (list: string[]) => void
  domainFilterEnabled: boolean
  onToggleDomainFilter: () => void
  filterDomains: string[]
  extraDomains: string
  onExtraDomainsChange: (v: string) => void
  hiddenByFilterCount: number
}) {
  const [emailFilter, setEmailFilter] = useState('')

  // rankOf sorts breached addresses to the top, then ones still mid-check
  // or errored, then not-yet-checked, then confirmed-clean last -- so a
  // crawl across 100s of targets that turns up hundreds of addresses shows
  // what's actually breached first instead of requiring a scroll through
  // every clean/unchecked one to find it.
  const rankOf = (e: string): number => {
    const c = checks[e]
    if (!c || c.status === 'idle') return 2
    if (c.status === 'running' || c.status === 'error') return 1
    return (c.breaches?.length ?? 0) > 0 ? 0 : 3
  }
  const sortedEmails = useMemo(() => [...emails].sort((a, b) => rankOf(a) - rankOf(b) || a.localeCompare(b)), [emails, checks])
  const visibleEmails = useMemo(() => {
    const q = emailFilter.trim().toLowerCase()
    return q ? sortedEmails.filter((e) => e.toLowerCase().includes(q)) : sortedEmails
  }, [sortedEmails, emailFilter])

  return (
    <div className="space-y-3 rounded-lg border border-neutral-800 bg-neutral-950/40 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-xs font-semibold uppercase tracking-wide text-neutral-400">Emails{emails.length > 0 ? ` (${emails.length})` : ''}</h2>
        <button
          type="button"
          onClick={onToggleAll}
          disabled={emails.length === 0}
          className="ml-auto rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-[11px] text-neutral-400 hover:border-sky-600 hover:text-sky-400 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {allSelected ? 'Deselect all' : `Select all${emails.length > 0 ? ` (${emails.length})` : ''}`}
        </button>
        <button
          type="button"
          disabled={selected.size === 0 || checking}
          onClick={() => onCheck([...selected])}
          className="rounded bg-sky-600 px-3 py-1 text-[11px] font-medium text-white hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {checking ? 'Checking…' : `Check selected (${selected.size})`}
        </button>
      </div>

      <div className="space-y-1.5 rounded border border-neutral-800 bg-neutral-900/60 p-2">
        <label className="flex items-center gap-2 text-xs text-neutral-300">
          <input type="checkbox" checked={domainFilterEnabled} onChange={onToggleDomainFilter} className="accent-sky-500" />
          Only show crawled addresses on the target domain(s)/subdomains
        </label>
        {domainFilterEnabled && (
          <>
            <label className="block">
              <span className="mt-0.5 block text-[11px] text-neutral-600">
                Additional domains to allow, beyond the crawled target(s) -- comma- or newline-separated.
              </span>
              <textarea
                value={extraDomains}
                onChange={(e) => onExtraDomainsChange(e.target.value)}
                placeholder="target.htb, corp.target.htb"
                rows={1}
                className={`mt-1 ${inputBase} text-xs`}
              />
            </label>
            {filterDomains.length > 0 && (
              <p className="text-[11px] text-neutral-600">
                Matching: <span className="font-mono text-neutral-400">{filterDomains.join(', ')}</span>
                {hiddenByFilterCount > 0 && ` -- ${hiddenByFilterCount} other address${hiddenByFilterCount === 1 ? '' : 'es'} hidden`}
              </p>
            )}
          </>
        )}
      </div>

      <div className="flex items-center gap-2">
        <input
          value={addEmailInput}
          onChange={(e) => onAddEmailInputChange(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault()
              onAddEmail()
            }
          }}
          placeholder="Add an address by hand -- admin@target.htb"
          className={`${inputBase} text-xs`}
        />
        <button
          type="button"
          onClick={onAddEmail}
          className="shrink-0 rounded border border-neutral-700 px-2.5 py-1.5 text-xs text-neutral-300 hover:border-sky-500 hover:text-sky-400"
        >
          Add
        </button>
      </div>

      {emails.length === 0 ? (
        <p className="py-4 text-center text-xs text-neutral-600">No emails yet -- crawl a target above, or add one by hand.</p>
      ) : (
        <>
          {emails.length > EMAIL_FILTER_THRESHOLD && (
            <input
              value={emailFilter}
              onChange={(e) => setEmailFilter(e.target.value)}
              placeholder={`Filter ${emails.length} addresses…`}
              className={`${inputBase} text-xs`}
            />
          )}
          {visibleEmails.length === 0 ? (
            <p className="py-4 text-center text-xs text-neutral-600">No addresses match "{emailFilter}".</p>
          ) : (
            <div className="max-h-[32rem] divide-y divide-neutral-900 overflow-y-auto">
              {visibleEmails.map((e) => (
                <EmailRow
                  key={e}
                  email={e}
                  selected={selected.has(e)}
                  state={checks[e] ?? { status: 'idle' }}
                  onToggle={() => onToggle(e)}
                  onCheck={() => onCheck([e])}
                />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}

function EmailRow({
  email,
  selected,
  state,
  onToggle,
  onCheck,
}: {
  email: string
  selected: boolean
  state: EmailCheckState
  onToggle: () => void
  onCheck: () => void
}) {
  const [expanded, setExpanded] = useState(false)
  const count = state.breaches?.length ?? 0
  const canExpand = state.status === 'done' || state.status === 'error'

  return (
    <div className="py-1.5">
      <div className="flex items-center gap-2">
        <input type="checkbox" checked={selected} onChange={onToggle} className="accent-sky-500" />
        <span
          onClick={() => canExpand && setExpanded((v) => !v)}
          className={`min-w-0 flex-1 truncate font-mono text-xs text-neutral-200 ${canExpand ? 'cursor-pointer' : ''}`}
        >
          {email}
        </span>
        <CopyButton text={email} />
        {state.status === 'idle' && <span className="shrink-0 text-[11px] text-neutral-600">Not checked</span>}
        {state.status === 'running' && (
          <span className="shrink-0 rounded border border-amber-700 bg-amber-950/40 px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-amber-300">
            Checking…
          </span>
        )}
        {state.status === 'error' && (
          <span className="shrink-0 rounded border border-red-700 bg-red-950/60 px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-red-300">
            Error
          </span>
        )}
        {state.status === 'done' && (
          <span
            className={`shrink-0 rounded border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${
              count > 0 ? 'border-red-700 bg-red-950/60 text-red-300' : 'border-emerald-700 bg-emerald-950/60 text-emerald-300'
            }`}
          >
            {count > 0 ? `${count} breach${count === 1 ? '' : 'es'}` : 'Clean'}
          </span>
        )}
        {state.status !== 'running' && (
          <button type="button" onClick={onCheck} className="shrink-0 text-[11px] text-sky-400 hover:text-sky-300">
            {state.status === 'idle' ? 'Check' : 'Recheck'}
          </button>
        )}
        {canExpand && (
          <span onClick={() => setExpanded((v) => !v)} className="shrink-0 cursor-pointer text-xs text-neutral-600">
            {expanded ? '▾' : '▸'}
          </span>
        )}
      </div>
      {expanded && state.status === 'done' && (
        <div className="ml-6 mt-1 border-l border-neutral-900 pl-3">
          {count === 0 ? (
            <p className="py-1 text-xs text-neutral-600">No known breaches found for this address.</p>
          ) : (
            <ul className="divide-y divide-neutral-900">
              {state.breaches!.map((b) => (
                <BreachRow key={b.name} breach={b} />
              ))}
            </ul>
          )}
        </div>
      )}
      {expanded && state.status === 'error' && <p className="ml-6 mt-1 border-l border-neutral-900 py-1 pl-3 text-xs text-red-300">{state.error}</p>}
    </div>
  )
}

function BreachRow({ breach: b }: { breach: Breach }) {
  return (
    <li className="py-2 text-xs">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium text-neutral-100">{b.title}</span>
        {b.breachDate && <span className="text-neutral-500">{b.breachDate}</span>}
        {b.domain && <span className="font-mono text-neutral-600">{b.domain}</span>}
        {!b.isVerified && (
          <span className="rounded border border-neutral-700 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-neutral-500">Unverified</span>
        )}
        {b.isSensitive && (
          <span className="rounded border border-amber-700 bg-amber-950/40 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-amber-300">
            Sensitive
          </span>
        )}
        {b.pwnCount ? <span className="ml-auto shrink-0 text-neutral-600">{b.pwnCount.toLocaleString()} accounts</span> : null}
      </div>
      {b.dataClasses && b.dataClasses.length > 0 && (
        <div className="mt-1 flex flex-wrap items-center gap-1.5">
          <p className="flex flex-wrap gap-1 text-neutral-500">{b.dataClasses.join(', ')}</p>
          <CopyButton text={b.dataClasses.join(', ')} />
        </div>
      )}
    </li>
  )
}

// checkSummary is the live check card's status pill: running while the batch
// is in flight, then how many breaches the addresses turned up once it lands.
function checkSummary(run: TrackedScan<BreachCheckResponse>): BatchResultSummary {
  if (run.status === 'running') return { label: 'Running…', tone: 'neutral', running: true }
  if (run.status === 'error') return { label: 'Error', tone: 'danger' }
  const total = (run.result?.results ?? []).reduce((n, r) => n + (r.breaches?.length ?? 0), 0)
  return total === 0 ? { label: 'Clean', tone: 'clean' } : { label: `${total} breach${total === 1 ? '' : 'es'}`, tone: 'danger' }
}
