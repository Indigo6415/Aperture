# Suggested Features

Ideas for extending Aperture, grouped into extensions of existing features and
entirely new ones. Based on a review of the codebase as of 2026-09-20 — a
follow-up pass after the 2026-09-18 round (probescan wiring, repeater, secret
scanner, credential vault, job templates/history, and activity timeline from
that round are now all built, so this list intentionally covers new ground).

## Extensions to existing features

1. **Persist Probe / JWT / Secret Scanner results into the case model.**
   Right now all three are stateless — `riskSummary.ts` explicitly notes Probe/
   JWT/Secret results "aren't persisted to a case", and `report.Build()` only
   pulls in `Checks` and job `Findings`, nothing from these three. Give them
   case-scoped storage (like `case_checks`) so a Probe/Secret/JWT run shows up
   in the Activity Timeline, rolls into the Risk Panel's severity tiles, and
   lands in exported reports instead of vanishing when the tab closes.
   **[implemented 2026-09-20]**

2. **Extend the Credential Vault to ffuf/feroxbuster job launches.** Saved
   credentials already flow into Probe, Repeater, and probescan
   (`handlers_probe.go`, `handlers_repeater.go`, `probescan/client.go`) — but
   the main job launcher for bulk ffuf/feroxbuster runs has no credential
   picker, even though `FFufConfig.Headers` already supports arbitrary
   headers. Authenticated directory-busting currently means retyping headers
   by hand every time. **[implemented 2026-09-20]**

3. **Cross-case global search.** `CaseList.tsx` only filters case names/status
   within the list itself — there's no way to search subdomains, secrets, or
   findings across the whole workspace. With cases piling up, "which case had
   that exposed `.git` on a `*.acme.com` host" currently means opening cases
   one by one.

## New features

4. **Case scope rules.** There's no scope concept anywhere in the codebase
   today. Add in-scope/out-of-scope domain and CIDR patterns per case, and
   flag (not silently block, to stay consistent with the "nothing runs
   automatically" philosophy) any crt.sh/DNSDumpster discovery or
   target-promotion that falls outside it — the single most common way
   passive subdomain enum drags an out-of-scope host into an engagement.

5. **Engagement journal / analyst notes.** The Activity Timeline
   (`handlers_activity.go`) is purely an auto-generated system log, and
   target `notes` are per-target only. Add free-form, timestamped Markdown
   notes at the case level where a finding, screenshot, or CVE can be pinned
   — this becomes the narrative that turns `report.Build()`'s raw data dump
   into an actual engagement writeup.

6. **Repeater request history.** Every Repeater send today is genuinely
   one-off — nothing is saved (`handlers_repeater.go`/`Repeater.tsx` have no
   history state at all). Persist sent requests/responses per case so a
   manual test run an hour ago can be revisited, tagged, replayed, or diffed.
   **[implemented 2026-09-20]**

7. **KEV/EPSS enrichment on CVE findings.** `internal/cve` does live NVD
   lookups only, surfacing raw CVSS severity. Layer in CISA's KEV (Known
   Exploited Vulnerabilities) feed and FIRST.org's EPSS exploit-probability
   score so the Risk Panel can distinguish "high CVSS but theoretical" from
   "actually being exploited right now" — same live-lookup pattern
   `internal/cve` already uses. **[implemented 2026-09-20]**

8. **Passive Shodan/Censys lookup as a new Identify check.** `internal/recon`
   is entirely passive/stdlib (DNS, TLS, HTTP, WHOIS, crt.sh, DNSDumpster) by
   design. A Shodan/Censys banner+port lookup is just as passive (no packets
   sent to the target) and would slot in as another Identify check, gated by
   an API key using the exact `handleSetDNSDumpsterKey`/`handleSetNVDKey`
   settings pattern that already exists.

9. **Case export/import as a portable bundle.** Aperture is explicitly a
   single-operator local tool with no server/team story. A single-file
   export (case + targets + findings + screenshots + wordlist references)
   that re-imports into another Aperture instance would allow handing off or
   archiving a completed engagement without shipping the whole SQLite DB.

10. **ASN/hosting-org clustering in the Estate Hierarchy view.** The
    Hierarchy view already clusters hosts by shared tech stack
    (`useEstateModel.ts`), but WHOIS/RDAP data is already fetched per target
    (`internal/recon/whois.go`) and unused for grouping. Add it as an
    alternate clustering lens — grouping by hosting provider/ASN instead of
    software stack surfaces shared third-party infrastructure that a
    CMS-based cluster view can't show. **[implemented 2026-09-20]**
</content>
