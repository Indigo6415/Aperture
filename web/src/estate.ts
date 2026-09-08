import type { TechDetection } from './types'

export type ClusterId = string

// EstateHost is the minimal per-host shape clusterOf/riskOf need --
// useEstateModel builds these from useScanGraph's node/edge graph, keeping
// this module itself free of any knowledge of how that graph is shaped.
export interface EstateHost {
  hostname: string
  technologies: TechDetection[]
  exposedFiles: number
}

// clusterOf groups hosts that look like the same application: an identical
// fingerprint signature (sorted, de-duplicated technology names) first,
// since two hosts running the same stack are almost always the same app
// behind a load-balancer or a staging/prod pair. Hosts with no fingerprint
// yet -- mail infra like mx1/smtp/smtp2, which never serve HTTP so never get
// a technologies check -- fall back to their hostname's leading alphabetic
// run (stripping trailing digits), so mx1/mx2 still land in one cluster
// together instead of each getting a singleton.
export function clusterOf(host: EstateHost): ClusterId {
  const signature = [...new Set(host.technologies.map((t) => t.name))].sort().join('|')
  if (signature) return `sig:${signature}`
  const label = host.hostname.split('.')[0] ?? host.hostname
  const prefix = label.replace(/[0-9]+$/, '') || label
  return `prefix:${prefix}`
}

// riskOf is the sort key for hosts and the badge total for clusters --
// weighted so one critical CVE outweighs several mediums, and an exposed
// file (a backup, a .env, a database dump) counts for more than a single
// CVE since it's already-realized exposure, not just a possibility.
export function riskOf(host: EstateHost): number {
  let critical = 0
  let high = 0
  let medium = 0
  for (const tech of host.technologies) {
    for (const cve of tech.cves ?? []) {
      switch (cve.severity.toLowerCase()) {
        case 'critical':
          critical++
          break
        case 'high':
          high++
          break
        case 'medium':
          medium++
          break
      }
    }
  }
  return critical * 12 + high * 6 + medium * 2 + host.exposedFiles * 5
}
