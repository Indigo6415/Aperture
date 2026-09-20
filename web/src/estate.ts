import type { TechDetection } from './types'

export type ClusterId = string

// EstateHost is the minimal per-host shape clusterOf/riskOf need --
// useEstateModel builds these from useScanGraph's node/edge graph, keeping
// this module itself free of any knowledge of how that graph is shaped.
// network is absent for a host with no completed 'asn' check yet (see
// internal/recon/asn.go) -- clusterOfNetwork falls back the same way
// clusterOf does for a host with no technology fingerprint.
export interface EstateHost {
  hostname: string
  technologies: TechDetection[]
  exposedFiles: number
  network?: { asn: string; org: string }
}

// ClusterMode picks which dimension the Estate Hierarchy view groups hosts
// by -- 'stack' (clusterOf, the default: shared technology fingerprint) or
// 'network' (clusterOfNetwork: shared hosting ASN/organization, surfacing
// third-party infrastructure a tech-stack grouping can't show).
export type ClusterMode = 'stack' | 'network'

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
  return prefixClusterOf(host)
}

// clusterOfNetwork groups hosts by hosting network: the same ASN almost
// always means the same cloud account/hosting provider, which is often the
// more useful lens than shared tech stack for spotting third-party
// infrastructure (a CDN, a SaaS vendor, a forgotten cloud account) spread
// across a large subdomain estate. Falls back to clusterOf's own
// hostname-prefix grouping for a host with no ASN resolved yet.
export function clusterOfNetwork(host: EstateHost): ClusterId {
  if (host.network?.asn) return `net:${host.network.asn}:${host.network.org}`
  return prefixClusterOf(host)
}

function prefixClusterOf(host: EstateHost): ClusterId {
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
