// scannerNavData.ts is the scanner sidebar's shape -- which tabs exist, what
// each is called/iconed, and how they're grouped -- factored out of
// CaseView.tsx so it can be shared between CaseView (which owns the actual
// tab state and renders each tab's content) and ScannerNav.tsx (which only
// renders the sidebar itself, in whichever of the four saved layouts is
// active -- see scannerNavStyle.ts). Neither file owns this data; both just
// consume it.
import type { ReactElement, SVGProps } from 'react'
import {
  IconActivity,
  IconBraces,
  IconBug,
  IconCode,
  IconCookie,
  IconCrosshair,
  IconFolder,
  IconFolderSearch,
  IconGlobe,
  IconKey,
  IconLightning,
  IconLock,
  IconMailQuestion,
  IconRadar,
  IconRepeat,
  IconRouteTree,
  IconScan,
  IconSend,
  IconServer,
  IconShieldKey,
  IconSitemap,
  IconTarget,
  IconGitBranch,
  IconUnlock,
  IconWarning,
  IconWrench,
} from './components/icons'

export type Tab =
  | 'targets'
  | 'credentials'
  | 'cookieVault'
  | 'identify'
  | 'feroxbuster'
  | 'ffuf-subdomain'
  | 'ffuf-vhost'
  | 'ffuf-custom'
  | 'subfinder'
  | 'katana'
  | 'nuclei'
  | 'jwtscan'
  | 'probe'
  | 'domainscan'
  | 'secrets'
  | 'breach'
  | 'bypass403'
  | 'gitdump'
  | 'pwreset'
  | 'graphqlenum'
  | 'apienum'
  | 'corsscan'
  | 'openredirect'
  | 'ssrf'
  | 'csrf'
  | 'sstiscan'
  | 'pathtraversal'
  | 'idor'
  | 'xxe'
  | 'xss'
  | 'tester'
  | 'collaborator'

export type IconType = (props: SVGProps<SVGSVGElement>) => ReactElement

export const TAB_META: Record<Tab, { label: string; icon: IconType }> = {
  targets: { label: 'Targets', icon: IconTarget },
  credentials: { label: 'Credentials', icon: IconKey },
  cookieVault: { label: 'Cookie Vault', icon: IconCookie },
  identify: { label: 'Identify', icon: IconRadar },
  feroxbuster: { label: 'Directory', icon: IconFolderSearch },
  'ffuf-subdomain': { label: 'Subdomain', icon: IconGlobe },
  'ffuf-vhost': { label: 'VHost', icon: IconServer },
  'ffuf-custom': { label: 'FFuF', icon: IconLightning },
  subfinder: { label: 'Subfinder', icon: IconGlobe },
  katana: { label: 'Katana Crawler', icon: IconFolder },
  nuclei: { label: 'Nuclei', icon: IconWarning },
  jwtscan: { label: 'JWT', icon: IconShieldKey },
  probe: { label: 'Probe', icon: IconCrosshair },
  domainscan: { label: 'Domain Scan', icon: IconBug },
  secrets: { label: 'Secrets', icon: IconLock },
  breach: { label: 'Breach Check', icon: IconKey },
  bypass403: { label: '403 Bypass', icon: IconUnlock },
  gitdump: { label: 'Git Dump', icon: IconGitBranch },
  pwreset: { label: 'Password Reset', icon: IconMailQuestion },
  graphqlenum: { label: 'GraphQL Enumeration', icon: IconBraces },
  apienum: { label: 'API Enumerator', icon: IconRouteTree },
  corsscan: { label: 'CORS', icon: IconGlobe },
  openredirect: { label: 'Open Redirect', icon: IconRepeat },
  ssrf: { label: 'SSRF', icon: IconServer },
  csrf: { label: 'CSRF Sweep', icon: IconSitemap },
  sstiscan: { label: 'SSTI', icon: IconBraces },
  pathtraversal: { label: 'Path Traversal', icon: IconFolder },
  idor: { label: 'IDOR', icon: IconUnlock },
  xxe: { label: 'XXE', icon: IconCode },
  xss: { label: 'XSS', icon: IconCode },
  tester: { label: 'Tester', icon: IconSend },
  collaborator: { label: 'Collaborator', icon: IconActivity },
}

// NAV_GROUPS is the sidebar's shape. PINNED_TABS sit above every group with
// no group around them: the case-management tabs, plus Identify, since
// that's the first thing a case is worked with and shouldn't be hidden
// inside a collapsible section. Below them, each group is independently
// collapsible and ordered the way a case is actually worked: recon to
// discover the attack surface, vulnerability scanners against that surface,
// then the standalone utilities for targeted manual work.
export type NavGroup = { id: string; label: string; icon: IconType; tabs: Tab[] }

export const PINNED_TABS: Tab[] = ['targets', 'identify', 'credentials', 'cookieVault']

export const NAV_GROUPS: NavGroup[] = [
  {
    id: 'recon',
    label: 'Recon',
    icon: IconRadar,
    tabs: ['feroxbuster', 'ffuf-subdomain', 'ffuf-vhost', 'ffuf-custom', 'subfinder', 'katana', 'nuclei'],
  },
  {
    id: 'vulnerabilities',
    label: 'Vulnerabilities',
    icon: IconScan,
    tabs: [
      'jwtscan',
      'probe',
      'domainscan',
      'secrets',
      'breach',
      'bypass403',
      'gitdump',
      'pwreset',
      'graphqlenum',
      'apienum',
      'corsscan',
      'openredirect',
      'ssrf',
      'csrf',
      'sstiscan',
      'pathtraversal',
      'idor',
      'xxe',
      'xss',
    ],
  },
  {
    id: 'utilities',
    label: 'Utilities',
    icon: IconWrench,
    tabs: ['tester', 'collaborator'],
  },
]
