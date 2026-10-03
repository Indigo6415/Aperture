import type { TargetListKind } from './types'

// Shared between every target-list UI (CaseView's Targets tab, SaveToListModal)
// so the set of kinds and how they're labeled/prompted stays in one place.
export const TARGET_LIST_KINDS: TargetListKind[] = ['domain', 'directory', 'file', 'url', 'other']

export const TARGET_LIST_KIND_LABELS: Record<TargetListKind, string> = {
  domain: 'Domains',
  directory: 'Directories',
  file: 'Files',
  url: 'URLs',
  other: 'Other',
}

export const TARGET_LIST_KIND_PLACEHOLDERS: Record<TargetListKind, string> = {
  domain: 'example.com, sub.example.com, 10.0.0.1 …',
  directory: '/var/www/html, ./uploads, C:\\inetpub\\wwwroot …',
  file: '/etc/passwd, backup.zip, config.php …',
  url: 'https://example.com/login, https://example.com/account/signin …',
  other: 'Add a target…',
}
