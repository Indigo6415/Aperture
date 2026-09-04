// Extensions worth a second look on any content-discovery/vhost result --
// backups, raw configs, credentials, and archives that regularly leak
// secrets or source when left reachable on a web server.
export const DANGEROUS_EXTENSIONS = new Set([
  'sql', 'db', 'db2', 'sqlite', 'sqlite3', 'mdb', 'accdb', 'bak', 'bkp', 'backup', 'old', 'orig', 'save', 'swp', 'swo', 'tmp',
  'conf', 'config', 'cfg', 'ini', 'env', 'yml', 'yaml', 'toml',
  'key', 'pem', 'p12', 'pfx', 'crt', 'cer', 'der', 'csr', 'jks', 'keystore', 'ppk', 'ovpn', 'asc', 'gpg', 'pgp',
  'log', 'htpasswd', 'htaccess', 'npmrc', 'netrc',
  'zip', 'tar', 'gz', 'tgz', 'rar', '7z', 'bz2',
  'git', 'svn', 'dump', 'bson', 'kdbx',
])

export function isDangerousExtension(ext: string | undefined): boolean {
  return ext !== undefined && DANGEROUS_EXTENSIONS.has(ext)
}
