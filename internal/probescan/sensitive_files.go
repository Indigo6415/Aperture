package probescan

import (
	"bytes"
	"context"
	"strings"
)

// sensitiveFilesModule ports modules/exposed_sensitive_files.py and extends it
// with framework and CMS configuration, credential stores, log files, and
// archives. Dependency manifests and IDE files live in devArtifactsModule, and
// each path appears in exactly one module, so one file is never reported
// twice. Every check here must parse the file it claims to find.
var sensitiveFilesModule = moduleDef{
	id:       "sensitive_files",
	name:     "Sensitive files",
	severity: "high",
	run: func(ctx context.Context, t *Target, c *probeClient) []Finding {
		strong := []pathCheck{
			// --- Environment files ---
			{"/.env", "Environment file", validDotEnv},
			{"/.env.backup", "Environment backup file", validDotEnv},
			{"/.env.bak", "Environment backup file", validDotEnv},
			{"/.env.local", "Local environment file", validDotEnv},
			{"/.env.development", "Development environment file", validDotEnv},
			{"/.env.dev", "Development environment file", validDotEnv},
			{"/.env.production", "Production environment file", validDotEnv},
			{"/.env.prod", "Production environment file", validDotEnv},
			{"/.env.staging", "Staging environment file", validDotEnv},
			{"/.env.test", "Test environment file", validDotEnv},
			{"/.env.swp", "Environment file (Vim swap copy)", validVimSwap},

			// --- Web server and access control ---
			{"/web.config", "IIS web config", validXMLRoot("configuration")},
			{"/.htpasswd", "Apache password file", validHtpasswd},
			{"/app/etc/local.xml", "Magento local config", validXMLRoot("config")},

			// --- PHP configuration served as source ---
			{"/wp-config.php", "WordPress config", phpSourceWith("DB_PASSWORD")},
			{"/wp-config.php.bak", "WordPress config backup", phpSourceWith("DB_PASSWORD")},
			{"/wp-config.php~", "WordPress config backup", phpSourceWith("DB_PASSWORD")},
			{"/wp-config.php.old", "WordPress config backup", phpSourceWith("DB_PASSWORD")},
			{"/wp-config.php.save", "WordPress config backup", phpSourceWith("DB_PASSWORD")},
			{"/wp-config.bak", "WordPress config backup", phpSourceWith("DB_PASSWORD")},
			{"/config.php.bak", "PHP config backup", validPHPSource},
			{"/config.php~", "PHP config backup", validPHPSource},
			{"/configuration.php", "Joomla configuration", phpSourceWith("JConfig")},
			{"/configuration.php.bak", "Joomla configuration backup", phpSourceWith("JConfig")},
			{"/sites/default/settings.php", "Drupal settings", phpSourceWith("$databases")},
			{"/index.php.bak", "PHP source backup", validPHPSource},
			{"/index.php~", "PHP source backup", validPHPSource},
			{"/index.php.old", "PHP source backup", validPHPSource},
			{"/index.php.orig", "PHP source backup", validPHPSource},

			// --- Framework configuration ---
			{"/settings.py", "Django settings module", validDjangoSettings},
			{"/local_settings.py", "Django local settings", validDjangoSettings},
			{"/database.yml", "Rails database config", validYAMLKey("adapter")},
			{"/config/database.yml", "Rails database config", validYAMLKey("adapter")},
			{"/config/secrets.yml", "Rails secrets file", validRegexp(railsSecretsYAML)},
			{"/config/master.key", "Rails master key", validRailsMasterKey},
			{"/appsettings.json", "ASP.NET app settings", validJSONKeys("ConnectionStrings", "AllowedHosts")},
			{"/appsettings.Development.json", "ASP.NET development settings", validJSONKeys("ConnectionStrings", "AllowedHosts")},
			{"/storage/logs/laravel.log", "Laravel application log", validRegexp(laravelLogLine)},

			// --- Infrastructure state and credential stores ---
			{"/terraform.tfstate", "Terraform state file", validJSONKeys("terraform_version", "resources")},
			{"/.aws/credentials", "AWS credentials file", validAWSCredentials},
			{"/.s3cfg", "S3 client credentials", validS3cfg},
			{"/.git-credentials", "Git credentials store", validRegexp(gitCredentialsLine)},
			{"/.netrc", "netrc credentials file", validNetrc},
			{"/.pgpass", "PostgreSQL password file", validRegexp(pgpassLine)},
			{"/.my.cnf", "MySQL client config", validMySQLClientCnf},
			{"/.npmrc", "npm registry credentials", validRegexp(npmrcAuthLine)},
			{"/.dockercfg", "Docker registry credentials", validJSONKeys("auths")},
			{"/.docker/config.json", "Docker registry credentials", validJSONKeys("auths")},

			// --- Private keys ---
			{"/.ssh/id_rsa", "Private SSH key", validPEMPrivate},
			{"/.ssh/id_ed25519", "Private SSH key", validPEMPrivate},
			{"/.ssh/id_ecdsa", "Private SSH key", validPEMPrivate},
			{"/.ssh/id_dsa", "Private SSH key", validPEMPrivate},
			{"/id_rsa", "Private SSH key", validPEMPrivate},
			{"/id_dsa", "Private SSH key", validPEMPrivate},
			{"/server.key", "Private TLS key", validPEMPrivate},
			{"/privkey.pem", "Private TLS key", validPEMPrivate},
			{"/private.key", "Private key", validPEMPrivate},

			// --- Finder metadata that leaks directory contents ---
			{"/.DS_Store", "macOS DS_Store file", validDSStore},

			// --- Database dumps and database files ---
			{"/backup.sql", "SQL database dump", validSQLDump},
			{"/dump.sql", "SQL database dump", validSQLDump},
			{"/db.sql", "SQL database dump", validSQLDump},
			{"/db_backup.sql", "SQL database dump", validSQLDump},
			{"/database.sql", "SQL database dump", validSQLDump},
			{"/data.sql", "SQL database dump", validSQLDump},
			{"/mysql.sql", "SQL database dump", validSQLDump},
			{"/site.sql", "SQL database dump", validSQLDump},
			{"/db.sqlite3", "SQLite database", validSQLiteDB},
			{"/database.sqlite", "SQLite database", validSQLiteDB},

			// --- Archives of the site or its backups ---
			{"/backup.zip", "Backup archive", validZip},
			{"/site.zip", "Site archive", validZip},
			{"/www.zip", "Site archive", validZip},
			{"/html.zip", "Site archive", validZip},
			{"/app.zip", "Application archive", validZip},
			{"/db.zip", "Database archive", validZip},
			{"/backup.tar.gz", "Backup archive", validTarGz},
			{"/backup.tgz", "Backup archive", validTarGz},
			{"/www.tar.gz", "Site archive", validTarGz},
			{"/site.tar.gz", "Site archive", validTarGz},
			{"/backup.tar", "Backup archive", validTar},
			{"/backup.7z", "Backup archive", validSevenZip},

			// --- Logs that carry request or error detail ---
			{"/wp-content/debug.log", "WordPress debug log", validRegexp(phpErrorLogLine)},
			{"/error_log", "PHP error log", validRegexp(phpErrorLogLine)},
		}

		// Structure-only matches: the file is the right kind, but its secrets
		// (if any) are not verified, so these are reported as "likely".
		weak := []pathCheck{
			{"/.env.example", "Environment template file", validDotEnv},
			{"/config.json", "JSON configuration file", validJSONKeys("database", "db", "password", "secret", "api_key", "apiKey", "secretKey")},
			{"/.htaccess", "Apache .htaccess file", validRegexp(htaccessDirective)},
		}

		findings := runFileChecks(ctx, c, t.URL, strong, ConfidenceConfirmed)
		return append(findings, runFileChecks(ctx, c, t.URL, weak, ConfidenceLikely)...)
	},
}

// validAWSCredentials requires an INI file with at least one profile header
// and an access key assignment, the shape of ~/.aws/credentials.
func validAWSCredentials(r *httpResult) bool {
	return validINIMatch(`\[[^\]]+\]`)(r) && strings.Contains(r.Text, "aws_access_key_id")
}

// validS3cfg requires the s3cmd config layout: a [default] section with an
// access_key entry.
func validS3cfg(r *httpResult) bool {
	return validINIMatch(`\[default\]`)(r) && strings.Contains(r.Text, "access_key")
}

// validNetrc requires a .netrc entry that names a machine and carries a
// password, since a netrc without a password is not a credential.
func validNetrc(r *httpResult) bool {
	return validRegexp(netrcMachine)(r) && strings.Contains(strings.ToLower(r.Text), "password")
}

// validMySQLClientCnf requires the [client] section of a MySQL option file that
// includes a password line.
func validMySQLClientCnf(r *httpResult) bool {
	return validINIMatch(`\[client\]`)(r) && strings.Contains(r.Text, "password")
}

// validVimSwap checks the magic of a Vim swap file. A swap file is a copy of a
// file being edited, so it leaks the same content as the original.
func validVimSwap(r *httpResult) bool {
	return bodyPrefix([]byte("b0VIM "))(r)
}

// validTar checks the ustar magic at offset 257 of an uncompressed tar archive.
func validTar(r *httpResult) bool {
	return len(r.Body) >= 262 && bytes.Equal(r.Body[257:262], []byte("ustar"))
}

// validSevenZip checks the signature that opens every 7z archive.
func validSevenZip(r *httpResult) bool {
	return bodyPrefix([]byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C})(r)
}
