package probescan

import "context"

// sensitiveFilesModule ports modules/exposed_sensitive_files.py: env files,
// config backups, dependency manifests, database dumps, and private keys.
var sensitiveFilesModule = moduleDef{
	id:       "sensitive_files",
	name:     "Sensitive files",
	severity: "high",
	run: func(ctx context.Context, t *Target, c *probeClient) []Finding {
		checks := []pathCheck{
			{"/.env", "Environment file", containsCase("=")},
			{"/.env.backup", "Environment backup file", containsCase("=")},
			{"/.env.local", "Local environment file", containsCase("=")},
			{"/.env.production", "Production environment file", containsCase("=")},
			{"/.env.staging", "Staging environment file", containsCase("=")},
			{"/web.config", "IIS web config", containsAny("<configuration>")},
			{"/.htpasswd", "Apache password file", containsCase(":")},
			{"/wp-config.php.bak", "WordPress config backup", containsCase("DB_")},
			{"/config.php.bak", "PHP config backup", nonEmptyBody},
			{"/database.yml", "Rails database config", containsCase("adapter:")},
			{"/config/database.yml", "Rails database config", containsCase("adapter:")},
			{"/composer.json", "PHP composer manifest", containsCase("require")},
			{"/composer.lock", "PHP composer lockfile", containsCase("packages")},
			{"/package.json", "Node.js package manifest", containsCase("dependencies")},
			{"/Gemfile", "Ruby Gemfile", containsCase("gem ")},
			{"/requirements.txt", "Python requirements file", nonEmptyBody},
			{"/backup.sql", "SQL database dump", containsCase("INSERT", "CREATE")},
			{"/dump.sql", "SQL database dump", containsCase("INSERT", "CREATE")},
			{"/db.sql", "SQL database dump", containsCase("INSERT", "CREATE")},
			{"/backup.zip", "Backup archive", bodyPrefix([]byte("PK\x03\x04"))},
			{"/backup.tar.gz", "Backup archive", bodyPrefix([]byte("\x1f\x8b"))},
			{"/.ssh/id_rsa", "Private SSH key", containsCase("PRIVATE KEY")},
			{"/.ssh/id_ed25519", "Private SSH key", containsCase("PRIVATE KEY")},
			{"/id_rsa", "Private SSH key", containsCase("PRIVATE KEY")},
			{"/.aws/credentials", "AWS credentials file", containsAny("aws_access_key")},
			{"/.DS_Store", "macOS DS_Store file", bodyPrefix([]byte{0, 0, 0, 1})},
			{"/.vscode/settings.json", "VSCode settings", containsCase("{")},
			{"/.idea/workspace.xml", "JetBrains workspace file", containsAny("<project")},
		}
		return runPathChecks(ctx, c, t.URL, checks, false, "exposed at")
	},
}
