package probescan

import (
	"context"
	"strings"
)

// sensitiveFilesModule ports modules/exposed_sensitive_files.py: environment
// files, config backups, database dumps, private keys, and credential files.
// Dependency manifests live in devArtifactsModule so the same file is never
// reported twice. Every check here must parse the file it claims to find.
var sensitiveFilesModule = moduleDef{
	id:       "sensitive_files",
	name:     "Sensitive files",
	severity: "high",
	run: func(ctx context.Context, t *Target, c *probeClient) []Finding {
		strong := []pathCheck{
			{"/.env", "Environment file", validDotEnv},
			{"/.env.backup", "Environment backup file", validDotEnv},
			{"/.env.local", "Local environment file", validDotEnv},
			{"/.env.production", "Production environment file", validDotEnv},
			{"/.env.staging", "Staging environment file", validDotEnv},
			{"/web.config", "IIS web config", validXMLRoot("configuration")},
			{"/.htpasswd", "Apache password file", validHtpasswd},
			{"/wp-config.php.bak", "WordPress config backup", func(r *httpResult) bool {
				return validPHPSource(r) && strings.Contains(r.Text, "DB_PASSWORD")
			}},
			{"/config.php.bak", "PHP config backup", validPHPSource},
			{"/database.yml", "Rails database config", validYAMLKey("adapter")},
			{"/config/database.yml", "Rails database config", validYAMLKey("adapter")},
			{"/backup.sql", "SQL database dump", validSQLDump},
			{"/dump.sql", "SQL database dump", validSQLDump},
			{"/db.sql", "SQL database dump", validSQLDump},
			{"/backup.zip", "Backup archive", validZip},
			{"/backup.tar.gz", "Backup archive", validTarGz},
			{"/.ssh/id_rsa", "Private SSH key", validPEMPrivate},
			{"/.ssh/id_ed25519", "Private SSH key", validPEMPrivate},
			{"/id_rsa", "Private SSH key", validPEMPrivate},
			{"/.aws/credentials", "AWS credentials file", validAWSCredentials},
			{"/.DS_Store", "macOS DS_Store file", validDSStore},
		}
		return runFileChecks(ctx, c, t.URL, strong, ConfidenceConfirmed)
	},
}

// validAWSCredentials requires an INI file with at least one profile header
// and an access key assignment, the shape of ~/.aws/credentials.
func validAWSCredentials(r *httpResult) bool {
	return validINIMatch(`\[[^\]]+\]`)(r) && strings.Contains(r.Text, "aws_access_key_id")
}
