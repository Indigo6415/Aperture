package probescan

import (
	"context"
	"regexp"
)

// goModLine matches the module directive that opens every go.mod file.
var goModLine = regexp.MustCompile(`(?m)^module\s+\S+`)

// dockerFromLine matches the FROM instruction every Dockerfile must contain.
var dockerFromLine = regexp.MustCompile(`(?m)^FROM\s+\S+`)

// gemfileLockSection matches the GEM section header of a Bundler lockfile.
var gemfileLockSection = regexp.MustCompile(`(?m)^GEM$`)

// validOLE checks the compound-file magic used by Windows Thumbs.db.
func validOLE(r *httpResult) bool {
	return bodyPrefix([]byte{0xD0, 0xCF, 0x11, 0xE0})(r)
}

// validYAMLAny passes when any of the given top-level YAML keys is present.
func validYAMLAny(keys ...string) func(r *httpResult) bool {
	checks := make([]func(r *httpResult) bool, 0, len(keys))
	for _, k := range keys {
		checks = append(checks, validYAMLKey(k))
	}
	return func(r *httpResult) bool {
		for _, chk := range checks {
			if chk(r) {
				return true
			}
		}
		return false
	}
}

// devArtifactsModule ports modules/exposed_dev_artifacts.py: PHP debug
// pages, editor/IDE files, OS artifacts, dependency manifests, and CI/CD
// configs. Structured files are validated by their format; PHP pages are HTML
// by nature and keep the non-strict path, still behind the catch-all gate.
var devArtifactsModule = moduleDef{
	id:       "dev_artifacts",
	name:     "Development artifacts",
	severity: "medium",
	run: func(ctx context.Context, t *Target, c *probeClient) []Finding {
		strong := []pathCheck{
			{"/.vscode/settings.json", "VSCode settings", validJSONAnyKey("editor.tabSize", "editor.formatOnSave", "files.exclude", "files.associations", "python.defaultInterpreterPath")},
			{"/.vscode/launch.json", "VSCode launch config", validJSONAnyKey("version", "configurations")},
			{"/.idea/workspace.xml", "JetBrains workspace", validXMLRoot("project")},
			{"/.DS_Store", "macOS DS_Store file", validDSStore},
			{"/Thumbs.db", "Windows Thumbs.db file", validOLE},
			{"/composer.json", "PHP Composer manifest", validJSONAnyKey("require", "require-dev", "autoload")},
			{"/composer.lock", "PHP Composer lockfile", validJSONAnyKey("packages", "packages-dev")},
			{"/package.json", "Node.js package manifest", validJSONAnyKey("dependencies", "devDependencies", "scripts")},
			{"/package-lock.json", "Node.js lockfile", validJSONAnyKey("lockfileVersion", "packages", "dependencies")},
			{"/yarn.lock", "Yarn lockfile", notHTML(containsCase("# yarn lockfile"))},
			{"/Gemfile", "Ruby Gemfile", validGemfile},
			{"/Gemfile.lock", "Ruby Gemfile lockfile", notHTML(func(r *httpResult) bool { return gemfileLockSection.MatchString(r.Text) })},
			{"/requirements.txt", "Python requirements", validRequirements},
			{"/Pipfile", "Python Pipfile", validINIMatch(`\[packages\]`)},
			{"/Pipfile.lock", "Python Pipfile lockfile", validJSONAnyKey("_meta", "default")},
			{"/go.mod", "Go module file", notHTML(func(r *httpResult) bool { return goModLine.MatchString(r.Text) })},
			{"/pom.xml", "Maven POM file", validXMLRoot("project")},
			{"/.travis.yml", "Travis CI config", validYAMLKey("language")},
			{"/.gitlab-ci.yml", "GitLab CI config", validYAMLAny("stages", "image", "include")},
			{"/docker-compose.yml", "Docker Compose file", validYAMLKey("services")},
			{"/docker-compose.yaml", "Docker Compose file", validYAMLKey("services")},
			{"/Dockerfile", "Dockerfile", notHTML(func(r *httpResult) bool { return dockerFromLine.MatchString(r.Text) })},
			{"/.editorconfig", "Editor config", validINIMatch(`\[[^\]]+\]`)},
			{"/.eslintrc", "ESLint config", validJSONAnyKey("rules", "extends", "env", "parserOptions")},
			{"/.eslintrc.json", "ESLint config", validJSONAnyKey("rules", "extends", "env", "parserOptions")},
			{"/tsconfig.json", "TypeScript config", validJSONAnyKey("compilerOptions")},
		}
		// Plain-text or weakly-shaped files: reported as "likely".
		weak := []pathCheck{
			{"/.idea/.name", "JetBrains project name", validPlainText},
			{"/build.gradle", "Gradle build file", notHTML(containsCase("dependencies"))},
			{"/Jenkinsfile", "Jenkinsfile", notHTML(containsCase("pipeline"))},
			{"/webpack.config.js", "Webpack config", notHTML(containsCase("module.exports"))},
			{"/vite.config.js", "Vite config", notHTML(containsCase("export default"))},
			{"/vite.config.ts", "Vite config", notHTML(containsCase("export default"))},
		}
		// PHP pages and directory listings are HTML by design, so they keep
		// the non-strict path; the catch-all gate still applies to them.
		pages := []pathCheck{
			{"/phpinfo.php", "PHP info page", containsAny("phpinfo()", "php version")},
			{"/info.php", "PHP info page", containsAny("phpinfo()")},
			{"/test.php", "PHP test page", nonEmptyBody},
			{"/debug.php", "PHP debug page", nonEmptyBody},
			{"/.github/workflows", "GitHub Actions workflows", containsAny("index of")},
		}

		findings := runFileChecks(ctx, c, t.URL, strong, ConfidenceConfirmed)
		findings = append(findings, runFileChecks(ctx, c, t.URL, weak, ConfidenceLikely)...)
		return append(findings, runPathChecks(ctx, c, t.URL, pages, false, "exposed at")...)
	},
}
