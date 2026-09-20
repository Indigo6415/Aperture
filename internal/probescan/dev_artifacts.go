package probescan

import "context"

// devArtifactsModule ports modules/exposed_dev_artifacts.py: PHP debug
// pages, editor/IDE files, OS artifacts, dependency manifests, and CI/CD
// configs.
var devArtifactsModule = moduleDef{
	id:       "dev_artifacts",
	name:     "Development artifacts",
	severity: "medium",
	run: func(ctx context.Context, t *Target, c *probeClient) []Finding {
		checks := []pathCheck{
			{"/phpinfo.php", "PHP info page", containsAny("phpinfo()", "php version")},
			{"/info.php", "PHP info page", containsAny("phpinfo()")},
			{"/test.php", "PHP test page", nonEmptyBody},
			{"/debug.php", "PHP debug page", nonEmptyBody},
			{"/.vscode/settings.json", "VSCode settings", containsCase("{")},
			{"/.vscode/launch.json", "VSCode launch config", containsCase("{")},
			{"/.idea/workspace.xml", "JetBrains workspace", containsAny("<project")},
			{"/.idea/.name", "JetBrains project name", nonEmptyBody},
			{"/.DS_Store", "macOS DS_Store file", bodyPrefix([]byte{0, 0, 0, 1})},
			{"/Thumbs.db", "Windows Thumbs.db file", func(r *httpResult) bool { return len(r.Body) > 0 }},
			{"/composer.json", "PHP Composer manifest", containsCase("require")},
			{"/composer.lock", "PHP Composer lockfile", containsCase("packages")},
			{"/package.json", "Node.js package manifest", containsCase("dependencies", "name")},
			{"/package-lock.json", "Node.js lockfile", containsCase("dependencies")},
			{"/yarn.lock", "Yarn lockfile", containsAny("# yarn lockfile")},
			{"/Gemfile", "Ruby Gemfile", containsCase("gem ")},
			{"/Gemfile.lock", "Ruby Gemfile lockfile", containsCase("GEM")},
			{"/requirements.txt", "Python requirements", nonEmptyBody},
			{"/Pipfile", "Python Pipfile", containsCase("[packages]")},
			{"/Pipfile.lock", "Python Pipfile lockfile", containsCase("default")},
			{"/go.mod", "Go module file", containsCase("module ")},
			{"/pom.xml", "Maven POM file", containsAny("<project")},
			{"/build.gradle", "Gradle build file", containsCase("dependencies")},
			{"/.travis.yml", "Travis CI config", containsCase("language:")},
			{"/.gitlab-ci.yml", "GitLab CI config", containsCase("stages:", "script:")},
			{"/.github/workflows", "GitHub Actions workflows", containsAny("index of")},
			{"/Jenkinsfile", "Jenkinsfile", containsAny("pipeline")},
			{"/docker-compose.yml", "Docker Compose file", containsCase("services:")},
			{"/docker-compose.yaml", "Docker Compose file", containsCase("services:")},
			{"/Dockerfile", "Dockerfile", containsCase("FROM ")},
			{"/webpack.config.js", "Webpack config", containsCase("module.exports")},
			{"/vite.config.js", "Vite config", containsCase("export default")},
			{"/vite.config.ts", "Vite config", containsCase("export default")},
			{"/.editorconfig", "Editor config", containsCase("[")},
			{"/.eslintrc", "ESLint config", containsCase("{")},
			{"/.eslintrc.json", "ESLint config", containsCase("{")},
			{"/tsconfig.json", "TypeScript config", containsCase("compilerOptions")},
		}
		return runPathChecks(ctx, c, t.URL, checks, false, "exposed at")
	},
}
