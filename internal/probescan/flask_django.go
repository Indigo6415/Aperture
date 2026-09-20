package probescan

import (
	"context"
	"strings"
)

// flaskDjangoChecks ports flask_django.py's CHECKS table.
var flaskDjangoChecks = []pathCheck{
	{"/console", "Werkzeug interactive debugger", containsAny("werkzeug", "interactive console", "debugger")},
	{"/?__debugger__=yes", "Werkzeug debugger probe", containsAny("werkzeug", "traceback")},
	{"/django-admin/", "Django admin panel", containsAll("django", "login")},
	{"/admin/login/", "Django admin login", containsAll("csrfmiddlewaretoken", "django")},
	{"/__debug__/", "Django debug toolbar", containsAny("djdt", "debug toolbar")},
	{"/__debug__/sql_select/", "Django debug toolbar SQL panel", containsAny("sql")},
	{"/this-path-should-not-exist", "Django DEBUG mode enabled", containsAll("django", "traceback", "request information")},
	{"/api/", "Django REST framework browsable API", containsAny("django rest framework", "browsable api")},
	{"/debug", "Flask debug page", containsAll("flask", "debug")},
	{"/config", "Exposed config endpoint", containsAny("secret", "debug", "database")},
	{"/settings", "Exposed settings endpoint", containsAny("secret", "debug")},
	{"/static/admin/", "Django static admin files exposed", containsAny("index of")},
	{"/media/", "Django media directory exposed", containsAny("index of")},
	{"/flower/", "Celery Flower task monitor", containsAny("flower", "celery")},
	{"/flower/dashboard", "Celery Flower dashboard", containsAny("flower", "celery")},
}

// detectFlaskDjango inspects the homepage's headers/body/cookies to decide
// whether the target looks like Flask or Django -- ported from
// flask_django.py's _detect_framework.
func detectFlaskDjango(ctx context.Context, t *Target, c *probeClient) (isFlask, isDjango bool) {
	r, err := c.get(ctx, t.URL, true)
	if err != nil {
		return false, false
	}
	server := strings.ToLower(r.Header.Get("Server"))
	poweredBy := strings.ToLower(r.Header.Get("X-Powered-By"))
	body := r.textLower()

	isFlask = strings.Contains(server, "werkzeug") || strings.Contains(body, "flask") || strings.Contains(body, "jinja")
	isDjango = strings.Contains(body, "django") || strings.Contains(body, "csrfmiddlewaretoken") || strings.Contains(poweredBy, "django")
	if !isDjango {
		for _, ck := range r.Header.Values("Set-Cookie") {
			if strings.HasPrefix(strings.ToLower(ck), "csrftoken=") {
				isDjango = true
				break
			}
		}
	}
	return isFlask, isDjango
}

// flaskDjangoModule ports modules/flask_django.py: skips entirely (returns
// no findings) unless the target looks like Flask or Django, same as the
// original's early-return.
var flaskDjangoModule = moduleDef{
	id:       "flask_django",
	name:     "Flask / Django",
	severity: "high",
	run: func(ctx context.Context, t *Target, c *probeClient) []Finding {
		isFlask, isDjango := detectFlaskDjango(ctx, t, c)
		if !isFlask && !isDjango {
			return nil
		}

		findings := runPathChecks(ctx, c, t.URL, flaskDjangoChecks, true, "at")

		// Werkzeug debugger PIN prompt -- present (even PIN-locked) is
		// itself a critical misconfiguration.
		if r, err := c.get(ctx, t.URL+"/console", true); err == nil && r.StatusCode == 200 && containsAll("pin", "werkzeug")(r) {
			url := t.URL + "/console"
			findings = append(findings, Finding{
				Label:      "Werkzeug debugger PIN prompt exposed at " + url,
				URL:        url,
				Method:     "GET",
				StatusCode: r.StatusCode,
				Detail:     "Response body is the Werkzeug interactive debugger's PIN prompt -- the PIN can potentially be calculated from server/environment info leaked elsewhere",
			})
		}

		// Django DEBUG=True leaks a full traceback on a definitely-missing
		// path instead of a plain 404.
		if r, err := c.get(ctx, t.URL+"/__probe_debug_check__", true); err == nil && r.StatusCode == 404 && containsAny("request information")(r) {
			url := t.URL + "/__probe_debug_check__"
			findings = append(findings, Finding{
				Label:      "Django DEBUG=True detected at " + url,
				URL:        url,
				Method:     "GET",
				StatusCode: r.StatusCode,
				Detail:     "A request to a deliberately nonexistent path returned Django's detailed debug error page (\"request information\") instead of a plain 404 -- this leaks settings, environment variables, and file paths",
			})
		}

		return findings
	},
}
