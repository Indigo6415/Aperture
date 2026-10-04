package csrf

import (
	"net/url"
	"testing"
)

// pageFor parses the page URL used by every discovery test below.
func pageFor(t *testing.T) *url.URL {
	t.Helper()
	u, err := url.Parse("http://site.test/page")
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// methodsOf lists the method of every discovered submission, in order.
func methodsOf(forms []discoveredForm) []string {
	var out []string
	for _, f := range forms {
		out = append(out, f.Method+" "+f.Action)
	}
	return out
}

// TestExtractFormsDeclaredMethod checks that only a POST form counts as state
// changing, and that data-method is never read as the form's own method. A
// method like "put" on a form is not a real browser verb, so it submits as GET.
func TestExtractFormsDeclaredMethod(t *testing.T) {
	cases := []struct {
		name, html string
		want       []string
	}{
		{"post form", `<form method="POST" action="/a"></form>`, []string{"POST http://site.test/a"}},
		{"data-method is not the method", `<form data-method="delete" method="get" action="/a"></form>`, nil},
		{"method=put is GET to a browser", `<form method="put" action="/a"></form>`, nil},
		{"no method is GET", `<form action="/a"></form>`, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := methodsOf(extractForms(c.html, pageFor(t)))
			if !equalStrings(got, c.want) {
				t.Errorf("extractForms = %v, want %v", got, c.want)
			}
		})
	}
}

// TestExtractFormsMethodOverride checks the _method override is honored only on
// a POST, and whatever the attribute order of its name and value.
func TestExtractFormsMethodOverride(t *testing.T) {
	cases := []struct {
		name, html string
		want       []string
	}{
		{"override on POST, name first", `<form method="post" action="/a"><input type="hidden" name="_method" value="DELETE"></form>`, []string{"DELETE http://site.test/a"}},
		{"override on POST, value first", `<form method="post" action="/a"><input value="patch" name="_method" type="hidden"></form>`, []string{"PATCH http://site.test/a"}},
		{"override on GET is ignored", `<form method="get" action="/a"><input type="hidden" name="_method" value="DELETE"></form>`, nil},
		{"override to GET is not state changing", `<form method="post" action="/a"><input type="hidden" name="_method" value="GET"></form>`, []string{"POST http://site.test/a"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := methodsOf(extractForms(c.html, pageFor(t)))
			if !equalStrings(got, c.want) {
				t.Errorf("extractForms = %v, want %v", got, c.want)
			}
		})
	}
}

// TestExtractFormsButtonFormMethod checks that a submit button's formmethod
// creates a POST submission even inside a GET form, using the button's own
// formaction when given.
func TestExtractFormsButtonFormMethod(t *testing.T) {
	got := methodsOf(extractForms(
		`<form method="get" action="/search"><button formmethod="post" formaction="/delete-all">Go</button></form>`,
		pageFor(t)))
	want := []string{"POST http://site.test/delete-all"}
	if !equalStrings(got, want) {
		t.Errorf("extractForms = %v, want %v", got, want)
	}
}

// TestExtractFormsIgnoresCommentedMarkup checks that a form inside an HTML
// comment, which a browser never renders, is not reported.
func TestExtractFormsIgnoresCommentedMarkup(t *testing.T) {
	got := extractForms(`<!-- <form method="post" action="/old"></form> --><p>no forms</p>`, pageFor(t))
	if len(got) != 0 {
		t.Errorf("commented-out form reported: %v", methodsOf(got))
	}
}

// TestExtractFormsSkipsCrossOriginAction checks that a form posting to another
// origin is not reported: a third-party form can't forge a request to this site.
func TestExtractFormsSkipsCrossOriginAction(t *testing.T) {
	got := extractForms(`<form method="post" action="https://payments.example/charge"></form>`, pageFor(t))
	if len(got) != 0 {
		t.Errorf("cross-origin form reported: %v", methodsOf(got))
	}
}

// TestExtractFormsResolvesBaseHref checks that a relative action is resolved
// against <base href>, not against the page URL.
func TestExtractFormsResolvesBaseHref(t *testing.T) {
	got := methodsOf(extractForms(`<base href="/app/"><form method="post" action="save"></form>`, pageFor(t)))
	want := []string{"POST http://site.test/app/save"}
	if !equalStrings(got, want) {
		t.Errorf("extractForms = %v, want %v", got, want)
	}
}

// TestExtractFormsMissingCloseTag checks that two forms with the second one's
// </form> missing are both found, with the first form's controls ending at the
// second form's start tag.
func TestExtractFormsMissingCloseTag(t *testing.T) {
	got := methodsOf(extractForms(
		`<form method="post" action="/a"><input name="x"><form method="post" action="/b"><input name="y"></form>`,
		pageFor(t)))
	want := []string{"POST http://site.test/a", "POST http://site.test/b"}
	if !equalStrings(got, want) {
		t.Errorf("extractForms = %v, want %v", got, want)
	}
}

// TestExtractFormsQuotedGreaterThan checks that a ">" inside a quoted attribute
// value does not end the form tag early, so the action after it is still read.
func TestExtractFormsQuotedGreaterThan(t *testing.T) {
	got := methodsOf(extractForms(`<form data-expr="a>b" method="post" action="/a"></form>`, pageFor(t)))
	want := []string{"POST http://site.test/a"}
	if !equalStrings(got, want) {
		t.Errorf("extractForms = %v, want %v", got, want)
	}
}

// TestTokenFieldDetection checks which hidden fields count as a CSRF token.
// Visible fields and generic *_token names (access_token) don't, while the
// framework token names (csrf, _token, __RequestVerificationToken, ...) do.
func TestTokenFieldDetection(t *testing.T) {
	cases := []struct {
		name, input string
		hasToken    bool
	}{
		{"hidden csrf_token", `<input type="hidden" name="csrf_token" value="x">`, true},
		{"hidden, value before name", `<input value="x" name="csrf_token" type="hidden">`, true},
		{"laravel _token", `<input type="hidden" name="_token" value="x">`, true},
		{"asp.net verification token", `<input type="hidden" name="__RequestVerificationToken" value="x">`, true},
		{"visible csrf-named text field", `<input type="text" name="csrf_note">`, false},
		{"hidden access_token is not CSRF", `<input type="hidden" name="access_token" value="x">`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractForms(`<form method="post" action="/a">`+c.input+`</form>`, pageFor(t))
			if len(got) != 1 {
				t.Fatalf("expected one form, got %d", len(got))
			}
			if got[0].HasToken != c.hasToken {
				t.Errorf("HasToken = %v, want %v", got[0].HasToken, c.hasToken)
			}
		})
	}
}

// TestTokenMetaDetection checks page-level token metas: a csrf-token meta counts,
// while csrf-param (which names the field, not the token) does not, whatever the
// attribute order.
func TestTokenMetaDetection(t *testing.T) {
	cases := []struct {
		name, head string
		want       bool
	}{
		{"csrf-token, name first", `<meta name="csrf-token" content="abc">`, true},
		{"csrf-token, content first", `<meta content="abc" name="csrf-token">`, true},
		{"csrf-param alone", `<meta name="csrf-param" content="authenticity_token">`, false},
		{"csrf-param and csrf-token", `<meta name="csrf-param" content="authenticity_token"><meta name="csrf-token" content="abc">`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractForms(`<html><head>`+c.head+`</head><body><form method="post" action="/a"></form></body></html>`, pageFor(t))
			if len(got) != 1 {
				t.Fatalf("expected one form, got %d", len(got))
			}
			if got[0].HasMetaToken != c.want {
				t.Errorf("HasMetaToken = %v, want %v", got[0].HasMetaToken, c.want)
			}
		})
	}
}

// TestExtractLinksAcceptsUnquotedHref checks that links are found whether
// their href is quoted or bare, and that a commented-out link is skipped.
func TestExtractLinksAcceptsUnquotedHref(t *testing.T) {
	got := extractLinks(`<a href=/next>x</a><a href='/other'>y</a><!-- <a href="/hidden"> -->`, pageFor(t))
	want := []string{"http://site.test/next", "http://site.test/other"}
	if !equalStrings(got, want) {
		t.Errorf("extractLinks = %v, want %v", got, want)
	}
}

// TestParseSetCookieReadsAttributesOnly checks that SameSite is read from the
// attribute list, so a cookie value containing "samesite=lax" is not mistaken
// for it.
func TestParseSetCookieReadsAttributesOnly(t *testing.T) {
	if got := parseSetCookie("session=samesite=lax; Path=/").SameSite; got != "" {
		t.Errorf("SameSite inside the value was read as %q, want empty", got)
	}
	if got := parseSetCookie("session=abc; Path=/; SameSite=Strict").SameSite; got != "strict" {
		t.Errorf("SameSite = %q, want strict", got)
	}
	if got := parseSetCookie("session=abc; samesite=None; Secure").Name; got != "session" {
		t.Errorf("Name = %q, want session", got)
	}
}

// equalStrings reports whether a and b hold the same strings in the same order.
// A nil slice and an empty one are treated as equal.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
