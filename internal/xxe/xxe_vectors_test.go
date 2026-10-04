package xxe

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Indigo6415/Aperture/internal/collaborator"
)

// TestParseTemplateFindsAttributeLeaves checks that attribute values are
// injection points, that namespace declarations are not, and that each leaf's
// byte range covers exactly its value.
func TestParseTemplateFindsAttributeLeaves(t *testing.T) {
	raw := `<?xml version="1.0"?><item id="7" kind='a' xmlns:x="urn:x"><name>bob</name></item>`
	tpl, err := parseTemplate(raw)
	if err != nil {
		t.Fatalf("parseTemplate: %v", err)
	}
	var got []string
	for _, l := range tpl.leaves {
		got = append(got, l.describe())
		if v := tpl.text[l.start:l.end]; v == "" {
			t.Errorf("leaf %s has an empty range", l.describe())
		}
	}
	want := []string{"@id of <item>", "@kind of <item>", "<name>"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("leaves = %v, want %v", got, want)
	}
	for _, l := range tpl.leaves {
		if l.attr == "id" {
			if v := tpl.text[l.start:l.end]; v != "7" {
				t.Errorf("id leaf covers %q, want %q", v, "7")
			}
		}
	}
}

// TestAttributeLeafRendersWellFormed checks that a canary written into an
// attribute value keeps the document well-formed, so the attribute point can
// carry the in-band canary.
func TestAttributeLeafRendersWellFormed(t *testing.T) {
	tpl, err := parseTemplate(`<?xml version="1.0"?><item id="7"><name>bob</name></item>`)
	if err != nil {
		t.Fatal(err)
	}
	pt := tpl.leaves[0]
	out := tpl.render(&pt, "&xxe;", `<!DOCTYPE aperture [<!ENTITY xxe "v">]>`)
	if err := checkWellFormed(entityRefPattern.ReplaceAllString(out, "x")); err != nil {
		t.Errorf("rendered attribute leaf is not well-formed: %v\n%s", err, out)
	}
}

// TestRunAttributePointsSkipTextOnlyPayloads runs against an endpoint whose
// parser would expand an external entity anywhere, attribute included. The
// file-read module must still report only the text point: an external entity
// reference is not allowed in an attribute value, so that payload is never
// sent there.
func TestRunAttributePointsSkipTextOnlyPayloads(t *testing.T) {
	srv := httptest.NewServer(fakeParser("vuln"))
	defer srv.Close()

	body := `<order id="42"><customer>alice</customer></order>`
	res, err := Run(context.Background(), Request{URL: srv.URL + "/order", Body: body}, OOBConfig{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.PointsTested != 2 {
		t.Fatalf("PointsTested = %d, want 2 (attribute and text)", res.PointsTested)
	}
	m := moduleByID(t, res, "file-read")
	if len(m.Findings) != 1 {
		t.Fatalf("file-read findings = %d, want 1 (the text point only)", len(m.Findings))
	}
	if !strings.Contains(m.Findings[0].Label, "<customer>") {
		t.Errorf("file-read finding on the wrong point: %s", m.Findings[0].Label)
	}
	// The canary is allowed in an attribute, since an internal entity is legal there.
	if canary := moduleByID(t, res, "entity-canary"); len(canary.Findings) != 2 {
		t.Errorf("entity-canary findings = %d, want 2 (both points)", len(canary.Findings))
	}
}

// TestRunLocalDTDErrorConfirmsFileRead checks the local-DTD module: a parser
// that loads the server's DTD and reports a missing-file path that embeds the
// first line of /etc/passwd is a confirmed read.
func TestRunLocalDTDErrorConfirmsFileRead(t *testing.T) {
	srv := httptest.NewServer(fakeParser("vuln"))
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/import"}, OOBConfig{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	m := moduleByID(t, res, "local-dtd-error")
	if len(m.Findings) == 0 {
		t.Fatal("local-dtd-error: no findings against a parser that leaks the file in an error")
	}
	if m.Findings[0].Confidence != ConfidenceConfirmed {
		t.Errorf("confidence = %q, want confirmed", m.Findings[0].Confidence)
	}
	if !strings.Contains(m.Findings[0].Request.Body, "docbookx.dtd") {
		t.Errorf("finding does not carry the DTD redefinition that caused it")
	}
}

// TestRunLocalDTDErrorIgnoresEchoedDTD checks the local-DTD module against an
// echo endpoint. The DOCTYPE is returned verbatim, and it names /etc/passwd,
// but it never carries the file's contents, so nothing may match.
func TestRunLocalDTDErrorIgnoresEchoedDTD(t *testing.T) {
	srv := httptest.NewServer(fakeParser("echo"))
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/echo"}, OOBConfig{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if m := moduleByID(t, res, "local-dtd-error"); len(m.Findings) != 0 {
		t.Errorf("local-dtd-error reported %d findings on an echoed DOCTYPE", len(m.Findings))
	}
}

// TestPHPFilterPatternMatchesBase64PasswdPrefix checks that the php://filter
// signature is the base64 of the passwd prefix, so an encoded read is matched
// and a plain-text response that merely mentions the path is not.
func TestPHPFilterPatternMatchesBase64PasswdPrefix(t *testing.T) {
	var pattern = findPayload(t, fileReadModule.id, "php://filter").pattern
	encoded := base64.StdEncoding.EncodeToString([]byte(passwdText))
	if !pattern.MatchString("<result>" + encoded + "</result>") {
		t.Errorf("base64 passwd not matched")
	}
	if pattern.MatchString("file:///etc/passwd is not readable") {
		t.Errorf("a path mention matched the base64 signature")
	}
}

// findPayload returns the in-band payload of module id whose label contains
// marker, failing the test if none does.
func findPayload(t *testing.T, id, marker string) inbandPayload {
	t.Helper()
	for _, m := range inbandModules("abc") {
		if m.meta.id != id {
			continue
		}
		for _, p := range m.payloads {
			if strings.Contains(p.label, marker) {
				return p
			}
		}
	}
	t.Fatalf("no payload %q in module %s", marker, id)
	return inbandPayload{}
}

// TestRunOOBFileExfilConfirmsRead checks the out-of-band file read. The parser
// sends /etc/passwd as the query string of its callback, so the finding must
// say the file was read, not only that a request was made.
func TestRunOOBFileExfilConfirmsRead(t *testing.T) {
	reg := collaborator.NewRegistry()
	cb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 && parts[0] == "collab" {
			reg.Record(parts[1], collaborator.Interaction{
				Protocol: "http", RemoteAddr: "203.0.113.9",
				Identifier: parts[2], Query: r.URL.RawQuery,
			})
		}
	}))
	defer cb.Close()

	srv := httptest.NewServer(fakeParser("oob"))
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/blind", Body: `<doc><field>x</field></doc>`},
		OOBConfig{Registry: reg, CallbackBaseURL: cb.URL})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	m := moduleByID(t, res, "oob-callback")
	if len(m.Findings) != 1 {
		t.Fatalf("oob-callback findings = %d, want 1", len(m.Findings))
	}
	f := m.Findings[0]
	if !strings.Contains(f.Label, "read /etc/passwd through a callback") {
		t.Errorf("label does not report the file read: %s", f.Label)
	}
	if f.Confidence != ConfidenceConfirmed {
		t.Errorf("confidence = %q, want confirmed", f.Confidence)
	}
	if !strings.Contains(f.Evidence, "root:x:0:0:") {
		t.Errorf("evidence does not carry the file line: %q", f.Evidence)
	}
	if f.Request == nil || !strings.Contains(f.Request.Body, "%file;") {
		t.Errorf("finding does not carry the exfiltrating DOCTYPE")
	}
}

// TestRunOOBExternalSubsetCallsBack checks the external-subset variant on its
// own: a parser that fetches the DOCTYPE's external DTD calls back, and the hit
// is named for that variant.
func TestRunOOBExternalSubsetCallsBack(t *testing.T) {
	reg := collaborator.NewRegistry()
	cb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 && parts[0] == "collab" {
			reg.Record(parts[1], collaborator.Interaction{Protocol: "http", Identifier: parts[2]})
		}
	}))
	defer cb.Close()

	// A parser that only fetches external subsets: it never expands an entity,
	// so the callback can only come from the external-subset variant.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := readAllBody(r)
		if m := externalSubsetPattern.FindStringSubmatch(raw); m != nil {
			if resp, err := http.Get(m[1]); err == nil {
				_ = resp.Body.Close()
			}
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = fmt.Fprint(w, "<ok/>")
	}))
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/dtd", Body: `<doc><field>x</field></doc>`},
		OOBConfig{Registry: reg, CallbackBaseURL: cb.URL})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	m := moduleByID(t, res, "oob-callback")
	if len(m.Findings) != 1 {
		t.Fatalf("oob-callback findings = %d, want 1", len(m.Findings))
	}
	if !strings.Contains(m.Findings[0].Detail, "external-subset") {
		t.Errorf("detail does not name the external-subset variant: %s", m.Findings[0].Detail)
	}
}

// TestExfiltratedPasswdDecodesQuery checks that a percent-encoded callback query
// is decoded before the passwd line is matched, and that an unrelated query is
// not treated as a file read.
func TestExfiltratedPasswdDecodesQuery(t *testing.T) {
	encoded := collaborator.Interaction{Query: "x=root%3Ax%3A0%3A0%3Aroot%3A%2Froot%3A%2Fbin%2Fsh"}
	if line, ok := exfiltratedPasswd([]collaborator.Interaction{encoded}); !ok || !strings.HasPrefix(line, "root:x:0:0:") {
		t.Errorf("encoded passwd line not found: %q, %v", line, ok)
	}
	if _, ok := exfiltratedPasswd([]collaborator.Interaction{{Query: "x=hello"}}); ok {
		t.Errorf("unrelated query matched as a file read")
	}
}

// readAllBody returns a request body as a string, for the test listeners that
// inspect the XML they receive.
func readAllBody(r *http.Request) string {
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := r.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return b.String()
}
