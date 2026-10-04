package bypass403

import "testing"

// TestWithoutWriteMethodsDropsOnlyWriteVerbs checks the default filter: the
// PUT, PATCH and DELETE attempts are removed, while the read-only method and
// header attempts remain so the default run still covers method tampering.
func TestWithoutWriteMethodsDropsOnlyWriteVerbs(t *testing.T) {
	specs := buildAttempts("/admin", "", "https", "https://host.test/")

	sawWrite := false
	for _, s := range specs {
		if s.method == "PUT" || s.method == "PATCH" || s.method == "DELETE" {
			sawWrite = true
		}
	}
	if !sawWrite {
		t.Fatal("buildAttempts produced no write-method attempts, so the filter test proves nothing")
	}

	kept := withoutWriteMethods(specs)
	if len(kept) == 0 || len(kept) >= len(specs) {
		t.Fatalf("filter kept %d of %d attempts; want some dropped and some kept", len(kept), len(specs))
	}
	for _, s := range kept {
		switch s.method {
		case "PUT", "PATCH", "DELETE":
			t.Errorf("write attempt %q survived the default filter", s.id)
		}
	}

	sawGet := false
	for _, s := range kept {
		if s.method == "GET" || s.method == "HEAD" || s.method == "POST" {
			sawGet = true
		}
	}
	if !sawGet {
		t.Error("filter removed the read-only method attempts too")
	}
}
