package api

import "testing"

// TestTokenProbeFor checks the gate in front of the state-changing token
// check: nothing requested means nothing run, and an incomplete or
// unconfirmed request is refused instead of quietly dropped.
func TestTokenProbeFor(t *testing.T) {
	if got, err := tokenProbeFor(nil); got != nil || err != nil {
		t.Fatalf("nil request = %v, %v; want nil, nil", got, err)
	}
	if got, err := tokenProbeFor(&csrfTokenProbeRequest{URL: "  "}); got != nil || err != nil {
		t.Fatalf("blank URL = %v, %v; want nil, nil", got, err)
	}

	valid := csrfTokenProbeRequest{URL: " https://t.example/form ", Body: "csrf=x&name=a", Field: "csrf", Confirm: true}
	got, err := tokenProbeFor(&valid)
	if err != nil {
		t.Fatalf("valid request: %v", err)
	}
	if got.URL != "https://t.example/form" || got.Method != "POST" || got.Field != "csrf" {
		t.Errorf("converted probe = %+v; want trimmed URL, default POST, field csrf", got)
	}

	unconfirmed := valid
	unconfirmed.Confirm = false
	if _, err := tokenProbeFor(&unconfirmed); err == nil {
		t.Error("probe without confirm was accepted")
	}

	noField := valid
	noField.Field = ""
	if _, err := tokenProbeFor(&noField); err == nil {
		t.Error("probe without a token field was accepted")
	}

	badMethod := valid
	badMethod.Method = "GET"
	if _, err := tokenProbeFor(&badMethod); err == nil {
		t.Error("GET was accepted as a state-changing probe method")
	}
}
