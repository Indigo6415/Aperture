package techfp

import "testing"

// TestDetectExtractsVersionFromServerHeader checks a Server header is matched
// to its product, with the version captured and confidence set to high.
func TestDetectExtractsVersionFromServerHeader(t *testing.T) {
	dets := Detect(map[string]string{"Server": "nginx/1.18.0"}, "", "https://example.test/")
	for _, d := range dets {
		if d.Name == "nginx" {
			if d.Version != "1.18.0" {
				t.Fatalf("nginx version = %q, want 1.18.0", d.Version)
			}
			if d.Confidence != "high" {
				t.Fatalf("confidence = %q, want high when a version was extracted", d.Confidence)
			}
			return
		}
	}
	t.Fatalf("nginx not detected in %+v", dets)
}

// TestDetectNothingForPlainResponse makes sure an empty response yields no
// detections, so the fingerprinter can't invent technologies from nothing.
func TestDetectNothingForPlainResponse(t *testing.T) {
	if dets := Detect(map[string]string{}, "", "https://example.test/"); len(dets) != 0 {
		t.Fatalf("expected no detections, got %+v", dets)
	}
}
