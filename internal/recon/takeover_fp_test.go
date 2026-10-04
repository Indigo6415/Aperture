package recon

import (
	"context"
	"net"
	"strings"
	"testing"
)

// TestCNAMEMatchesOnLabelBoundary checks that a provider domain must appear as
// whole labels. "fakegithub.io" contains "github.io" as text, but it is not a
// GitHub Pages host, so flagging it would be a false positive.
func TestCNAMEMatchesOnLabelBoundary(t *testing.T) {
	if name, ok := detectDanglingCNAME("fakegithub.io"); ok {
		t.Errorf("fakegithub.io matched %q; the suffix must start at a label boundary", name)
	}
	if name, ok := detectDanglingCNAME("app.github.io."); !ok || name != "GitHub Pages" {
		t.Errorf("app.github.io. (trailing dot) = %q, %v; want GitHub Pages", name, ok)
	}
	if name, ok := detectDanglingCNAME("GITHUB.IO"); !ok || name != "GitHub Pages" {
		t.Errorf("bare provider domain in upper case = %q, %v; want GitHub Pages", name, ok)
	}
}

// TestRegionalS3HostsMatch checks that S3 hostnames in every shape are matched:
// the bare endpoint, a regional one, and a website endpoint with a region name.
func TestRegionalS3HostsMatch(t *testing.T) {
	for _, host := range []string{
		"bucket.s3.amazonaws.com",
		"bucket.s3.us-west-2.amazonaws.com",
		"bucket.s3-website-us-east-1.amazonaws.com",
	} {
		if name, ok := detectDanglingCNAME(host); !ok || name != "Amazon S3" {
			t.Errorf("%s = %q, %v; want Amazon S3", host, name, ok)
		}
	}
	if _, ok := detectDanglingCNAME("ec2.amazonaws.com"); ok {
		t.Error("a non-S3 amazonaws.com host was matched as S3")
	}
}

// TestNewProvidersAreDetected checks the providers added to the table, so each
// one resolves to its own name from a representative CNAME.
func TestNewProvidersAreDetected(t *testing.T) {
	cases := map[string]string{
		"assets.storage.googleapis.com": "Google Cloud Storage",
		"app.elasticbeanstalk.com":      "AWS Elastic Beanstalk",
		"www.vercel-dns.com":            "Vercel",
		"docs.readme.io":                "Readme.io",
		"d111111abcdef8.cloudfront.net": "AWS CloudFront",
		"news.wordpress.com":            "WordPress.com",
	}
	for cname, want := range cases {
		if got, ok := detectDanglingCNAME(cname); !ok || got != want {
			t.Errorf("%s = %q, %v; want %q", cname, got, ok, want)
		}
	}
}

// TestNewFingerprintsCorroborate checks that the new fingerprints count as
// page confirmation only for their own provider, and that a generic 404 page
// no longer confirms the providers whose text was too common to trust.
func TestNewFingerprintsCorroborate(t *testing.T) {
	if !bodyMatchesProvider("Google Cloud Storage", "<Error><Message>The specified bucket does not exist.</Message>") {
		t.Error("GCS unclaimed-bucket text was not matched")
	}
	if !bodyMatchesProvider("Readme.io", "Project doesnt exist... yet!") {
		t.Error("Readme.io unclaimed text was not matched")
	}
	// detectTakeover only counts a page when providerHasFingerprint is true, so a
	// provider without a fingerprint can never be confirmed by a generic 404 page.
	if providerHasFingerprint("Cargo") {
		t.Error("Cargo still has a fingerprint that generic 404 pages would match")
	}
	if providerHasFingerprint("Unbounce") {
		t.Error("Unbounce still has a fingerprint that generic Apache 404 pages would match")
	}
}

// TestCNAMETargetUnresolvable checks the resolution signal with an injected
// resolver: a target that resolves to nothing counts, a target that resolves
// does not, and a timeout is not evidence either way.
func TestCNAMETargetUnresolvable(t *testing.T) {
	orig := cnameTargetLookup
	defer func() { cnameTargetLookup = orig }()

	cases := []struct {
		name string
		fn   func(ctx context.Context, host string) ([]string, error)
		want bool
	}{
		{
			name: "target does not exist",
			fn: func(ctx context.Context, host string) ([]string, error) {
				return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
			},
			want: true,
		},
		{
			name: "target resolves",
			fn: func(ctx context.Context, host string) ([]string, error) {
				return []string{"203.0.113.7"}, nil
			},
			want: false,
		},
		{
			name: "lookup times out",
			fn: func(ctx context.Context, host string) ([]string, error) {
				return nil, &net.DNSError{Err: "i/o timeout", Name: host, IsTimeout: true}
			},
			want: false,
		},
	}
	for _, c := range cases {
		cnameTargetLookup = c.fn
		if got := cnameTargetUnresolvable(context.Background(), "gone.azurewebsites.net."); got != c.want {
			t.Errorf("%s: cnameTargetUnresolvable = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestNormalizeHost checks that host comparison ignores case and the trailing dot.
func TestNormalizeHost(t *testing.T) {
	if got := normalizeHost(" Example.COM. "); got != "example.com" {
		t.Errorf("normalizeHost = %q, want example.com", got)
	}
	if strings.HasSuffix(normalizeHost("a.b."), ".") {
		t.Error("trailing dot survived normalizeHost")
	}
}

// TestRefineTakeoverUsesTargetResolution checks that a heuristic takeover is
// lifted to likely only when the CNAME target resolves to nothing, and that
// other grades are left alone without a lookup.
func TestRefineTakeoverUsesTargetResolution(t *testing.T) {
	orig := cnameTargetLookup
	defer func() { cnameTargetLookup = orig }()

	heuristic := func() Check {
		return Check{Data: map[string]any{"cname": "gone.azurewebsites.net", "confidence": "heuristic"}}
	}

	cnameTargetLookup = func(ctx context.Context, host string) ([]string, error) {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	got := refineTakeover(context.Background(), heuristic())
	if got.Data["confidence"] != "likely" || got.Data["targetUnresolved"] != true {
		t.Errorf("unresolvable target: got %+v, want likely with targetUnresolved", got.Data)
	}

	cnameTargetLookup = func(ctx context.Context, host string) ([]string, error) {
		return []string{"203.0.113.7"}, nil
	}
	if got := refineTakeover(context.Background(), heuristic()); got.Data["confidence"] != "heuristic" {
		t.Errorf("resolving target: confidence = %v, want heuristic", got.Data["confidence"])
	}

	lookups := 0
	cnameTargetLookup = func(ctx context.Context, host string) ([]string, error) {
		lookups++
		return nil, nil
	}
	confirmed := Check{Data: map[string]any{"cname": "gone.azurewebsites.net", "confidence": "confirmed"}}
	if got := refineTakeover(context.Background(), confirmed); got.Data["confidence"] != "confirmed" || lookups != 0 {
		t.Errorf("confirmed takeover: confidence = %v, lookups = %d; want confirmed with no lookup", got.Data["confidence"], lookups)
	}
}
