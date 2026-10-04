package recon

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strings"
)

// takeoverProvider is one cloud service whose CNAME target, once
// deprovisioned, stops resolving to anything -- letting an attacker who
// claims the same slug on that provider serve content under the victim's
// still-CNAMEd subdomain. fingerprint (when set) is a lowercase substring
// nearly always present in that provider's own "not claimed" response body,
// used to corroborate a dangling CNAME when the apex HTTP check managed to
// get a response at all (many dangling CNAMEs just fail to connect, in
// which case the CNAME/A-record mismatch alone is the signal).
//
// cnameSuffix names the provider domain; a CNAME matches when it equals that
// domain or ends in "."+cnameSuffix, so "fakegithub.io" does not match
// "github.io". cnameRe, when set, replaces that test for providers whose
// hostnames vary by region or product (for example S3 website endpoints).
type takeoverProvider struct {
	name        string
	cnameSuffix string
	cnameRe     *regexp.Regexp
	fingerprint string
}

// takeoverProviders is a well-known subset of
// https://github.com/EdOverflow/can-i-take-over-xyz -- providers whose
// dangling-CNAME takeover is documented and commonly seen in the wild. A
// provider with an empty fingerprint can only be judged from DNS: its
// unclaimed page text is either not known with confidence or too generic to
// trust, so a page match is never counted for it.
var takeoverProviders = []takeoverProvider{
	{name: "GitHub Pages", cnameSuffix: "github.io", fingerprint: "there isn't a github pages site here"},
	{name: "Heroku", cnameSuffix: "herokuapp.com", fingerprint: "no such app"},
	{name: "Amazon S3", cnameSuffix: "s3.amazonaws.com", cnameRe: regexp.MustCompile(`\bs3[.-]([a-z0-9-]+\.)?amazonaws\.com$`), fingerprint: "nosuchbucket"},
	{name: "Google Cloud Storage", cnameSuffix: "storage.googleapis.com", fingerprint: "the specified bucket does not exist"},
	{name: "Azure App Service", cnameSuffix: "azurewebsites.net", fingerprint: "404 web site not found"},
	{name: "Azure Cloud Service", cnameSuffix: "cloudapp.net"},
	{name: "Azure Traffic Manager", cnameSuffix: "trafficmanager.net"},
	{name: "AWS Elastic Beanstalk", cnameSuffix: "elasticbeanstalk.com"},
	{name: "Fastly", cnameSuffix: "fastly.net", fingerprint: "fastly error: unknown domain"},
	{name: "Pantheon", cnameSuffix: "pantheonsite.io", fingerprint: "the gods are wise"},
	{name: "Surge.sh", cnameSuffix: "surge.sh", fingerprint: "project not found"},
	{name: "Bitbucket", cnameSuffix: "bitbucket.io", fingerprint: "repository not found"},
	{name: "Tumblr", cnameSuffix: "tumblr.com", fingerprint: "there's nothing here"},
	{name: "Shopify", cnameSuffix: "myshopify.com", fingerprint: "sorry, this shop is currently unavailable"},
	{name: "Ghost", cnameSuffix: "ghost.io", fingerprint: "the thing you were looking for is no longer here"},
	{name: "WP Engine", cnameSuffix: "wpengine.com"},
	{name: "WordPress.com", cnameSuffix: "wordpress.com", fingerprint: "do you want to register"},
	{name: "Netlify", cnameSuffix: "netlify.app", fingerprint: "not found - request id"},
	{name: "Vercel", cnameSuffix: "vercel-dns.com", fingerprint: "the deployment could not be found on vercel"},
	{name: "Zendesk", cnameSuffix: "zendesk.com", fingerprint: "help center closed"},
	{name: "UserVoice", cnameSuffix: "uservoice.com", fingerprint: "this uservoice subdomain is currently available"},
	{name: "Statuspage", cnameSuffix: "statuspage.io", fingerprint: "statuspage.io/pricing"},
	{name: "Readme.io", cnameSuffix: "readme.io", fingerprint: "project doesnt exist... yet!"},
	{name: "Feedpress", cnameSuffix: "redirect.feedpress.it", fingerprint: "the feed has not been found."},
	{name: "AWS CloudFront", cnameSuffix: "cloudfront.net", fingerprint: "the request could not be satisfied"},
	// The earlier "404 not found" text for Cargo appears on every 404 page on the
	// web, so it could never separate a claimed host from an unclaimed one.
	{name: "Cargo", cnameSuffix: "cargocollective.com"},
	// Unbounce's own unclaimed text is the same generic Apache 404 line, so it is
	// DNS-only here for the same reason as Cargo.
	{name: "Unbounce", cnameSuffix: "unbouncepages.com"},
}

// normalizeHost lowercases a host name and drops the trailing dot of its
// fully qualified form, so a CNAME compares the same however the resolver wrote it.
func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

// matches reports whether a normalized CNAME target belongs to this provider.
func (p takeoverProvider) matches(cname string) bool {
	if p.cnameRe != nil {
		return p.cnameRe.MatchString(cname)
	}
	return cname == p.cnameSuffix || strings.HasSuffix(cname, "."+p.cnameSuffix)
}

// detectDanglingCNAME reports whether cname (a subdomain's CNAME target)
// names a known cloud provider, i.e. is worth flagging as a possible
// takeover once paired with the caller's own confirmation that the
// subdomain doesn't actually resolve (no A/AAAA records) -- detectDanglingCNAME
// itself only matches the provider, since it has no opinion on whether the
// DNS record is actually dangling.
func detectDanglingCNAME(cname string) (provider string, ok bool) {
	host := normalizeHost(cname)
	if host == "" {
		return "", false
	}
	for _, p := range takeoverProviders {
		if p.matches(host) {
			return p.name, true
		}
	}
	return "", false
}

// bodyMatchesProvider reports whether body (a response body snippet, any
// case) contains the given provider's known "unclaimed" fingerprint text --
// used to corroborate a takeover flag when the HTTP check did get a
// response instead of merely failing to connect. A provider with no known
// fingerprint (fingerprint == "") always reports true here, since the
// dangling-CNAME signal (checkDNS's cname-with-no-A/AAAA) already stands on
// its own for those providers.
func bodyMatchesProvider(provider, body string) bool {
	for _, p := range takeoverProviders {
		if p.name != provider {
			continue
		}
		if p.fingerprint == "" {
			return true
		}
		return strings.Contains(strings.ToLower(body), p.fingerprint)
	}
	return false
}

// providerHasFingerprint reports whether provider has its own "unclaimed"
// page text. Providers without one can only be judged from DNS, so a page match
// is never possible for them and must not be counted as confirmation.
func providerHasFingerprint(provider string) bool {
	for _, p := range takeoverProviders {
		if p.name == provider {
			return p.fingerprint != ""
		}
	}
	return false
}

// cnameTargetLookup resolves a host's address records. It is a variable so the
// tests can substitute a resolver that returns a chosen DNS error.
var cnameTargetLookup = func(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// refineTakeover looks at a flagged takeover whose only evidence is a dangling
// CNAME (confidence "heuristic"), and checks whether the CNAME target itself
// resolves to nothing. If it doesn't, the provider resource is most likely gone,
// which lifts the finding to "likely" and records that in the Check data. Other
// confidence levels are returned unchanged, so no extra lookup is made for them.
func refineTakeover(ctx context.Context, takeover Check) Check {
	if takeover.Data["confidence"] != "heuristic" {
		return takeover
	}
	cname, _ := takeover.Data["cname"].(string)
	// Only a clear "nothing resolves here" answer upgrades the finding; a
	// timeout or server error leaves the heuristic grade as it was.
	if !cnameTargetUnresolvable(ctx, cname) {
		return takeover
	}
	takeover.Data["confidence"] = "likely"
	takeover.Data["targetUnresolved"] = true
	return takeover
}

// cnameTargetUnresolvable reports whether the CNAME target itself resolves to
// nothing. A deprovisioned provider resource often leaves its own hostname
// without any record, which is stronger evidence than the subdomain alone
// lacking one. The net package reports "no records" and "name does not exist"
// under the same IsNotFound flag, so this is the "nothing resolves here"
// signal, not a strict NXDOMAIN test. Any other error, such as a timeout or a
// server failure, returns false, because it says nothing about the name.
func cnameTargetUnresolvable(ctx context.Context, cname string) bool {
	host := normalizeHost(cname)
	if host == "" {
		return false
	}
	_, err := cnameTargetLookup(ctx, host)
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}
