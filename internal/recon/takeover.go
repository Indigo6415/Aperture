package recon

import "strings"

// takeoverProvider is one cloud service whose CNAME target, once
// deprovisioned, stops resolving to anything -- letting an attacker who
// claims the same slug on that provider serve content under the victim's
// still-CNAMEd subdomain. fingerprint (when set) is a lowercase substring
// nearly always present in that provider's own "not claimed" response body,
// used to corroborate a dangling CNAME when the apex HTTP check managed to
// get a response at all (many dangling CNAMEs just fail to connect, in
// which case the CNAME/A-record mismatch alone is the signal).
type takeoverProvider struct {
	name        string
	cnameSuffix string
	fingerprint string
}

// takeoverProviders is a compact, well-known subset of
// https://github.com/EdOverflow/can-i-take-over-xyz -- providers whose
// dangling-CNAME takeover is well documented and commonly seen in the wild.
var takeoverProviders = []takeoverProvider{
	{"GitHub Pages", "github.io", "there isn't a github pages site here"},
	{"Heroku", "herokuapp.com", "no such app"},
	{"Amazon S3", "s3.amazonaws.com", "nosuchbucket"},
	{"Azure App Service", "azurewebsites.net", ""},
	{"Azure Cloud Service", "cloudapp.net", ""},
	{"Azure Traffic Manager", "trafficmanager.net", ""},
	{"Fastly", "fastly.net", "fastly error: unknown domain"},
	{"Pantheon", "pantheonsite.io", "the gods are wise"},
	{"Surge.sh", "surge.sh", "project not found"},
	{"Bitbucket", "bitbucket.io", "repository not found"},
	{"Tumblr", "tumblr.com", "there's nothing here"},
	{"Shopify", "myshopify.com", "sorry, this shop is currently unavailable"},
	{"Ghost", "ghost.io", "the thing you were looking for is no longer here"},
	{"WP Engine", "wpengine.com", ""},
	{"Netlify", "netlify.app", "not found - request id"},
	{"Zendesk", "zendesk.com", "help center closed"},
	{"UserVoice", "uservoice.com", "this uservoice subdomain is currently available"},
	{"Statuspage", "statuspage.io", "statuspage.io/pricing"},
	{"Cargo", "cargocollective.com", "404 not found"},
	{"Unbounce", "unbouncepages.com", "the requested url was not found on this server"},
}

// detectDanglingCNAME reports whether cname (a subdomain's CNAME target)
// names a known cloud provider, i.e. is worth flagging as a possible
// takeover once paired with the caller's own confirmation that the
// subdomain doesn't actually resolve (no A/AAAA records) -- detectDanglingCNAME
// itself only matches the provider, since it has no opinion on whether the
// DNS record is actually dangling.
func detectDanglingCNAME(cname string) (provider string, ok bool) {
	if cname == "" {
		return "", false
	}
	lower := strings.ToLower(cname)
	for _, p := range takeoverProviders {
		if strings.Contains(lower, p.cnameSuffix) {
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
