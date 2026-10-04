package ssrf

import (
	"context"
	"io"
	"net/http"
	"net/url"

	"github.com/Indigo6415/Aperture/internal/fingerprint"
)

// knownEndpoint is one product-specific path that fetches a URL taken from a
// query parameter. The nuclei templates this list is converted from each
// describe a real CVE or misconfiguration: a fixed path on a known product, a
// parameter that the product fetches server-side, and sometimes a few fixed
// query parameters the product needs before it will act on that one.
//
// Only fetch-style endpoints are kept. Templates whose parameter is passed to a
// shell, a template engine, or an LDAP/JNDI lookup test a different class of
// bug and are left to their own scanners.
type knownEndpoint struct {
	// name is the product or CVE the path came from, shown on each check so the
	// operator can tell what was probed.
	name  string
	path  string
	param string
	// fixed are query parameters sent with param every time. Some products
	// refuse the fetch without them.
	fixed map[string]string
}

// knownEndpoints are the converted fetch-endpoints. Each one is only probed
// after the existence gate in endpointTargets passes, so a product that is not
// installed costs one request.
var knownEndpoints = []knownEndpoint{
	{name: "generic redirect helper", path: "/_internal/redirect.php", param: "url"},
	{name: "image proxy (href)", path: "/_image", param: "href"},
	{name: "Apache Solr/PHP krgourl", path: "/adm/krgourl.php", param: "DOCUMENT_ROOT"},
	{name: "Oracle/GlassFish admingui version", path: "/admingui/version/Version", param: "productNameSrc",
		fixed: map[string]string{"productNameHeight": "500", "productNameWidth": "500"}},
	{name: "generic apply endpoint", path: "/apply/index.php", param: "url"},
	{name: "generic CORS proxy", path: "/cors", param: "url"},
	{name: "oEmbed proxy", path: "/external_content/retrieve/oembed", param: "endpoint", fixed: map[string]string{"url": "foo"}},
	{name: "FOG getversion", path: "/fog/service/getversion.php", param: "url"},
	{name: "jpeginfo", path: "/jpeginfo/jpeginfo.php", param: "url"},
	{name: "generic log proxy", path: "/log_proxy", param: "url"},
	{name: "Liferay httpmeta", path: "/o/get/httpmeta", param: "url"},
	{name: "generic picture proxy", path: "/pictureproxy.php", param: "url"},
	{name: "Prometheus blackbox probe", path: "/probe", param: "target", fixed: map[string]string{"module": "http_2xx"}},
	{name: "generic proxy", path: "/proxy", param: "url"},
	{name: "generic streaming proxy", path: "/proxy.stream", param: "origin"},
	{name: "Umbraco feed proxy", path: "/Umbraco/feedproxy.aspx", param: "url"},
	{name: "avatar favicon fetcher", path: "/v1/avatars/favicon", param: "url"},
	{name: "FormCraft 3 (WordPress)", path: "/wp-admin/admin-ajax.php", param: "URL",
		fixed: map[string]string{"action": "formcraft3_get"}},
	{name: "vCAV provider logo", path: "/ui/vcav-bootstrap/rest/vcav-providers/provider-logo", param: "url"},
	{name: "WebLogic UDDI explorer SSRF (CVE-2014-4210)", path: "/uddiexplorer/SearchPublicRegistries.jsp", param: "operator",
		fixed: map[string]string{"rdoSearch": "name", "txtSearchname": "sdf", "btnSubmit": "Search"}},
	{name: "Confluence/Jenkins-style getFavicon", path: "/services/pluginscript/..;/..;/..;/getFavicon", param: "host"},
	{name: "generic plugin configure", path: "/rest/configure", param: "plugins"},
}

// nonexistentPath is requested once per scan to learn what the server returns
// for a path that does not exist. A known endpoint that answers the same way is
// a catch-all, not the product, and is dropped.
const nonexistentPath = "/aperture-ssrf-no-such-path-7f3a9c"

// endpointTargets returns a formTarget for every known endpoint the target
// actually serves. Each formTarget carries only its own parameter, so its
// checks test that one point and not the whole candidate set. The gate:
//
//   - a 404 or a transport error means the product is not here;
//   - a response matching the catch-all page's status and content means the
//     server answers every path the same way (typical of a single-page app),
//     so it cannot tell the product from its own front end.
//
// An endpoint that fails the gate is skipped silently, since skipping is the
// expected result for most products.
func endpointTargets(ctx context.Context, client *http.Client, origin *url.URL, headers map[string]string) []formTarget {
	catchAllURL := *origin
	catchAllURL.Path = nonexistentPath
	catchAllURL.RawQuery = ""
	catchAll := fetchGET(ctx, client, &catchAllURL, headers)
	catchAllObs := fingerprint.Observe(catchAll.StatusCode, "", []byte(catchAll.Body))

	var out []formTarget
	for _, ep := range knownEndpoints {
		// Stop starting new existence probes once the scan is cancelled.
		if ctx.Err() != nil {
			break
		}
		// The gate sends a harmless canary in place of a URL, so it fetches
		// nothing and does not read like an attack.
		target := endpointURL(origin, ep, "aperturecanary")
		res := fetchGET(ctx, client, target, headers)
		if res.Err != nil || res.StatusCode == 0 || res.StatusCode == http.StatusNotFound {
			continue
		}
		obs := fingerprint.Observe(res.StatusCode, "", []byte(res.Body))
		if res.StatusCode == catchAll.StatusCode && fingerprint.Similar(obs, catchAllObs) {
			continue
		}

		// The formTarget's URL carries only the fixed parameters. The probe
		// point's value is set per payload by fetchParam.
		out = append(out, formTarget{
			name:   ep.name,
			method: http.MethodGet,
			url:    endpointURL(origin, ep, ""),
			params: []string{ep.param},
		})
	}
	return out
}

// endpointURL builds origin's URL for ep with its fixed parameters, plus
// param set to value when param is non-empty.
func endpointURL(origin *url.URL, ep knownEndpoint, value string) *url.URL {
	u := *origin
	u.Path = ep.path
	q := url.Values{}
	for k, v := range ep.fixed {
		q.Set(k, v)
	}
	if value != "" {
		q.Set(ep.param, value)
	}
	u.RawQuery = q.Encode()
	return &u
}

// fetchGET sends one plain GET of u and returns its status and body. It is only
// used for the existence and catch-all probes, which carry no payload, so it
// does not go through the throttled fetch path.
func fetchGET(ctx context.Context, client *http.Client, u *url.URL, headers map[string]string) *ssrfResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return &ssrfResult{Err: err}
	}
	req.Header.Set("User-Agent", "Aperture-SSRF")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return &ssrfResult{Err: err}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return &ssrfResult{Err: err, StatusCode: resp.StatusCode}
	}
	return &ssrfResult{StatusCode: resp.StatusCode, Body: string(raw)}
}
