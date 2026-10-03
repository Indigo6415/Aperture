package collaborator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// webhookSiteBase is webhook.site's own API root -- an alternative callback
// provider to this process's own Registry/StartDNS listener above, for an
// operator who'd rather not expose their own host to the internet, or who
// just wants the "get a unique link, open it in a browser, see what hit it"
// workflow webhook.site itself offers with zero configuration on Aperture's
// side. Unlike Registry, a webhook.site token and its interaction history
// live on their servers, not this process's memory -- polled the same way
// (see PollWebhookSite) but proxied through this server rather than called
// directly from the browser, since webhook.site's API doesn't return
// Access-Control-Allow-Origin and a cross-origin fetch would just be
// rejected by the browser's own CORS enforcement.
const webhookSiteBase = "https://webhook.site"

// webhookSiteTimeout bounds every call out to webhook.site -- it's a
// third-party service on the far side of the internet, not a resource this
// process controls the latency of.
const webhookSiteTimeout = 10 * time.Second

// WebhookSiteToken is a freshly minted webhook.site token: UUID identifies
// it for polling (see PollWebhookSite), URL is the actual callback address a
// payload gets pointed at, ViewURL is webhook.site's own hosted page for
// watching it live in a browser without needing Aperture's poll loop at all.
type WebhookSiteToken struct {
	UUID    string `json:"uuid"`
	URL     string `json:"url"`
	ViewURL string `json:"viewUrl"`
}

// WebhookSiteCallbackURL returns the callback address for an
// already-minted webhook.site uuid -- used by a scanner's OOB module (e.g.
// internal/ssrf) building one per-test URL under a shared, operator-picked
// webhook.site token, where only the bare uuid (see collaborator.Ref.Token)
// is on hand rather than the full WebhookSiteToken this package returned
// when it was first minted.
func WebhookSiteCallbackURL(uuid string) string {
	return webhookSiteBase + "/" + uuid
}

// NewWebhookSiteToken asks webhook.site to mint a fresh, unique callback
// URL -- no API key needed, it's the same anonymous-token flow
// webhook.site's own web UI uses when a visitor lands on the homepage.
func NewWebhookSiteToken(ctx context.Context) (WebhookSiteToken, error) {
	ctx, cancel := context.WithTimeout(ctx, webhookSiteTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookSiteBase+"/token", nil)
	if err != nil {
		return WebhookSiteToken{}, fmt.Errorf("webhook.site: build request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return WebhookSiteToken{}, fmt.Errorf("webhook.site: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		return WebhookSiteToken{}, fmt.Errorf("webhook.site: unexpected status %d: %s", resp.StatusCode, body)
	}

	var parsed struct {
		UUID string `json:"uuid"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return WebhookSiteToken{}, fmt.Errorf("webhook.site: decode: %w", err)
	}
	if parsed.UUID == "" {
		return WebhookSiteToken{}, fmt.Errorf("webhook.site: response had no token uuid")
	}

	return WebhookSiteToken{
		UUID:    parsed.UUID,
		URL:     webhookSiteBase + "/" + parsed.UUID,
		ViewURL: webhookSiteBase + "/#!/view/" + parsed.UUID,
	}, nil
}

// webhookSiteRequest mirrors the subset of one entry of
// GET /token/{uuid}/requests' "data" array that Aperture surfaces -- see
// https://docs.webhook.site for the full schema.
type webhookSiteRequest struct {
	UUID      string              `json:"uuid"`
	Method    string              `json:"method"`
	IP        string              `json:"ip"`
	Headers   map[string][]string `json:"headers"`
	Content   string              `json:"content"`
	URL       string              `json:"url"`
	CreatedAt string              `json:"created_at"`
}

// webhookSiteCreatedAtLayout is the timestamp format webhook.site's API
// returns "created_at" in -- observed, not documented, so parse failures
// (webhookSiteToInteraction) fall back to leaving Timestamp zero rather than
// erroring the whole poll out over one cosmetic field.
const webhookSiteCreatedAtLayout = "2006-01-02 15:04:05"

// PollWebhookSite fetches every request recorded against uuid so far,
// newest first, and reshapes it into the same Interaction shape Registry.
// Poll returns, so the UI's rendering code doesn't need to know which
// provider a given token came from.
func PollWebhookSite(ctx context.Context, uuid string) ([]Interaction, error) {
	ctx, cancel := context.WithTimeout(ctx, webhookSiteTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, webhookSiteBase+"/token/"+url.PathEscape(uuid)+"/requests?sorting=newest", nil)
	if err != nil {
		return nil, fmt.Errorf("webhook.site: build request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("webhook.site: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		return nil, fmt.Errorf("webhook.site: unexpected status %d: %s", resp.StatusCode, body)
	}

	var parsed struct {
		Data []webhookSiteRequest `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("webhook.site: decode: %w", err)
	}

	out := make([]Interaction, 0, len(parsed.Data))
	for _, req := range parsed.Data {
		out = append(out, webhookSiteToInteraction(uuid, req))
	}
	return out, nil
}

// webhookSiteToInteraction converts one webhook.site request record into
// Aperture's own Interaction shape. Headers are kept in full (unlike
// handlers_collaborator.go's collabHeaderAllowlist for Aperture's own
// listener) -- webhook.site's servers already captured and stored
// everything regardless of what Aperture chooses to display, so there's no
// privacy benefit to filtering here, only lost information.
func webhookSiteToInteraction(tokenUUID string, req webhookSiteRequest) Interaction {
	ts, _ := time.Parse(webhookSiteCreatedAtLayout, req.CreatedAt)

	headers := make(map[string]string, len(req.Headers))
	for name, vals := range req.Headers {
		if len(vals) > 0 {
			headers[name] = vals[0]
		}
	}

	path, query, identifier := "/", "", ""
	if u, err := url.Parse(req.URL); err == nil {
		path = strings.TrimPrefix(u.Path, "/"+tokenUUID)
		if path == "" {
			path = "/"
		}
		query = u.RawQuery
		// Mirrors handlers_collaborator.go's own HTTP listener: the first
		// path segment after the token is the caller-chosen identifier
		// (e.g. ".../<uuid>/ssrf-webhook_url"), not part of Path itself.
		if trimmed := strings.TrimPrefix(path, "/"); trimmed != "" {
			if i := strings.IndexByte(trimmed, '/'); i >= 0 {
				identifier, path = trimmed[:i], trimmed[i:]
			} else {
				identifier, path = trimmed, "/"
			}
		}
	}

	return Interaction{
		ID:         req.UUID,
		Protocol:   "http",
		Timestamp:  ts,
		RemoteAddr: req.IP,
		Method:     req.Method,
		Path:       path,
		Query:      query,
		Headers:    headers,
		Body:       req.Content,
		Identifier: identifier,
	}
}
