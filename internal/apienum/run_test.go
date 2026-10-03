package apienum

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// openapiFixture is a minimal OpenAPI 3 document describing one
// path-parameterized route with an id-shaped path param and a free-text
// body field -- enough to exercise spec discovery, path-param
// substitution, method characterization, and injection-point flagging in
// one run.
const openapiFixture = `{
  "openapi": "3.0.0",
  "paths": {
    "/users/{id}": {
      "parameters": [
        {"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}
      ],
      "get": {},
      "delete": {},
      "patch": {
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {"properties": {"name": {"type": "string"}}}
            }
          }
        }
      }
    }
  }
}`

// newFixtureServer stands in for a real target: it serves openapiFixture at
// /openapi.json, answers /users/1 for GET/DELETE/PATCH/OPTIONS, and 404s
// everything else -- including every brute-force guess and GraphQL probe
// path this run will also fire, so the test stays fast and deterministic.
func newFixtureServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(openapiFixture))
	})
	mux.HandleFunc("/users/1", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodOptions:
			w.Header().Set("Allow", "GET, DELETE, PATCH")
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":1,"name":"alice"}`))
		case http.MethodDelete, http.MethodPatch:
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestRunScanFindsSpecRouteAndFlagsIDParam(t *testing.T) {
	srv := newFixtureServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := RunScan(ctx, srv.URL, Options{CrawlDepth: 1, MaxPages: 1})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}

	if result.Schema == nil || !result.Schema.Found || result.Schema.Kind != "openapi" {
		t.Fatalf("expected an OpenAPI spec to be found, got %+v", result.Schema)
	}
	if result.Schema.RouteCount != 1 {
		t.Fatalf("expected 1 route described by the spec, got %d", result.Schema.RouteCount)
	}

	var route *Route
	for i := range result.Routes {
		if result.Routes[i].Path == "/users/{id}" {
			route = &result.Routes[i]
			break
		}
	}
	if route == nil {
		t.Fatalf("expected a /users/{id} route in %+v", result.Routes)
	}
	if !route.Confirmed {
		t.Error("expected the spec-discovered route to be Confirmed")
	}
	if route.Source != "spec" {
		t.Errorf("expected Source \"spec\", got %q", route.Source)
	}

	allowedSeen := map[string]bool{}
	probedSeen := map[string]bool{}
	for _, m := range route.Methods {
		probedSeen[m.Method] = true
		if m.Allowed {
			allowedSeen[m.Method] = true
		}
	}
	for _, want := range []string{"GET", "DELETE", "PATCH"} {
		if !allowedSeen[want] {
			t.Errorf("expected method %s to be marked allowed, got methods %+v", want, route.Methods)
		}
	}
	// PUT/POST were never declared, accepted, or hinted by the Allow header
	// -- the method swap should still have tried them (candidateMethods is
	// exhaustive regardless of what the spec says) and found them rejected
	// (405 from the fixture server), not simply absent from the results.
	for _, want := range []string{"PUT", "POST"} {
		if !probedSeen[want] {
			t.Errorf("expected %s to have been swap-tested even though the spec never declared it", want)
		}
		if allowedSeen[want] {
			t.Errorf("expected %s to be marked not-allowed (fixture 405s it)", want)
		}
	}

	var idParam, nameParam *Param
	for i := range route.Params {
		switch route.Params[i].Name {
		case "id":
			idParam = &route.Params[i]
		case "name":
			nameParam = &route.Params[i]
		}
	}
	if idParam == nil {
		t.Fatal("expected an \"id\" path param")
	}
	if idParam.Location != LocationPath {
		t.Errorf("expected id param location \"path\", got %q", idParam.Location)
	}
	if !idParam.Flagged {
		t.Error("expected the id-shaped path param to be flagged as an injection point candidate")
	}
	if idParam.Sample != "1" {
		t.Errorf("expected substitutePathParams to have filled in the spec's own sample, got %q", idParam.Sample)
	}
	if nameParam == nil || nameParam.Location != LocationBody {
		t.Fatalf("expected a body \"name\" param from the PATCH requestBody, got %+v", route.Params)
	}

	found := false
	for _, ip := range result.InjectionPoints {
		if ip.Endpoint == "/users/{id}" && ip.Param == "id" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the id param to appear in InjectionPoints, got %+v", result.InjectionPoints)
	}

	if result.Stats.RoutesFound != len(result.Routes) {
		t.Errorf("Stats.RoutesFound (%d) doesn't match len(Routes) (%d)", result.Stats.RoutesFound, len(result.Routes))
	}
}

func TestResolveSpecRoundTrip(t *testing.T) {
	// A target with no reachable spec/GraphQL/crawl surface at all should
	// still return a clean, non-nil Result rather than erroring -- a run
	// against a target with nothing exposed is a normal, expected outcome.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := RunScan(ctx, srv.URL, Options{})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	if result.Schema == nil || result.Schema.Found {
		t.Errorf("expected no spec found, got %+v", result.Schema)
	}
	if result.GraphQL == nil || result.GraphQL.Found {
		t.Errorf("expected no GraphQL endpoint found, got %+v", result.GraphQL)
	}

	// Sanity-check the result still round-trips through JSON cleanly (the
	// shape the API handler actually sends).
	if _, err := json.Marshal(result); err != nil {
		t.Fatalf("marshal result: %v", err)
	}
}
