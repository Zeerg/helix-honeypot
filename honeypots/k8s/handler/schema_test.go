package handler

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const testSchema = `{"swagger":"2.0","info":{"title":"Kubernetes","version":"test"},"paths":{"/api/v1/pods":{"get":{"responses":{"200":{"description":"ok"}}}}},"definitions":{"io.k8s.api.core.v1.Pod":{"type":"object"}}}`

type schemaRoundTripper func(*http.Request) (*http.Response, error)

func (f schemaRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func schemaResponse(r *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: r, ContentLength: int64(len(body))}
}

func TestSchemaProfilesPinOfficialReleaseURLs(t *testing.T) {
	for _, version := range []string{"1.25", "v1.25", " v1.25 "} {
		profile, err := SchemaProfileForVersion(version)
		if err != nil {
			t.Fatal(err)
		}
		if profile.Version != "v1.25" || profile.Release != "v1.25.0" || profile.SchemaURL != "https://raw.githubusercontent.com/kubernetes/kubernetes/v1.25.0/api/openapi-spec/swagger.json" {
			t.Fatalf("unexpected profile: %+v", profile)
		}
	}
	for _, version := range []string{"v1.18", "v1.38", "v1.025", "v1.25.0", "1.25/../../master", "https://localhost/schema"} {
		if _, err := SchemaProfileForVersion(version); err == nil {
			t.Fatalf("accepted unsupported profile %q", version)
		}
	}
}

func TestLoadSchemaDownloadsSelectedRelease(t *testing.T) {
	profile, _ := SchemaProfileForVersion("1.25")
	client := schemaHTTPClient()
	requests := 0
	client.Transport = schemaRoundTripper(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.URL.String() != profile.SchemaURL || r.Method != http.MethodGet {
			t.Fatalf("unexpected download: %s %s", r.Method, r.URL)
		}
		return schemaResponse(r, http.StatusOK, testSchema), nil
	})
	data, _, err := loadOpenAPISchema(context.Background(), profile, false, client)
	if err != nil || string(data) != testSchema || requests != 1 {
		t.Fatalf("download: requests=%d, error=%v; expected downloaded schema", requests, err)
	}
}

func TestSchemaFallbackUsesExactBundledVersion(t *testing.T) {
	client := schemaHTTPClient()
	requests := 0
	client.Transport = schemaRoundTripper(func(r *http.Request) (*http.Response, error) {
		requests++
		return schemaResponse(r, http.StatusServiceUnavailable, "unavailable"), nil
	})
	profile, _ := SchemaProfileForVersion("v1.25")
	downloadFallback, _, err := loadOpenAPISchema(context.Background(), profile, false, client)
	if err != nil || requests != 1 {
		t.Fatalf("matching fallback failed: requests=%d error=%v", requests, err)
	}
	offline, _, err := loadOpenAPISchema(context.Background(), profile, true, client)
	if err != nil || !bytes.Equal(offline, downloadFallback) || requests != 1 {
		t.Fatalf("offline loading made a request or changed the schema: requests=%d error=%v", requests, err)
	}
	otherProfile, _ := SchemaProfileForVersion("v1.27")
	other, _, err := loadOpenAPISchema(context.Background(), otherProfile, true, client)
	if err != nil || bytes.Equal(other, offline) {
		t.Fatalf("1.25 and 1.27 should have different schemas: %v", err)
	}
	unbundled, _ := SchemaProfileForVersion("v1.28")
	if _, _, err := loadOpenAPISchema(context.Background(), unbundled, false, client); err == nil || !strings.Contains(err.Error(), "no matching bundled schema") {
		t.Fatalf("unbundled profile silently substituted a schema: %v", err)
	}
	if _, _, err := loadOpenAPISchema(context.Background(), unbundled, true, client); err == nil || !strings.Contains(err.Error(), "disable schema_offline") {
		t.Fatalf("unbundled offline profile should fail clearly: %v", err)
	}
}

func TestSchemaLoaderRejectsBadResponses(t *testing.T) {
	// 1.28 deliberately has no bundle, so a rejected response must fail startup.
	profile, _ := SchemaProfileForVersion("v1.28")
	for _, scenario := range []string{"404", "malformed", "not-openapi", "oversized-header", "oversized-stream", "redirect"} {
		t.Run(scenario, func(t *testing.T) {
			client := schemaHTTPClient()
			requests := 0
			client.Transport = schemaRoundTripper(func(r *http.Request) (*http.Response, error) {
				requests++
				response := schemaResponse(r, http.StatusOK, testSchema)
				switch scenario {
				case "404":
					response.StatusCode = http.StatusNotFound
				case "malformed":
					response = schemaResponse(r, http.StatusOK, "{")
				case "not-openapi":
					response = schemaResponse(r, http.StatusOK, `{"message":"no schema"}`)
				case "oversized-header":
					response.ContentLength = maxOpenAPIDocumentBytes + 1
				case "oversized-stream":
					response = schemaResponse(r, http.StatusOK, strings.Repeat(" ", maxOpenAPIDocumentBytes+1))
					response.ContentLength = -1
				case "redirect":
					response.StatusCode = http.StatusFound
					response.Header.Set("Location", "https://example.com/untrusted-schema")
				}
				return response, nil
			})
			if _, _, err := loadOpenAPISchema(context.Background(), profile, false, client); err == nil {
				t.Fatal("accepted an invalid schema response")
			}
			if requests != 1 {
				t.Fatalf("made %d requests; want one, without redirects or retries", requests)
			}
		})
	}
}

func TestSchemaStartupCancellationDoesNotFallback(t *testing.T) {
	profile, _ := SchemaProfileForVersion("v1.25")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	client := schemaHTTPClient()
	client.Transport = schemaRoundTripper(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	if _, _, err := loadOpenAPISchema(ctx, profile, false, client); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled startup used the bundled fallback: %v", err)
	}
}
