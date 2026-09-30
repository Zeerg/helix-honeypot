package handler

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	openapi_v2 "github.com/google/gnostic/openapiv2"
)

// SchemaProfile binds a simulated minor version to a pinned upstream release.
// URLs are generated here, never from request data or an operator-supplied URL.
type SchemaProfile struct {
	Version      string
	Release      string
	SchemaURL    string
	EmbeddedPath string
}

// SchemaProfileForVersion accepts 1.25 or v1.25, selecting the v1.25.0 schema.
// A schema describes the wire API; it does not implement release behavior.
func SchemaProfileForVersion(version string) (SchemaProfile, error) {
	version = strings.TrimSpace(version)
	if version == "" {
		version = "v1.37"
	}
	if strings.HasPrefix(version, "1.") {
		version = "v" + version
	}
	minor, err := parseKubernetesVersion(version)
	if err != nil || minor < 19 || minor > 37 || version != fmt.Sprintf("v1.%d", minor) {
		return SchemaProfile{}, fmt.Errorf("unsupported Kubernetes schema profile %q: use v1.19 through v1.37", version)
	}
	release := version + ".0"
	return SchemaProfile{
		Version: version, Release: release,
		SchemaURL:    "https://raw.githubusercontent.com/kubernetes/kubernetes/" + release + "/api/openapi-spec/swagger.json",
		EmbeddedPath: "embedded/openapi/" + version + "_openapi.json.gz",
	}, nil
}

func schemaHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return fmt.Errorf("schema redirects are disabled")
		},
	}
}

// loadOpenAPISchema makes one startup-only download attempt, then uses only an
// exact bundled version. It never substitutes another release's schema.
func loadOpenAPISchema(ctx context.Context, profile SchemaProfile, offline bool, client *http.Client) ([]byte, *openapi_v2.Document, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	var downloadErr error
	if !offline {
		data, err := downloadSchema(ctx, profile, client)
		if err == nil {
			document, validateErr := validateSchema(data)
			if validateErr == nil {
				return data, document, nil
			}
			err = validateErr
		}
		downloadErr = err
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
	}
	compressed, err := embeddedFS.ReadFile(profile.EmbeddedPath)
	if err != nil {
		if offline {
			return nil, nil, fmt.Errorf("no bundled OpenAPI schema for %s; disable schema_offline to download %s", profile.Version, profile.Release)
		}
		return nil, nil, fmt.Errorf("download OpenAPI schema for %s: %w; no matching bundled schema is available", profile.Release, downloadErr)
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, nil, fmt.Errorf("open bundled OpenAPI schema for %s: %w", profile.Version, err)
	}
	defer reader.Close()
	data, err := readSchema(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("read bundled OpenAPI schema for %s: %w", profile.Version, err)
	}
	document, err := validateSchema(data)
	if err != nil {
		return nil, nil, fmt.Errorf("validate bundled OpenAPI schema for %s: %w", profile.Version, err)
	}
	return data, document, nil
}

func downloadSchema(ctx context.Context, profile SchemaProfile, client *http.Client) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, profile.SchemaURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("schema endpoint returned HTTP %d", response.StatusCode)
	}
	if response.ContentLength > maxOpenAPIDocumentBytes {
		return nil, fmt.Errorf("OpenAPI schema exceeds the %d-byte limit", maxOpenAPIDocumentBytes)
	}
	return readSchema(response.Body)
}

func readSchema(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxOpenAPIDocumentBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxOpenAPIDocumentBytes {
		return nil, fmt.Errorf("OpenAPI schema exceeds the %d-byte limit", maxOpenAPIDocumentBytes)
	}
	return data, nil
}

func validateSchema(data []byte) (*openapi_v2.Document, error) {
	var header struct {
		Swagger     string                     `json:"swagger"`
		Paths       map[string]json.RawMessage `json:"paths"`
		Definitions map[string]json.RawMessage `json:"definitions"`
	}
	if err := json.Unmarshal(data, &header); err != nil || header.Swagger != "2.0" || len(header.Paths) == 0 || len(header.Definitions) == 0 {
		return nil, fmt.Errorf("expected an OpenAPI v2 document with paths and definitions")
	}
	document, err := openapi_v2.ParseDocument(data)
	if err != nil {
		return nil, fmt.Errorf("invalid OpenAPI v2 document")
	}
	return document, nil
}
