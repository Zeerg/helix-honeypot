package handler

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	openapi_v2 "github.com/google/gnostic/openapiv2"
	"github.com/labstack/echo/v5"
	"google.golang.org/protobuf/proto"

	"helix-honeypot/model"
)

const maxRequestBody = 64 << 10
const maxListPageBytes = 1 << 20
const maxListPageItems = 100
const maxListLimit = 1000

const headerETag = "ETag"

type apiResource struct {
	Name       string   `json:"name"`
	Singular   string   `json:"singularName"`
	Kind       string   `json:"kind"`
	Namespaced bool     `json:"namespaced"`
	Verbs      []string `json:"verbs"`
	ShortNames []string `json:"shortNames,omitempty"`
}

type groupVersion struct {
	Group   string
	Version string
}

type API struct {
	version            string
	startedAt          time.Time
	resources          map[groupVersion]map[string]apiResource
	store              *objectStore
	openAPIV2JSON      []byte
	openAPIV2JSONGzip  []byte
	openAPIV2ProtoGzip []byte
	openAPIETags       map[string]string
	openAPISlots       chan struct{}
	serverAddress      string
	requestSlots       chan struct{}
	listSlots          chan struct{}
	watchSlots         chan struct{}
}

var apiCatalog = map[groupVersion][]apiResource{
	{"", "v1"}: {
		resource("configmaps", "ConfigMap", true, "cm"),
		resource("endpoints", "Endpoints", true, "ep"),
		resource("events", "Event", true, "ev"),
		resource("namespaces", "Namespace", false, "ns"),
		resource("nodes", "Node", false, "no"),
		resource("persistentvolumeclaims", "PersistentVolumeClaim", true, "pvc"),
		resource("persistentvolumes", "PersistentVolume", false, "pv"),
		resource("pods", "Pod", true, "po"),
		resource("secrets", "Secret", true, "secret"),
		resource("serviceaccounts", "ServiceAccount", true, "sa"),
		resource("services", "Service", true, "svc"),
	},
	{"apps", "v1"}: {
		resource("daemonsets", "DaemonSet", true, "ds"),
		resource("deployments", "Deployment", true, "deploy"),
		resource("replicasets", "ReplicaSet", true, "rs"),
		resource("statefulsets", "StatefulSet", true, "sts"),
	},
	{"autoscaling", "v2"}: {
		resource("horizontalpodautoscalers", "HorizontalPodAutoscaler", true, "hpa"),
	},
	{"autoscaling", "v1"}: {
		resource("horizontalpodautoscalers", "HorizontalPodAutoscaler", true, "hpa"),
	},
	{"batch", "v1"}: {
		resource("cronjobs", "CronJob", true, "cj"),
		resource("jobs", "Job", true, "job"),
	},
	{"certificates.k8s.io", "v1"}: {
		resource("certificatesigningrequests", "CertificateSigningRequest", false, "csr"),
	},
	{"coordination.k8s.io", "v1"}: {
		resource("leases", "Lease", true, "lease"),
	},
	{"discovery.k8s.io", "v1"}: {
		resource("endpointslices", "EndpointSlice", true, "eps"),
	},
	{"events.k8s.io", "v1"}: {
		resource("events", "Event", true, "ev"),
	},
	{"networking.k8s.io", "v1"}: {
		resource("ingressclasses", "IngressClass", false, "ingclass"),
		resource("ingresses", "Ingress", true, "ing"),
		resource("networkpolicies", "NetworkPolicy", true, "netpol"),
	},
	{"policy", "v1"}: {
		resource("poddisruptionbudgets", "PodDisruptionBudget", true, "pdb"),
	},
	{"rbac.authorization.k8s.io", "v1"}: {
		resource("clusterrolebindings", "ClusterRoleBinding", false, "crb"),
		resource("clusterroles", "ClusterRole", false, "role"),
		resource("rolebindings", "RoleBinding", true, "rb"),
		resource("roles", "Role", true, "role"),
	},
	{"storage.k8s.io", "v1"}: {
		resource("csidrivers", "CSIDriver", false, "csidriver"),
		resource("storageclasses", "StorageClass", false, "sc"),
	},
}

func resource(name, kind string, namespaced bool, shortName string) apiResource {
	singular := strings.ToLower(kind)
	return apiResource{
		Name:       name,
		Singular:   singular,
		Kind:       kind,
		Namespaced: namespaced,
		Verbs:      []string{"create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"},
		ShortNames: []string{shortName},
	}
}

// NewAPI creates an isolated in-memory API server. OpenAPI v2 is served only
// for versions for which the repository contains an embedded upstream snapshot.
func NewAPI(cfg *model.Config) (*API, error) {
	if cfg == nil {
		return nil, fmt.Errorf("Kubernetes API configuration is required")
	}
	version := strings.TrimSpace(cfg.K8S.APIVersion)
	if version == "" {
		version = "v1.37"
	}
	minor, err := parseKubernetesVersion(version)
	if err != nil {
		return nil, err
	}
	if minor < 19 || minor > 37 {
		return nil, fmt.Errorf("unsupported Kubernetes API profile %q: supported simulated profiles are v1.19 through v1.37", version)
	}

	api := &API{
		version:      version,
		startedAt:    time.Now().UTC().Truncate(time.Second),
		resources:    make(map[groupVersion]map[string]apiResource, len(apiCatalog)),
		openAPIETags: make(map[string]string),
		openAPISlots: make(chan struct{}, 1),
		requestSlots: make(chan struct{}, 32),
		listSlots:    make(chan struct{}, 4),
		watchSlots:   make(chan struct{}, 8),
	}
	for gv, resources := range apiCatalog {
		byName := make(map[string]apiResource, len(resources))
		for _, item := range resources {
			byName[item.Name] = item
		}
		api.resources[gv] = byName
	}
	api.resources = resourcesForMinor(api.resources, minor)
	api.serverAddress = nodeAddress(cfg.K8S.IPBase, 10) + ":443"
	if len(cfg.K8S.TokenValues) > 128 {
		return nil, fmt.Errorf("Kubernetes honeypot supports at most 128 decoy tokens")
	}
	for _, token := range cfg.K8S.TokenValues {
		if len(token) > 4096 {
			return nil, fmt.Errorf("Kubernetes decoy token values must be 4 KiB or smaller")
		}
	}
	for _, name := range cfg.K8S.TokenNames {
		if name != "" && !validObjectName(name) {
			return nil, fmt.Errorf("Kubernetes decoy secret names must be valid DNS subdomains")
		}
	}
	if minor <= 27 {
		compressedFixture, err := embeddedFS.ReadFile("embedded/openapi/" + version + "_openapi.json.gz")
		if err != nil {
			return nil, fmt.Errorf("OpenAPI v2 fixture for %s is unavailable: %w", version, err)
		}
		reader, err := gzip.NewReader(bytes.NewReader(compressedFixture))
		if err != nil {
			return nil, fmt.Errorf("open compressed OpenAPI v2 fixture for %s: %w", version, err)
		}
		fixture, err := io.ReadAll(io.LimitReader(reader, maxOpenAPIDocumentBytes+1))
		if err != nil {
			reader.Close()
			return nil, fmt.Errorf("read OpenAPI v2 fixture for %s: %w", version, err)
		}
		if err := reader.Close(); err != nil {
			return nil, fmt.Errorf("close OpenAPI v2 fixture for %s: %w", version, err)
		}
		if len(fixture) > maxOpenAPIDocumentBytes {
			return nil, fmt.Errorf("OpenAPI v2 fixture for %s exceeds the configured document limit", version)
		}
		document, err := openapi_v2.ParseDocument(fixture)
		if err != nil {
			return nil, fmt.Errorf("OpenAPI v2 fixture for %s is invalid: %w", version, err)
		}
		binaryDoc, err := proto.Marshal(document)
		if err != nil {
			return nil, fmt.Errorf("encode OpenAPI v2 fixture for %s: %w", version, err)
		}
		var compressed bytes.Buffer
		zw := gzip.NewWriter(&compressed)
		if _, err := zw.Write(binaryDoc); err != nil {
			return nil, fmt.Errorf("compress OpenAPI v2 fixture for %s: %w", version, err)
		}
		if err := zw.Close(); err != nil {
			return nil, fmt.Errorf("finish OpenAPI v2 fixture for %s: %w", version, err)
		}
		api.openAPIV2JSON = fixture
		api.openAPIV2JSONGzip = compressedFixture
		api.openAPIV2ProtoGzip = compressed.Bytes()
		api.openAPIETags["json"] = etag(fixture)
		api.openAPIETags["json-gzip"] = etag(compressedFixture)
		api.openAPIETags["protobuf"] = etag(binaryDoc)
		api.openAPIETags["protobuf-gzip"] = etag(api.openAPIV2ProtoGzip)
	}
	api.store = newObjectStore()
	api.seed(cfg)
	return api, nil
}

const maxOpenAPIDocumentBytes = 8 << 20

func etag(data []byte) string {
	digest := sha256.Sum256(data)
	return fmt.Sprintf("\"%X\"", digest)
}

func resourcesForMinor(current map[groupVersion]map[string]apiResource, minor int) map[groupVersion]map[string]apiResource {
	resources := make(map[groupVersion]map[string]apiResource, len(current)+3)
	for gv, items := range current {
		copyOfItems := make(map[string]apiResource, len(items))
		for name, item := range items {
			copyOfItems[name] = item
		}
		resources[gv] = copyOfItems
	}
	if minor < 21 {
		moveResource(resources, groupVersion{"batch", "v1"}, groupVersion{"batch", "v1beta1"}, "cronjobs")
		moveResource(resources, groupVersion{"discovery.k8s.io", "v1"}, groupVersion{"discovery.k8s.io", "v1beta1"}, "endpointslices")
		moveResource(resources, groupVersion{"policy", "v1"}, groupVersion{"policy", "v1beta1"}, "poddisruptionbudgets")
	}
	if minor >= 21 && minor < 25 {
		copyResource(resources, groupVersion{"batch", "v1"}, groupVersion{"batch", "v1beta1"}, "cronjobs")
		copyResource(resources, groupVersion{"discovery.k8s.io", "v1"}, groupVersion{"discovery.k8s.io", "v1beta1"}, "endpointslices")
		copyResource(resources, groupVersion{"policy", "v1"}, groupVersion{"policy", "v1beta1"}, "poddisruptionbudgets")
	}
	if minor < 23 {
		moveResource(resources, groupVersion{"autoscaling", "v2"}, groupVersion{"autoscaling", "v2beta2"}, "horizontalpodautoscalers")
	} else if minor < 26 {
		copyResource(resources, groupVersion{"autoscaling", "v2"}, groupVersion{"autoscaling", "v2beta2"}, "horizontalpodautoscalers")
	}
	for gv, items := range resources {
		if len(items) == 0 {
			delete(resources, gv)
		}
	}
	return resources
}

func moveResource(resources map[groupVersion]map[string]apiResource, source, destination groupVersion, name string) {
	copyResource(resources, source, destination, name)
	delete(resources[source], name)
}

func copyResource(resources map[groupVersion]map[string]apiResource, source, destination groupVersion, name string) {
	item, ok := resources[source][name]
	if !ok {
		return
	}
	if resources[destination] == nil {
		resources[destination] = make(map[string]apiResource)
	}
	resources[destination][name] = item
}

func parseKubernetesVersion(value string) (int, error) {
	if !strings.HasPrefix(value, "v1.") {
		return 0, fmt.Errorf("invalid Kubernetes API profile %q: expected v1.MINOR", value)
	}
	minor, err := strconv.Atoi(strings.TrimPrefix(value, "v1."))
	if err != nil || minor < 0 {
		return 0, fmt.Errorf("invalid Kubernetes API profile %q: expected v1.MINOR", value)
	}
	return minor, nil
}

// ServeHTTP routes requests through a deliberately bounded subset of the
// Kubernetes API. State is local to this API instance and never reaches a cluster.
func (a *API) ServeHTTP(c *echo.Context) error {
	select {
	case a.requestSlots <- struct{}{}:
		defer func() { <-a.requestSlots }()
	default:
		return a.status(c, http.StatusTooManyRequests, "TooManyRequests", "the simulated API server is at capacity", "")
	}
	r := c.Request()
	switch r.URL.Path {
	case "/healthz", "/livez", "/readyz":
		return c.String(http.StatusOK, "ok")
	case "/metrics":
		c.Response().Header().Set(echo.HeaderContentType, "text/plain; version=0.0.4; charset=utf-8")
		return c.String(http.StatusOK, "# HELP apiserver_request_total Total simulated API requests.\n# TYPE apiserver_request_total counter\napiserver_request_total 1\n")
	case "/version":
		return c.JSON(http.StatusOK, a.versionInfo())
	case "/openapi/v2":
		return a.serveOpenAPIV2(c)
	case "/openapi/v3", "/openapi/v3/":
		return a.status(c, http.StatusNotFound, "NotFound", "OpenAPI v3 is unavailable for the configured simulated profile; this repository contains OpenAPI v2 snapshots only through v1.27", "")
	case "/":
		return c.JSON(http.StatusOK, a.rootDiscovery())
	case "/api":
		return c.JSON(http.StatusOK, map[string]any{
			"kind": "APIVersions", "apiVersion": "v1", "versions": []string{"v1"},
			"serverAddressByClientCIDRs": []map[string]string{{"clientCIDR": "0.0.0.0/0", "serverAddress": a.serverAddress}},
		})
	case "/api/v1":
		return c.JSON(http.StatusOK, a.resourceList(groupVersion{"", "v1"}))
	case "/apis":
		return c.JSON(http.StatusOK, a.apiGroupList())
	}

	parts := splitPath(r.URL.Path)
	if len(parts) == 2 && parts[0] == "apis" {
		return a.serveGroup(c, parts[1])
	}
	if len(parts) == 3 && parts[0] == "apis" {
		return a.serveGroupVersion(c, groupVersion{parts[1], parts[2]})
	}
	if len(parts) >= 2 && parts[0] == "apis" {
		if len(parts) < 3 {
			return a.notFound(c)
		}
		return a.serveResourcePath(c, groupVersion{parts[1], parts[2]}, parts[3:])
	}
	if len(parts) >= 2 && parts[0] == "api" {
		if parts[1] != "v1" {
			return a.status(c, http.StatusNotFound, "NotFound", "the requested core API version is not served", "")
		}
		if len(parts) == 2 {
			return c.JSON(http.StatusOK, a.resourceList(groupVersion{"", "v1"}))
		}
		return a.serveResourcePath(c, groupVersion{"", "v1"}, parts[2:])
	}
	return a.notFound(c)
}

func splitPath(raw string) []string {
	clean := strings.Trim(path.Clean(raw), "/")
	if clean == "." || clean == "" {
		return nil
	}
	return strings.Split(clean, "/")
}

func (a *API) versionInfo() map[string]string {
	commit := sha256.Sum256([]byte("helix-honeypot/" + a.version))
	return map[string]string{
		"major": "1", "minor": strings.TrimPrefix(a.version, "v1."),
		"gitVersion": a.version + ".0", "gitCommit": fmt.Sprintf("%x", commit[:20]),
		"gitTreeState": "clean", "buildDate": a.startedAt.Format(time.RFC3339),
		"goVersion": runtime.Version(), "compiler": runtime.Compiler,
		"platform": runtime.GOOS + "/" + runtime.GOARCH,
	}
}

func (a *API) rootDiscovery() map[string]any {
	paths := []string{"/api", "/api/v1", "/apis", "/version", "/healthz", "/livez", "/readyz"}
	for gv := range a.resources {
		if gv.Group != "" {
			paths = append(paths, "/apis/"+gv.Group, "/apis/"+gv.Group+"/"+gv.Version)
		}
	}
	if len(a.openAPIV2JSON) > 0 {
		paths = append(paths, "/openapi/v2")
	}
	sort.Strings(paths)
	paths = compactStrings(paths)
	return map[string]any{"paths": paths}
}

func compactStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

func preferredAPIVersion(versions []string) string {
	preferred := versions[len(versions)-1]
	preferredMajor := -1
	for _, version := range versions {
		if !strings.HasPrefix(version, "v") {
			continue
		}
		major, err := strconv.Atoi(strings.TrimPrefix(version, "v"))
		if err == nil && major > preferredMajor {
			preferred = version
			preferredMajor = major
		}
	}
	return preferred
}

func (a *API) apiGroupList() map[string]any {
	groups := make(map[string][]string)
	for gv := range a.resources {
		if gv.Group != "" {
			groups[gv.Group] = append(groups[gv.Group], gv.Version)
		}
	}
	groupNames := make([]string, 0, len(groups))
	for name := range groups {
		groupNames = append(groupNames, name)
	}
	sort.Strings(groupNames)
	out := make([]map[string]any, 0, len(groupNames))
	for _, name := range groupNames {
		versions := groups[name]
		sort.Strings(versions)
		versionEntries := make([]map[string]string, 0, len(versions))
		for _, version := range versions {
			versionEntries = append(versionEntries, map[string]string{"groupVersion": name + "/" + version, "version": version})
		}
		preferred := preferredAPIVersion(versions)
		out = append(out, map[string]any{
			"name": name, "versions": versionEntries,
			"preferredVersion": map[string]string{"groupVersion": name + "/" + preferred, "version": preferred},
		})
	}
	return map[string]any{"kind": "APIGroupList", "apiVersion": "v1", "groups": out}
}

func (a *API) serveGroup(c *echo.Context, group string) error {
	versions := make([]string, 0)
	for gv := range a.resources {
		if gv.Group == group {
			versions = append(versions, gv.Version)
		}
	}
	if len(versions) == 0 {
		return a.notFound(c)
	}
	sort.Strings(versions)
	entries := make([]map[string]string, 0, len(versions))
	for _, version := range versions {
		entries = append(entries, map[string]string{"groupVersion": group + "/" + version, "version": version})
	}
	preferred := preferredAPIVersion(versions)
	return c.JSON(http.StatusOK, map[string]any{
		"kind": "APIGroup", "apiVersion": "v1", "name": group, "versions": entries,
		"preferredVersion": map[string]string{"groupVersion": group + "/" + preferred, "version": preferred},
	})
}

func (a *API) serveGroupVersion(c *echo.Context, gv groupVersion) error {
	if _, ok := a.resources[gv]; !ok {
		return a.notFound(c)
	}
	return c.JSON(http.StatusOK, a.resourceList(gv))
}

func (a *API) resourceList(gv groupVersion) map[string]any {
	resources := make([]apiResource, 0, len(a.resources[gv]))
	for _, resource := range a.resources[gv] {
		resources = append(resources, resource)
	}
	sort.Slice(resources, func(i, j int) bool { return resources[i].Name < resources[j].Name })
	groupVersionName := gv.Version
	if gv.Group != "" {
		groupVersionName = gv.Group + "/" + gv.Version
	}
	return map[string]any{"kind": "APIResourceList", "apiVersion": "v1", "groupVersion": groupVersionName, "resources": resources}
}

func (a *API) serveOpenAPIV2(c *echo.Context) error {
	if len(a.openAPIV2JSON) == 0 {
		return a.status(c, http.StatusNotFound, "NotFound", "OpenAPI v2 fixture is unavailable for simulated profile "+a.version+"; embedded OpenAPI v2 snapshots cover v1.19 through v1.27", "")
	}
	select {
	case a.openAPISlots <- struct{}{}:
		defer func() { <-a.openAPISlots }()
	default:
		return a.capacityError(c)
	}
	protobufMediaType := "application/com.github.proto-openapi.spec.v2@v1.0+protobuf"
	accept := strings.TrimSpace(c.Request().Header.Get(echo.HeaderAccept))
	protobufQuality := mediaTypeQuality(accept, protobufMediaType)
	jsonQuality := mediaTypeQuality(accept, "application/json")
	if accept == "" {
		jsonQuality = 1
	}
	if protobufQuality == 0 && jsonQuality == 0 {
		return a.status(c, http.StatusNotAcceptable, "NotAcceptable", "OpenAPI v2 supports application/json and protobuf responses", "")
	}
	protobuf := protobufQuality > jsonQuality
	encodingGzip := acceptsGzip(c.Request().Header.Get(echo.HeaderAcceptEncoding))
	representation := "json"
	contentType := "application/json"
	payload := a.openAPIV2JSON
	if protobuf {
		representation = "protobuf"
		contentType = protobufMediaType
		if encodingGzip {
			representation += "-gzip"
			payload = a.openAPIV2ProtoGzip
		} else {
			reader, err := gzip.NewReader(bytes.NewReader(a.openAPIV2ProtoGzip))
			if err != nil {
				return a.status(c, http.StatusInternalServerError, "InternalError", "the simulated OpenAPI v2 document is unavailable", "")
			}
			payload, err = io.ReadAll(io.LimitReader(reader, maxOpenAPIDocumentBytes+1))
			reader.Close()
			if err != nil || len(payload) > maxOpenAPIDocumentBytes {
				return a.status(c, http.StatusInternalServerError, "InternalError", "the simulated OpenAPI v2 document is unavailable", "")
			}
		}
	} else if encodingGzip {
		representation += "-gzip"
		payload = a.openAPIV2JSONGzip
	}
	tag := a.openAPIETags[representation]
	if matchesETag(c.Request().Header.Get("If-None-Match"), tag) {
		c.Response().Header().Set(headerETag, tag)
		return c.NoContent(http.StatusNotModified)
	}
	c.Response().Header().Set(headerETag, tag)
	c.Response().Header().Set(echo.HeaderVary, "Accept, Accept-Encoding")
	c.Response().Header().Set(echo.HeaderCacheControl, "public, max-age=0, must-revalidate")
	c.Response().Header().Set(echo.HeaderContentType, contentType)
	if strings.HasSuffix(representation, "-gzip") {
		c.Response().Header().Set(echo.HeaderContentEncoding, "gzip")
	}
	return c.Blob(http.StatusOK, contentType, payload)
}

func acceptsGzip(header string) bool {
	wildcardQuality := 0.0
	for _, encoding := range strings.Split(header, ",") {
		parts := strings.Split(strings.TrimSpace(encoding), ";")
		name := strings.ToLower(strings.TrimSpace(parts[0]))
		quality := 1.0
		for _, parameter := range parts[1:] {
			parameter = strings.TrimSpace(parameter)
			if strings.HasPrefix(parameter, "q=") {
				parsed, err := strconv.ParseFloat(strings.TrimPrefix(parameter, "q="), 64)
				if err != nil || parsed < 0 || parsed > 1 {
					quality = 0
				} else {
					quality = parsed
				}
			}
		}
		if name == "*" {
			wildcardQuality = quality
			continue
		}
		if name == "gzip" {
			return quality > 0
		}
	}
	return wildcardQuality > 0
}

func mediaTypeQuality(header, wanted string) float64 {
	if strings.TrimSpace(header) == "" {
		return 0
	}
	quality := 0.0
	for _, item := range strings.Split(header, ",") {
		parts := strings.Split(strings.TrimSpace(item), ";")
		mediaType := strings.ToLower(strings.TrimSpace(parts[0]))
		itemQuality := 1.0
		for _, parameter := range parts[1:] {
			parameter = strings.TrimSpace(parameter)
			if strings.HasPrefix(parameter, "q=") {
				parsed, err := strconv.ParseFloat(strings.TrimPrefix(parameter, "q="), 64)
				if err != nil || parsed < 0 || parsed > 1 {
					itemQuality = 0
				} else {
					itemQuality = parsed
				}
			}
		}
		matches := mediaType == wanted || mediaType == "*/*" || mediaType == "application/*" && strings.HasPrefix(wanted, "application/")
		if matches && itemQuality > quality {
			quality = itemQuality
		}
	}
	return quality
}

func matchesETag(header, expected string) bool {
	for _, candidate := range strings.Split(header, ",") {
		if strings.TrimSpace(candidate) == "*" || strings.TrimSpace(candidate) == expected {
			return true
		}
	}
	return false
}

func (a *API) serveResourcePath(c *echo.Context, gv groupVersion, parts []string) error {
	if len(parts) == 0 {
		return a.notFound(c)
	}
	var namespace, resourceName, name string
	if len(parts) >= 3 && parts[0] == "namespaces" {
		namespace, resourceName = parts[1], parts[2]
		if len(parts) > 3 {
			name = parts[3]
		}
		if len(parts) > 4 {
			return a.status(c, http.StatusNotFound, "NotFound", "subresources are not modeled by this simulated API", "")
		}
	} else {
		resourceName = parts[0]
		if len(parts) > 1 {
			name = parts[1]
		}
		if len(parts) > 2 {
			return a.status(c, http.StatusNotFound, "NotFound", "subresources are not modeled by this simulated API", "")
		}
	}
	description, ok := a.resources[gv][resourceName]
	if !ok {
		return a.notFound(c)
	}
	if !description.Namespaced && namespace != "" {
		return a.status(c, http.StatusNotFound, "NotFound", "the requested resource is not namespaced", "")
	}
	if description.Namespaced && namespace == "" && name != "" {
		return a.status(c, http.StatusNotFound, "NotFound", "named namespaced resources require a namespace in the request path", name)
	}
	if watch := c.QueryParam("watch"); watch == "true" || watch == "1" {
		if name != "" || c.Request().Method != http.MethodGet {
			return a.status(c, http.StatusBadRequest, "BadRequest", "watch is supported only on resource collections", "")
		}
		return a.watch(c, gv, namespace, resourceName)
	}
	switch c.Request().Method {
	case http.MethodGet:
		if name == "" {
			return a.list(c, gv, namespace, description)
		}
		object, ok := a.store.get(objectKey{gv.Group, gv.Version, resourceName, namespace, name})
		if !ok {
			return a.status(c, http.StatusNotFound, "NotFound", fmt.Sprintf("%s %q not found", strings.ToLower(description.Kind), name), name)
		}
		return c.JSON(http.StatusOK, object)
	case http.MethodPost:
		if name != "" {
			return a.status(c, http.StatusMethodNotAllowed, "MethodNotAllowed", "POST is supported only on resource collections", "")
		}
		return a.create(c, gv, namespace, description)
	case http.MethodPut:
		if name == "" {
			return a.status(c, http.StatusMethodNotAllowed, "MethodNotAllowed", "PUT requires a resource name", "")
		}
		return a.update(c, gv, namespace, resourceName, name, description)
	case http.MethodPatch:
		if name == "" {
			return a.status(c, http.StatusMethodNotAllowed, "MethodNotAllowed", "PATCH requires a resource name", "")
		}
		return a.patch(c, gv, namespace, resourceName, name, description)
	case http.MethodDelete:
		if name == "" {
			return a.deleteCollection(c, gv, namespace, description)
		}
		return a.delete(c, gv, namespace, resourceName, name, description)
	default:
		c.Response().Header().Set(echo.HeaderAllow, "GET, POST, PUT, PATCH, DELETE")
		return a.status(c, http.StatusMethodNotAllowed, "MethodNotAllowed", "method is not supported for this resource", "")
	}
}

func (a *API) list(c *echo.Context, gv groupVersion, namespace string, description apiResource) error {
	select {
	case a.listSlots <- struct{}{}:
		defer func() { <-a.listSlots }()
	default:
		return a.capacityError(c)
	}
	if !validFieldSelector(c.QueryParam("fieldSelector")) {
		return a.status(c, http.StatusBadRequest, "BadRequest", "fieldSelector is invalid", "")
	}
	resourceVersion := a.store.resourceVersion()
	limit, err := parseListLimit(c.QueryParam("limit"))
	if err != nil {
		return a.status(c, http.StatusBadRequest, "BadRequest", err.Error(), "")
	}
	selectorMaterial := strings.Join([]string{gv.Group, gv.Version, namespace, description.Name, c.QueryParam("labelSelector"), c.QueryParam("fieldSelector")}, "\x00")
	selectorDigest := sha256.Sum256([]byte(selectorMaterial))
	selectorIdentity := fmt.Sprintf("%x", selectorDigest[:])
	offset, err := parseContinue(c.QueryParam("continue"), resourceVersion, selectorIdentity)
	if err != nil {
		code, reason := http.StatusBadRequest, "BadRequest"
		if strings.Contains(err.Error(), "no longer valid") {
			code, reason = http.StatusGone, "Expired"
		}
		return a.status(c, code, reason, err.Error(), "")
	}
	labels, _ := parseSelector(c.QueryParam("labelSelector"))
	fields, _ := parseSelector(c.QueryParam("fieldSelector"))
	items, total, nextOffset, err := a.store.listPage(gv, namespace, description.Name, labels, fields, offset, limit)
	if err != nil {
		return a.status(c, http.StatusBadRequest, "BadRequest", err.Error(), "")
	}
	if requestedVersion := c.QueryParam("resourceVersion"); requestedVersion != "" && requestedVersion != "0" {
		if requestedVersion != resourceVersion {
			return a.status(c, http.StatusGone, "Expired", "the requested resourceVersion is not available in the simulated store", "")
		}
	}
	continueToken := ""
	var remainingItemCount *int
	if nextOffset < total {
		continueToken = makeContinueToken(resourceVersion, nextOffset, selectorIdentity)
		remaining := total - nextOffset
		remainingItemCount = &remaining
	}
	list := map[string]any{
		"apiVersion": apiVersionFor(gv), "kind": description.Kind + "List",
		"metadata": map[string]any{"resourceVersion": resourceVersion, "continue": continueToken},
		"items":    items,
	}
	if remainingItemCount != nil {
		objectMap(list["metadata"])["remainingItemCount"] = *remainingItemCount
	}
	return c.JSON(http.StatusOK, list)
}

func apiVersionFor(gv groupVersion) string {
	if gv.Group == "" {
		return gv.Version
	}
	return gv.Group + "/" + gv.Version
}

func (a *API) create(c *echo.Context, gv groupVersion, namespace string, description apiResource) error {
	if description.Namespaced && namespace == "" {
		return a.status(c, http.StatusBadRequest, "BadRequest", "namespaced resources must be created through a namespace path", "")
	}
	object, err := decodeObject(c)
	if err != nil {
		return a.bodyError(c, err, "")
	}
	if err := validateObjectShape(object, gv, description, false); err != nil {
		return a.status(c, http.StatusUnprocessableEntity, "Invalid", err.Error(), "")
	}
	metadata := objectMap(object["metadata"])
	name, _ := metadata["name"].(string)
	if namespace != "" {
		if got, _ := metadata["namespace"].(string); got != "" && got != namespace {
			return a.status(c, http.StatusBadRequest, "BadRequest", "metadata.namespace must match the request namespace", name)
		}
		metadata["namespace"] = namespace
	} else if description.Namespaced && resourceNameNeedsNamespace(description.Name) {
		if ns, _ := metadata["namespace"].(string); ns == "" {
			return a.status(c, http.StatusBadRequest, "BadRequest", "metadata.namespace is required for this resource", name)
		}
		namespace, _ = metadata["namespace"].(string)
	}
	if description.Name != "namespaces" && description.Namespaced && !a.store.namespaceExists(namespace) {
		return a.status(c, http.StatusNotFound, "NotFound", fmt.Sprintf("namespaces %q not found", namespace), namespace)
	}
	if name == "" {
		generateName, _ := metadata["generateName"].(string)
		if generateName == "" {
			return a.status(c, http.StatusUnprocessableEntity, "Invalid", "metadata.name or metadata.generateName is required", "")
		}
		name, err = a.store.nextName(generateName)
		if err != nil {
			return a.status(c, http.StatusUnprocessableEntity, "Invalid", err.Error(), "")
		}
	}
	object["apiVersion"] = apiVersionFor(gv)
	object["kind"] = description.Kind
	metadata["name"] = name
	metadata["uid"] = stableUID(apiVersionFor(gv) + "/" + namespace + "/" + description.Name + "/" + name + "/" + strconv.FormatInt(time.Now().UnixNano(), 10))
	metadata["creationTimestamp"] = time.Now().UTC().Format(time.RFC3339)
	object["metadata"] = metadata
	if err := a.store.put(objectKey{gv.Group, gv.Version, description.Name, namespace, name}, object, "ADDED"); err != nil {
		if errors.Is(err, errObjectAlreadyExists) {
			return a.status(c, http.StatusConflict, "AlreadyExists", fmt.Sprintf("%s %q already exists", strings.ToLower(description.Kind), name), name)
		}
		return a.capacityError(c)
	}
	c.Response().Header().Set(echo.HeaderLocation, c.Request().URL.Path+"/"+name)
	return c.JSON(http.StatusCreated, object)
}

func resourceNameNeedsNamespace(name string) bool { return name != "namespaces" }

func (a *API) update(c *echo.Context, gv groupVersion, namespace, resourceName, name string, description apiResource) error {
	object, err := decodeObject(c)
	if err != nil {
		return a.bodyError(c, err, name)
	}
	if err := validateObjectShape(object, gv, description, false); err != nil {
		return a.status(c, http.StatusUnprocessableEntity, "Invalid", err.Error(), name)
	}
	metadata := objectMap(object["metadata"])
	requestedName, _ := metadata["name"].(string)
	if requestedName == "" {
		return a.status(c, http.StatusUnprocessableEntity, "Invalid", "metadata.name is required for update", name)
	}
	if requestedName != name {
		return a.status(c, http.StatusBadRequest, "BadRequest", "metadata.name must match the request path", name)
	}
	if namespace != "" {
		if requestedNamespace, _ := metadata["namespace"].(string); requestedNamespace != "" && requestedNamespace != namespace {
			return a.status(c, http.StatusBadRequest, "BadRequest", "metadata.namespace must match the request namespace", name)
		}
		metadata["namespace"] = namespace
	}
	key := objectKey{gv.Group, gv.Version, resourceName, namespace, name}
	previous, exists := a.store.get(key)
	if !exists {
		return a.status(c, http.StatusNotFound, "NotFound", fmt.Sprintf("%s %q not found", strings.ToLower(description.Kind), name), name)
	}
	previousMetadata := objectMap(previous["metadata"])
	metadata["name"] = name
	metadata["uid"] = previousMetadata["uid"]
	metadata["creationTimestamp"] = previousMetadata["creationTimestamp"]
	object["apiVersion"] = apiVersionFor(gv)
	object["kind"] = description.Kind
	object["metadata"] = metadata
	if err := a.store.put(key, object, "MODIFIED"); err != nil {
		return a.capacityError(c)
	}
	return c.JSON(http.StatusOK, object)
}

func (a *API) patch(c *echo.Context, gv groupVersion, namespace, resourceName, name string, description apiResource) error {
	key := objectKey{gv.Group, gv.Version, resourceName, namespace, name}
	current, exists := a.store.get(key)
	if !exists {
		return a.status(c, http.StatusNotFound, "NotFound", fmt.Sprintf("%s %q not found", strings.ToLower(description.Kind), name), name)
	}
	patch, err := decodeObject(c)
	if err != nil {
		return a.bodyError(c, err, name)
	}
	if err := validateObjectShape(patch, gv, description, true); err != nil {
		return a.status(c, http.StatusUnprocessableEntity, "Invalid", err.Error(), name)
	}
	mergeObject(current, patch)
	metadata := objectMap(current["metadata"])
	metadata["name"] = name
	current["apiVersion"] = apiVersionFor(gv)
	current["kind"] = description.Kind
	current["metadata"] = metadata
	if err := a.store.put(key, current, "MODIFIED"); err != nil {
		return a.capacityError(c)
	}
	return c.JSON(http.StatusOK, current)
}

func (a *API) delete(c *echo.Context, gv groupVersion, namespace, resourceName, name string, description apiResource) error {
	key := objectKey{gv.Group, gv.Version, resourceName, namespace, name}
	if _, ok := a.store.delete(key); !ok {
		return a.status(c, http.StatusNotFound, "NotFound", fmt.Sprintf("%s %q not found", strings.ToLower(description.Kind), name), name)
	}
	return c.JSON(http.StatusOK, map[string]any{
		"apiVersion": "v1", "kind": "Status", "status": "Success", "code": http.StatusOK,
		"details": map[string]string{"name": name, "kind": strings.ToLower(description.Kind)},
	})
}

func (a *API) deleteCollection(c *echo.Context, gv groupVersion, namespace string, description apiResource) error {
	select {
	case a.listSlots <- struct{}{}:
		defer func() { <-a.listSlots }()
	default:
		return a.capacityError(c)
	}
	if _, valid := parseSelector(c.QueryParam("labelSelector")); !valid {
		return a.status(c, http.StatusBadRequest, "BadRequest", "labelSelector is invalid", "")
	}
	if !validFieldSelector(c.QueryParam("fieldSelector")) {
		return a.status(c, http.StatusBadRequest, "BadRequest", "fieldSelector is invalid", "")
	}
	deleted := a.store.deleteMatching(gv, namespace, description.Name, c.QueryParam("labelSelector"), c.QueryParam("fieldSelector"))
	return c.JSON(http.StatusOK, map[string]any{
		"apiVersion": "v1", "kind": "Status", "status": "Success", "code": http.StatusOK,
		"details": map[string]any{"group": gv.Group, "kind": strings.ToLower(description.Kind), "causes": []any{}, "deleted": deleted},
	})
}

func (a *API) watch(c *echo.Context, gv groupVersion, namespace, resource string) error {
	select {
	case a.watchSlots <- struct{}{}:
		defer func() { <-a.watchSlots }()
	default:
		return a.capacityError(c)
	}
	if _, valid := parseSelector(c.QueryParam("labelSelector")); !valid {
		return a.status(c, http.StatusBadRequest, "BadRequest", "labelSelector is invalid", "")
	}
	if !validFieldSelector(c.QueryParam("fieldSelector")) {
		return a.status(c, http.StatusBadRequest, "BadRequest", "fieldSelector is invalid", "")
	}
	seconds := 5
	if raw := c.QueryParam("timeoutSeconds"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			return a.status(c, http.StatusBadRequest, "BadRequest", "timeoutSeconds must be a non-negative integer", "")
		}
		if parsed > 0 && parsed < seconds {
			seconds = parsed
		}
	}
	if seconds == 0 {
		seconds = 5
	}
	labels, _ := parseSelector(c.QueryParam("labelSelector"))
	fields, _ := parseSelector(c.QueryParam("fieldSelector"))
	watcher := a.store.watch(gv, namespace, resource, labels, fields)
	defer a.store.unwatch(watcher)
	c.Response().Header().Set(echo.HeaderContentType, "application/json;stream=watch")
	c.Response().Header().Set(echo.HeaderCacheControl, "no-cache")
	c.Response().WriteHeader(http.StatusOK)
	flusher, canFlush := c.Response().(http.Flusher)
	if !canFlush {
		return nil
	}
	flusher.Flush()
	timer := time.NewTimer(time.Duration(seconds) * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-c.Request().Context().Done():
			return nil
		case event, ok := <-watcher.ch:
			if !ok {
				return nil
			}
			if err := json.NewEncoder(c.Response()).Encode(event); err != nil {
				return nil
			}
			flusher.Flush()
		case <-timer.C:
			return nil
		}
	}
}

func decodeObject(c *echo.Context) (map[string]any, error) {
	body := c.Request().Body
	if body == nil {
		return nil, fmt.Errorf("request body is required")
	}
	data, err := io.ReadAll(io.LimitReader(body, maxRequestBody+1))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, errRequestTooLarge
		}
		return nil, fmt.Errorf("unable to read request body")
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("request body is required")
	}
	if len(data) > maxRequestBody {
		return nil, errRequestTooLarge
	}
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, fmt.Errorf("request body must be a JSON object")
	}
	if object == nil {
		return nil, fmt.Errorf("request body must be a JSON object")
	}
	return object, nil
}

var errRequestTooLarge = errors.New("request body exceeds the 64 KiB limit")

func (a *API) bodyError(c *echo.Context, err error, name string) error {
	if errors.Is(err, errRequestTooLarge) {
		return a.status(c, http.StatusRequestEntityTooLarge, "RequestEntityTooLarge", err.Error(), name)
	}
	return a.status(c, http.StatusBadRequest, "BadRequest", err.Error(), name)
}

func (a *API) capacityError(c *echo.Context) error {
	return a.status(c, http.StatusTooManyRequests, "TooManyRequests", "the simulated API object store is at capacity", "")
}

func validateObjectShape(object map[string]any, gv groupVersion, description apiResource, partial bool) error {
	if kind, exists := object["kind"]; exists {
		actual, ok := kind.(string)
		if !ok || actual != description.Kind {
			return fmt.Errorf("kind must be %q", description.Kind)
		}
	}
	if version, exists := object["apiVersion"]; exists {
		actual, ok := version.(string)
		if !ok || actual != apiVersionFor(gv) {
			return fmt.Errorf("apiVersion must be %q", apiVersionFor(gv))
		}
	}
	allowed := map[string]bool{
		"apiVersion": true, "kind": true, "metadata": true,
		"spec": true, "status": true,
	}
	switch description.Kind {
	case "Secret":
		for _, key := range []string{"data", "stringData", "type", "immutable"} {
			allowed[key] = true
		}
	case "ConfigMap":
		for _, key := range []string{"data", "binaryData", "immutable"} {
			allowed[key] = true
		}
	case "Role", "ClusterRole":
		allowed["rules"] = true
	case "RoleBinding", "ClusterRoleBinding":
		allowed["subjects"], allowed["roleRef"] = true, true
	case "StorageClass":
		for _, key := range []string{"provisioner", "parameters", "reclaimPolicy", "allowVolumeExpansion", "mountOptions", "volumeBindingMode", "allowedTopologies"} {
			allowed[key] = true
		}
	case "Event":
		for _, key := range []string{"type", "reason", "message", "source", "involvedObject", "action", "reportingComponent", "reportingInstance", "series", "regarding", "related", "deprecatedSource", "deprecatedFirstTimestamp", "deprecatedLastTimestamp", "deprecatedCount", "firstTimestamp", "lastTimestamp", "count", "source"} {
			allowed[key] = true
		}
	case "Endpoints":
		allowed["subsets"] = true
	case "ServiceAccount":
		allowed["secrets"], allowed["imagePullSecrets"], allowed["automountServiceAccountToken"] = true, true, true
	case "CertificateSigningRequest":
		allowed["spec"] = true
	case "EndpointSlice":
		allowed["addressType"], allowed["endpoints"], allowed["ports"] = true, true, true
	case "IngressClass":
		allowed["spec"] = true
	}
	for key := range object {
		if !allowed[key] {
			return fmt.Errorf("field %q is not supported for %s", key, description.Kind)
		}
	}
	for _, key := range []string{"spec", "status"} {
		if value, exists := object[key]; exists {
			if _, ok := value.(map[string]any); !ok {
				return fmt.Errorf("%s must be an object", key)
			}
		}
	}
	if rawMetadata, exists := object["metadata"]; exists {
		metadata, ok := rawMetadata.(map[string]any)
		if !ok {
			return fmt.Errorf("metadata must be an object")
		}
		allowedMetadata := map[string]bool{
			"name": true, "generateName": true, "namespace": true, "labels": true, "annotations": true,
			"uid": true, "resourceVersion": true, "creationTimestamp": true, "deletionTimestamp": true,
			"deletionGracePeriodSeconds": true, "ownerReferences": true, "finalizers": true, "managedFields": true,
		}
		for key := range metadata {
			if !allowedMetadata[key] {
				return fmt.Errorf("metadata field %q is not supported", key)
			}
		}
		for _, key := range []string{"name", "generateName", "namespace"} {
			if value, exists := metadata[key]; exists {
				text, ok := value.(string)
				if !ok {
					return fmt.Errorf("metadata.%s must be a string", key)
				}
				if key == "name" && text != "" && !validObjectName(text) {
					return fmt.Errorf("metadata.%s must be a valid DNS subdomain", key)
				}
				if key == "generateName" && text != "" && !validObjectName(strings.TrimSuffix(text, "-")) {
					return fmt.Errorf("metadata.%s must be a valid DNS subdomain prefix", key)
				}
				if key == "namespace" && text != "" && !validNamespaceName(text) {
					return fmt.Errorf("metadata.namespace must be a valid DNS label")
				}
			}
		}
		for _, key := range []string{"labels", "annotations"} {
			if raw, exists := metadata[key]; exists {
				values, ok := raw.(map[string]any)
				if !ok {
					return fmt.Errorf("metadata.%s must be an object of string values", key)
				}
				for _, value := range values {
					if _, ok := value.(string); !ok {
						return fmt.Errorf("metadata.%s values must be strings", key)
					}
				}
			}
		}
	}
	if !partial {
		if _, exists := object["metadata"]; !exists {
			return fmt.Errorf("metadata is required")
		}
	}
	return nil
}

func validObjectName(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for index, character := range label {
			valid := character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
			if !valid && !(character == '-' && index > 0 && index < len(label)-1) {
				return false
			}
		}
	}
	return true
}

func validNamespaceName(value string) bool {
	return len(value) <= 63 && !strings.Contains(value, ".") && validObjectName(value)
}

func objectMap(value any) map[string]any {
	if object, ok := value.(map[string]any); ok && object != nil {
		return object
	}
	return map[string]any{}
}

func mergeObject(destination, patch map[string]any) {
	for key, value := range patch {
		if value == nil {
			delete(destination, key)
			continue
		}
		if nested, ok := value.(map[string]any); ok {
			if existing, ok := destination[key].(map[string]any); ok {
				mergeObject(existing, nested)
				continue
			}
		}
		destination[key] = value
	}
}

func (a *API) status(c *echo.Context, code int, reason, message, name string) error {
	status := map[string]any{
		"apiVersion": "v1", "kind": "Status", "status": "Failure",
		"message": message, "reason": reason, "code": code,
	}
	if name != "" {
		status["details"] = map[string]string{"name": name}
	}
	return c.JSON(code, status)
}

func (a *API) notFound(c *echo.Context) error {
	return a.status(c, http.StatusNotFound, "NotFound", fmt.Sprintf("the requested API path %q was not found", c.Request().URL.Path), "")
}

func stableUID(seed string) string {
	digest := sha256.Sum256([]byte(seed))
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", digest[0:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16])
}

type selectorRequirement struct {
	key, operator, value string
}

func filterObjects(objects []map[string]any, labelSelector, fieldSelector string) []map[string]any {
	out := make([]map[string]any, 0, len(objects))
	labels, labelsOK := parseSelector(labelSelector)
	fields, fieldsOK := parseSelector(fieldSelector)
	for _, object := range objects {
		if labelsOK && fieldsOK && objectMatches(object, labels, fields) {
			out = append(out, object)
		}
	}
	return out
}

func objectMatches(object map[string]any, labels, fields []selectorRequirement) bool {
	metadata := objectMap(object["metadata"])
	objectLabels := objectMap(metadata["labels"])
	for _, requirement := range labels {
		actual, present := objectLabels[requirement.key].(string)
		if !matchesRequirement(actual, present, requirement) {
			return false
		}
	}
	for _, requirement := range fields {
		var actual string
		var present bool
		switch requirement.key {
		case "metadata.name":
			actual, present = metadata["name"].(string)
		case "metadata.namespace":
			actual, present = metadata["namespace"].(string)
		case "status.phase":
			actual, present = objectMap(object["status"])["phase"].(string)
		case "spec.nodeName":
			actual, present = objectMap(object["spec"])["nodeName"].(string)
		default:
			return false
		}
		if !matchesRequirement(actual, present, requirement) {
			return false
		}
	}
	return true
}

func parseSelector(raw string) ([]selectorRequirement, bool) {
	result := make([]selectorRequirement, 0)
	if strings.TrimSpace(raw) == "" {
		return result, true
	}
	for _, rawRequirement := range strings.Split(raw, ",") {
		text := strings.TrimSpace(rawRequirement)
		operator := ""
		for _, candidate := range []string{"!=", "==", "="} {
			if strings.Contains(text, candidate) {
				operator = candidate
				break
			}
		}
		if operator == "" {
			return nil, false
		}
		pair := strings.SplitN(text, operator, 2)
		key, value := strings.TrimSpace(pair[0]), strings.TrimSpace(pair[1])
		if key == "" || value == "" || strings.ContainsAny(value, "=!") {
			return nil, false
		}
		result = append(result, selectorRequirement{key: key, operator: operator, value: value})
	}
	return result, true
}

func validFieldSelector(raw string) bool {
	requirements, valid := parseSelector(raw)
	if !valid {
		return false
	}
	for _, requirement := range requirements {
		switch requirement.key {
		case "metadata.name", "metadata.namespace", "status.phase", "spec.nodeName":
		default:
			return false
		}
	}
	return true
}

func matchesRequirement(actual string, present bool, requirement selectorRequirement) bool {
	if requirement.operator == "!=" {
		return !present || actual != requirement.value
	}
	return present && actual == requirement.value
}

func parseListLimit(raw string) (int, error) {
	if raw == "" {
		return maxListPageItems, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 0 || limit > maxListLimit {
		return 0, fmt.Errorf("limit must be an integer from 0 to %d", maxListLimit)
	}
	if limit == 0 || limit > maxListPageItems {
		limit = maxListPageItems
	}
	return limit, nil
}

func parseContinue(token, resourceVersion, identity string) (int, error) {
	if token == "" {
		return 0, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return 0, fmt.Errorf("continue token is invalid")
	}
	var value struct {
		Version  string `json:"resourceVersion"`
		Identity string `json:"identity"`
		Offset   int    `json:"offset"`
	}
	if err := json.Unmarshal(decoded, &value); err != nil || value.Offset < 0 {
		return 0, fmt.Errorf("continue token is invalid")
	}
	if value.Version != resourceVersion || value.Identity != identity {
		return 0, fmt.Errorf("continue token is no longer valid")
	}
	return value.Offset, nil
}

func makeContinueToken(resourceVersion string, offset int, identity string) string {
	encoded, _ := json.Marshal(struct {
		Version  string `json:"resourceVersion"`
		Identity string `json:"identity"`
		Offset   int    `json:"offset"`
	}{Version: resourceVersion, Identity: identity, Offset: offset})
	return base64.RawURLEncoding.EncodeToString(encoded)
}
