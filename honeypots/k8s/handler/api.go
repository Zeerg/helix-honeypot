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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	openapi_v2 "github.com/google/gnostic/openapiv2"
	"github.com/labstack/echo/v5"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"

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
	Categories []string `json:"categories,omitempty"`
	Group      string   `json:"group,omitempty"`
	Version    string   `json:"version,omitempty"`
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
	openAPIV3Schemas   []byte
	openAPIV3Known     map[string]bool
	openAPIV3Cache     map[string][]byte
	openAPIV3Mu        sync.Mutex
	serverAddress      string
	requestSlots       chan struct{}
	listSlots          chan struct{}
	watchSlots         chan struct{}
	ipBase             string
	emit               func(model.Event)
}

var apiCatalog = map[groupVersion][]apiResource{
	{"", "v1"}: {
		readOnlyResource("componentstatuses", "ComponentStatus", false),
		resource("configmaps", "ConfigMap", true, "cm"),
		resource("endpoints", "Endpoints", true, "ep"),
		resource("events", "Event", true, "ev"),
		resource("namespaces", "Namespace", false, "ns"),
		resource("nodes", "Node", false, "no"),
		resource("limitranges", "LimitRange", true, "limits"),
		resource("persistentvolumeclaims", "PersistentVolumeClaim", true, "pvc"),
		resource("persistentvolumes", "PersistentVolume", false, "pv"),
		resource("podtemplates", "PodTemplate", true, ""),
		resource("pods", "Pod", true, "po"),
		resource("resourcequotas", "ResourceQuota", true, "quota"),
		resource("replicationcontrollers", "ReplicationController", true, "rc"),
		resource("secrets", "Secret", true, "secret"),
		resource("serviceaccounts", "ServiceAccount", true, "sa"),
		resource("services", "Service", true, "svc"),
	},
	{"admissionregistration.k8s.io", "v1"}: {
		resource("mutatingwebhookconfigurations", "MutatingWebhookConfiguration", false, ""),
		resource("validatingadmissionpolicies", "ValidatingAdmissionPolicy", false, ""),
		resource("validatingadmissionpolicybindings", "ValidatingAdmissionPolicyBinding", false, ""),
		resource("validatingwebhookconfigurations", "ValidatingWebhookConfiguration", false, ""),
	},
	{"apiextensions.k8s.io", "v1"}: {
		resource("customresourcedefinitions", "CustomResourceDefinition", false, "crd"),
	},
	{"apiregistration.k8s.io", "v1"}: {
		resource("apiservices", "APIService", false, "apiservice"),
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
	{"authorization.k8s.io", "v1"}: {
		createOnlyResource("localsubjectaccessreviews", "LocalSubjectAccessReview", true),
		createOnlyResource("selfsubjectaccessreviews", "SelfSubjectAccessReview", false),
		createOnlyResource("selfsubjectrulesreviews", "SelfSubjectRulesReview", false),
		createOnlyResource("subjectaccessreviews", "SubjectAccessReview", false),
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
	{"metrics.k8s.io", "v1beta1"}: {
		readOnlyResource("nodes", "NodeMetrics", false),
		readOnlyResource("pods", "PodMetrics", true),
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
	entry := apiResource{
		Name:       name,
		Singular:   singular,
		Kind:       kind,
		Namespaced: namespaced,
		Verbs:      []string{"create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"},
	}
	if shortName != "" {
		entry.ShortNames = []string{shortName}
	}
	return entry
}

func createOnlyResource(name, kind string, namespaced bool) apiResource {
	entry := resource(name, kind, namespaced, "")
	entry.Verbs = []string{"create"}
	return entry
}

func readOnlyResource(name, kind string, namespaced bool) apiResource {
	entry := resource(name, kind, namespaced, "")
	entry.Verbs = []string{"get", "list"}
	return entry
}

var (
	metricsGroupVersion       = groupVersion{"metrics.k8s.io", "v1beta1"}
	authorizationGroupVersion = groupVersion{"authorization.k8s.io", "v1"}
)

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
	// kubectl expand "all" from the categories advertised in discovery.
	for gv, allResources := range map[groupVersion][]string{
		{"", "v1"}:      {"pods", "services"},
		{"apps", "v1"}:  {"daemonsets", "deployments", "replicasets", "statefulsets"},
		{"batch", "v1"}: {"cronjobs", "jobs"},
	} {
		for _, name := range allResources {
			if entry, ok := api.resources[gv][name]; ok {
				entry.Categories = []string{"all"}
				api.resources[gv][name] = entry
			}
		}
	}
	api.serverAddress = nodeAddress(cfg.K8S.IPBase, 10) + ":443"
	api.ipBase = cfg.K8S.IPBase
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
	fixtureVersion := version
	if minor > 27 {
		// No fixture for newer profiles; schemas are version-agnostic io.k8s
		// names, so the newest embedded document validates them fine.
		fixtureVersion = "v1.27"
	}
	{
		compressedFixture, err := embeddedFS.ReadFile("embedded/openapi/" + fixtureVersion + "_openapi.json.gz")
		if err != nil {
			return nil, fmt.Errorf("OpenAPI v2 fixture for %s is unavailable: %w", fixtureVersion, err)
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
	// OpenAPI v3 docs are generated from the embedded v2 definitions, which are
	// version-agnostic io.k8s schemas; the newest fixture covers every served
	// profile closely enough for kubectl explain and apply validation.
	schemasSource := api.openAPIV2JSON
	if schemasSource == nil {
		if compressedFixture, err := embeddedFS.ReadFile("embedded/openapi/v1.27_openapi.json.gz"); err == nil {
			if reader, err := gzip.NewReader(bytes.NewReader(compressedFixture)); err == nil {
				schemasSource, _ = io.ReadAll(io.LimitReader(reader, maxOpenAPIDocumentBytes+1))
				reader.Close()
			}
		}
	}
	if len(schemasSource) > 0 {
		api.openAPIV3Schemas, api.openAPIV3Known = openAPIV3Schemas(schemasSource)
	}
	api.openAPIV3Cache = make(map[string][]byte, 8)
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
		return a.status(c, http.StatusTooManyRequests, "TooManyRequests", "request has been rate limited", "")
	}
	r := c.Request()
	switch r.URL.Path {
	case "/healthz", "/livez", "/readyz",
		"/healthz/etcd", "/healthz/poststarthook", "/healthz/log",
		"/livez/etcd", "/livez/poststarthook",
		"/readyz/etcd", "/readyz/poststarthook", "/readyz/informer-sync",
		"/readyz/verbose", "/healthz/verbose", "/livez/verbose",
		"/readyz/shutdown":
		return c.String(http.StatusOK, "ok")
	case "/metrics":
		c.Response().Header().Set(echo.HeaderContentType, "text/plain; version=0.0.4; charset=utf-8")
		return c.String(http.StatusOK, a.apiserverMetrics())
	case "/version":
		return c.JSON(http.StatusOK, a.versionInfo())
	case "/openapi/v2":
		return a.serveOpenAPIV2(c)
	case "/openapi/v3", "/openapi/v3/":
		return a.serveOpenAPIV3Index(c)
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
	if len(parts) >= 3 && parts[0] == "openapi" && parts[1] == "v3" {
		return a.serveOpenAPIV3Doc(c, parts[2:])
	}
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
	// The reported toolchain is fixed to a plausible upstream build: echoing
	// runtime.Version()/GOOS would fingerprint the honeypot's actual platform.
	return map[string]string{
		"major": "1", "minor": strings.TrimPrefix(a.version, "v1."),
		"gitVersion": a.version + ".0", "gitCommit": fmt.Sprintf("%x", commit[:20]),
		"gitTreeState": "clean", "buildDate": a.startedAt.Format(time.RFC3339),
		"goVersion": "go1.24.4", "compiler": "gc",
		"platform": "linux/amd64",
	}
}

func (a *API) apiserverMetrics() string {
	var builder strings.Builder
	builder.WriteString("# HELP apiserver_request_total [STABLE] Counter of apiserver requests broken out for each verb, dry run value, group, version, resource, subresource, scope, component, and HTTP response code.\n")
	builder.WriteString("# TYPE apiserver_request_total counter\n")
	for _, entry := range []struct{ verb, resource, code string }{
		{"GET", "namespaces", "200"}, {"GET", "pods", "200"}, {"LIST", "pods", "200"},
		{"GET", "secrets", "200"}, {"WATCH", "pods", "200"}, {"POST", "pods", "201"},
		{"GET", "nodes", "200"}, {"GET", "secrets", "404"},
	} {
		fmt.Fprintf(&builder, "apiserver_request_total{component=\"apiserver\",code=\"%s\",dry_run=\"\",group=\"\",resource=\"%s\",scope=\"cluster\",subresource=\"\",verb=\"%s\",version=\"v1\"} %d\n", entry.code, entry.resource, entry.verb, 1+int(digestByte(entry.verb+entry.resource))%48)
	}
	builder.WriteString("# HELP apiserver_request_duration_seconds [STABLE] Response latency distribution in seconds for each verb, dry run value, group, version, resource, subresource, scope, and component.\n")
	builder.WriteString("# TYPE apiserver_request_duration_seconds histogram\n")
	builder.WriteString("# HELP go_goroutines [STABLE] Number of goroutines that currently exist.\n")
	builder.WriteString("# TYPE go_goroutines gauge\ngo_goroutines 213\n")
	builder.WriteString("# HELP etcd_request_duration_seconds [STABLE] Etcd request latencies in seconds for each operation and object type.\n")
	builder.WriteString("# TYPE etcd_request_duration_seconds histogram\n")
	return builder.String()
}

func digestByte(key string) byte {
	return sha256.Sum256([]byte(key))[0]
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
	if len(a.openAPIV3Schemas) > 0 {
		paths = append(paths, "/openapi/v3")
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

// subresourcesFor advertises the subresources a real apiserver lists in
// discovery — kubectl resolves scale/log/exec/token through these entries.
func subresourcesFor(resource apiResource) []apiResource {
	sub := func(name, kind string, verbs ...string) apiResource {
		return apiResource{Name: resource.Name + "/" + name, Kind: kind, Namespaced: resource.Namespaced, Verbs: verbs}
	}
	autoscaling := func() apiResource {
		return apiResource{Name: resource.Name + "/scale", Kind: "Scale", Group: "autoscaling", Version: "v1",
			Namespaced: resource.Namespaced, Verbs: []string{"get", "patch", "update"}}
	}
	switch resource.Name {
	case "pods":
		return []apiResource{
			sub("attach", "Pod", "create", "get"), sub("ephemeralcontainers", "Pod", "get", "patch", "update"),
			sub("eviction", "Eviction", "create"), sub("exec", "Pod", "create", "get"),
			sub("log", "Pod", "get"),
			sub("portforward", "Pod", "create", "get"), sub("proxy", "Pod", "create", "delete", "get", "update"),
			sub("status", "Pod", "get", "patch", "update"),
		}
	case "services":
		return []apiResource{sub("proxy", "Service", "create", "delete", "get", "update"), sub("status", "Service", "get", "patch", "update")}
	case "serviceaccounts":
		return []apiResource{
			{Name: resource.Name + "/token", Kind: "TokenRequest", Group: "authentication.k8s.io", Version: "v1", Namespaced: true, Verbs: []string{"create"}},
			sub("status", resource.Kind, "get", "patch", "update"),
		}
	case "deployments", "statefulsets", "replicasets":
		return []apiResource{autoscaling(), sub("status", resource.Kind, "get", "patch", "update")}
	case "replicationcontrollers":
		return []apiResource{autoscaling(), sub("status", resource.Kind, "get", "patch", "update")}
	case "daemonsets":
		return []apiResource{sub("status", resource.Kind, "get", "patch", "update")}
	case "nodes":
		return []apiResource{sub("proxy", "Node", "create", "delete", "get", "update"), sub("status", "Node", "get", "patch", "update")}
	case "namespaces":
		return []apiResource{sub("finalize", "Namespace", "update"), sub("status", "Namespace", "get", "patch", "update")}
	case "configmaps", "secrets", "persistentvolumeclaims":
		return []apiResource{sub("status", resource.Kind, "get", "patch", "update")}
	case "cronjobs":
		return []apiResource{sub("status", resource.Kind, "get", "patch", "update")}
	case "jobs", "horizontalpodautoscalers", "ingresses", "networkpolicies", "poddisruptionbudgets":
		return []apiResource{sub("status", resource.Kind, "get", "patch", "update")}
	case "customresourcedefinitions", "apiservices", "certificatesigningrequests", "clusterroles", "clusterrolebindings",
		"mutatingwebhookconfigurations", "validatingwebhookconfigurations", "storageclasses", "csidrivers":
		return []apiResource{sub("status", resource.Kind, "get", "patch", "update")}
	case "roles", "rolebindings", "leases", "events", "endpointslices", "endpoints":
		return []apiResource{sub("status", resource.Kind, "get", "patch", "update")}
	}
	return nil
}

func (a *API) resourceList(gv groupVersion) map[string]any {
	resources := make([]apiResource, 0, len(a.resources[gv]))
	for _, resource := range a.resources[gv] {
		resources = append(resources, resource)
		resources = append(resources, subresourcesFor(resource)...)
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
		return a.status(c, http.StatusNotFound, "NotFound", "the server could not find the requested resource", "")
	}
	select {
	case a.openAPISlots <- struct{}{}:
		defer func() { <-a.openAPISlots }()
	default:
		return a.capacityError(c)
	}
	// The deprecated "@" accept subtype maps to the RFC-legal "." content
	// type on the way out, matching kube-openapi's handler.
	const protobufMediaType = "application/com.github.proto-openapi.spec.v2.v1.0+protobuf"
	accept := strings.TrimSpace(c.Request().Header.Get(echo.HeaderAccept))
	protobufQuality := mediaTypeQuality(accept, protobufMediaType)
	if deprecated := mediaTypeQuality(accept, "application/com.github.proto-openapi.spec.v2@v1.0+protobuf"); deprecated > protobufQuality {
		protobufQuality = deprecated
	}
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
				return a.status(c, http.StatusInternalServerError, "InternalError", "the OpenAPI document is temporarily unavailable", "")
			}
			payload, err = io.ReadAll(io.LimitReader(reader, maxOpenAPIDocumentBytes+1))
			reader.Close()
			if err != nil || len(payload) > maxOpenAPIDocumentBytes {
				return a.status(c, http.StatusInternalServerError, "InternalError", "the OpenAPI document is temporarily unavailable", "")
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

// openAPIV3Schemas extracts the swagger definitions blob, rewriting
// "#/definitions/" references to the v3 "#/components/schemas/" layout. The
// returned set lists schema names present so path generation can skip kinds
// the fixture does not describe.
func openAPIV3Schemas(swaggerJSON []byte) ([]byte, map[string]bool) {
	var document map[string]any
	if err := json.Unmarshal(swaggerJSON, &document); err != nil {
		return nil, nil
	}
	definitions, ok := document["definitions"].(map[string]any)
	if !ok || len(definitions) == 0 {
		return nil, nil
	}
	marshaled, err := json.Marshal(definitions)
	if err != nil {
		return nil, nil
	}
	marshaled = bytes.ReplaceAll(marshaled, []byte(`#/definitions/`), []byte(`#/components/schemas/`))
	known := make(map[string]bool, len(definitions))
	for name := range definitions {
		known[name] = true
	}
	return marshaled, known
}

func (a *API) serveOpenAPIV3Index(c *echo.Context) error {
	if len(a.openAPIV3Schemas) == 0 {
		return a.status(c, http.StatusNotFound, "NotFound", "the server could not find the requested resource", "")
	}
	select {
	case a.openAPISlots <- struct{}{}:
		defer func() { <-a.openAPISlots }()
	default:
		return a.capacityError(c)
	}
	paths := map[string]any{}
	for gv := range a.resources {
		key := "api/" + gv.Version
		if gv.Group != "" {
			key = "apis/" + gv.Group + "/" + gv.Version
		}
		paths[key] = map[string]string{"serverRelativeURL": "/openapi/v3/" + key}
	}
	return c.JSON(http.StatusOK, map[string]any{"paths": paths})
}

// openAPIV3SchemaName maps a served resource to its io.k8s schema name. The
// aggregator, metrics, and apiextensions types live in different packages than
// their API group names suggest.
func openAPIV3SchemaName(gv groupVersion, kind string) string {
	if gv.Group == "" {
		return "io.k8s.api.core." + gv.Version + "." + kind
	}
	switch gv.Group {
	case "metrics.k8s.io":
		return "io.k8s.metrics.pkg.apis.metrics." + gv.Version + "." + kind
	case "apiregistration.k8s.io":
		return "io.k8s.kube-aggregator.pkg.apis.apiregistration." + gv.Version + "." + kind
	case "apiextensions.k8s.io":
		return "io.k8s.apiextensions-apiserver.pkg.apis.apiextensions." + gv.Version + "." + kind
	}
	return "io.k8s.api." + gv.Group + "." + gv.Version + "." + kind
}

func (a *API) openAPIV3Paths(gv groupVersion) map[string]any {
	paths := map[string]any{}
	for _, description := range a.resources[gv] {
		schema := openAPIV3SchemaName(gv, description.Kind)
		if !a.openAPIV3Known[schema] {
			continue
		}
		base := "/api/v1"
		if gv.Group != "" {
			base = "/apis/" + gv.Group + "/" + gv.Version
		}
		collection := base + "/" + description.Name
		if description.Namespaced {
			collection = base + "/namespaces/{namespace}/" + description.Name
		}
		gvk := func(kind string) map[string]any {
			return map[string]any{"x-kubernetes-group-version-kind": map[string]string{
				"group": gv.Group, "version": gv.Version, "kind": kind}}
		}
		op := func(action, kind, ref string) map[string]any {
			return map[string]any{
				"x-kubernetes-action":             action,
				"x-kubernetes-group-version-kind": gvk(kind)["x-kubernetes-group-version-kind"],
				"responses": map[string]any{"200": map[string]any{
					"description": "OK",
					"content":     map[string]any{"application/json": map[string]any{"schema": map[string]string{"$ref": "#/components/schemas/" + ref}}},
				}},
			}
		}
		paths[collection] = map[string]any{
			"get":  op("list", description.Kind+"List", schema+"List"),
			"post": op("post", description.Kind, schema),
		}
		paths[collection+"/{name}"] = map[string]any{
			"get":    op("get", description.Kind, schema),
			"put":    op("put", description.Kind, schema),
			"patch":  op("patch", description.Kind, schema),
			"delete": op("delete", description.Kind, "io.k8s.apimachinery.pkg.apis.meta.v1.Status"),
		}
	}
	return paths
}

func (a *API) serveOpenAPIV3Doc(c *echo.Context, segments []string) error {
	if len(a.openAPIV3Schemas) == 0 {
		return a.status(c, http.StatusNotFound, "NotFound", "the server could not find the requested resource", "")
	}
	var gv groupVersion
	if len(segments) == 2 && segments[0] == "api" {
		gv = groupVersion{"", segments[1]}
	} else if len(segments) == 3 && segments[0] == "apis" {
		gv = groupVersion{segments[1], segments[2]}
	} else {
		return a.notFound(c)
	}
	if _, ok := a.resources[gv]; !ok {
		return a.notFound(c)
	}
	select {
	case a.openAPISlots <- struct{}{}:
		defer func() { <-a.openAPISlots }()
	default:
		return a.capacityError(c)
	}
	key := apiVersionFor(gv)
	a.openAPIV3Mu.Lock()
	cached, ok := a.openAPIV3Cache[key]
	a.openAPIV3Mu.Unlock()
	if !ok {
		pathsJSON, err := json.Marshal(a.openAPIV3Paths(gv))
		if err != nil {
			return a.status(c, http.StatusInternalServerError, "InternalError", "the OpenAPI document is temporarily unavailable", "")
		}
		doc := `{"openapi":"3.0.0","info":{"title":"Kubernetes","version":"` + a.version + `.0"},"paths":` +
			string(pathsJSON) + `,"components":{"schemas":` + string(a.openAPIV3Schemas) + `}}`
		var compressed bytes.Buffer
		zw := gzip.NewWriter(&compressed)
		if _, err := zw.Write([]byte(doc)); err != nil {
			return a.status(c, http.StatusInternalServerError, "InternalError", "the OpenAPI document is temporarily unavailable", "")
		}
		if err := zw.Close(); err != nil {
			return a.status(c, http.StatusInternalServerError, "InternalError", "the OpenAPI document is temporarily unavailable", "")
		}
		cached = compressed.Bytes()
		a.openAPIV3Mu.Lock()
		if len(a.openAPIV3Cache) < 8 {
			a.openAPIV3Cache[key] = cached
		}
		a.openAPIV3Mu.Unlock()
	}
	c.Response().Header().Set(echo.HeaderContentType, "application/json")
	if acceptsGzip(c.Request().Header.Get(echo.HeaderAcceptEncoding)) {
		c.Response().Header().Set(echo.HeaderContentEncoding, "gzip")
		return c.Blob(http.StatusOK, "application/json", cached)
	}
	reader, err := gzip.NewReader(bytes.NewReader(cached))
	if err != nil {
		return a.status(c, http.StatusInternalServerError, "InternalError", "the OpenAPI document is temporarily unavailable", "")
	}
	defer reader.Close()
	return c.Stream(http.StatusOK, "application/json", reader)
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
			return a.serveSubresource(c, gv, namespace, resourceName, name, parts[4])
		}
	} else {
		resourceName = parts[0]
		if len(parts) > 1 {
			name = parts[1]
		}
		if len(parts) > 2 {
			return a.serveSubresource(c, gv, "", resourceName, name, parts[2])
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
	if gv == metricsGroupVersion {
		return a.serveMetrics(c, description, namespace, name)
	}
	if gv == authorizationGroupVersion {
		return a.serveAccessReview(c, description, namespace)
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
		if requestsTable(c) {
			return c.JSON(http.StatusOK, tableResponse(gv, description, []map[string]any{object}))
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

// serveSubresource handles object subresource paths. Streaming subresources
// are refused the way a kubelet refuses non-upgraded requests; pods/log is
// served from synthetic workload output because log reads are one of the most
// common reconnaissance actions.
func (a *API) serveSubresource(c *echo.Context, gv groupVersion, namespace, resourceName, name, subresource string) error {
	if name == "" {
		return a.status(c, http.StatusNotFound, "NotFound", "the server could not find the requested resource", "")
	}
	if subresource == "eviction" && gv == (groupVersion{"", "v1"}) && resourceName == "pods" {
		return a.serveEviction(c, namespace, name)
	}
	if subresource == "scale" && gv == (groupVersion{"apps", "v1"}) {
		switch resourceName {
		case "deployments", "statefulsets", "replicasets":
			return a.serveScale(c, gv, namespace, resourceName, name)
		}
	}
	if subresource == "token" && gv == (groupVersion{"", "v1"}) && resourceName == "serviceaccounts" {
		return a.serveTokenRequest(c, namespace, name)
	}
	if gv != (groupVersion{"", "v1"}) {
		return a.status(c, http.StatusNotFound, "NotFound", "the server could not find the requested resource", "")
	}
	switch subresource {
	case "ephemeralcontainers":
		if resourceName == "pods" {
			if c.Request().Method == http.MethodPatch {
				if description, ok := a.resources[gv][resourceName]; ok {
					return a.patch(c, gv, namespace, resourceName, name, description)
				}
			}
			if object, ok := a.store.get(objectKey{gv.Group, gv.Version, resourceName, namespace, name}); ok {
				return c.JSON(http.StatusOK, object)
			}
			return a.status(c, http.StatusNotFound, "NotFound", fmt.Sprintf("pods %q not found", name), name)
		}
	case "log":
		if resourceName == "pods" {
			return a.servePodLog(c, namespace, name)
		}
	case "exec", "attach", "portforward":
		if resourceName == "pods" {
			return a.status(c, http.StatusBadRequest, "BadRequest", "Upgrade request required", name)
		}
	case "proxy":
		if resourceName == "pods" || resourceName == "services" || resourceName == "nodes" {
			return a.status(c, http.StatusBadRequest, "BadRequest", "Upgrade request required", name)
		}
	case "status":
		if c.Request().Method == http.MethodGet {
			if object, ok := a.store.get(objectKey{gv.Group, gv.Version, resourceName, namespace, name}); ok {
				return c.JSON(http.StatusOK, object)
			}
			return a.status(c, http.StatusNotFound, "NotFound", fmt.Sprintf("%s %q not found", strings.TrimSuffix(resourceName, "s"), name), name)
		}
		if c.Request().Method == http.MethodPatch || c.Request().Method == http.MethodPut {
			if description, ok := a.resources[gv][resourceName]; ok {
				if c.Request().Method == http.MethodPatch {
					return a.patch(c, gv, namespace, resourceName, name, description)
				}
				return a.update(c, gv, namespace, resourceName, name, description)
			}
		}
	}
	return a.status(c, http.StatusNotFound, "NotFound", "the server could not find the requested resource", "")
}

// serveEviction answers pods/<name>/eviction the way the apiserver's eviction
// subresource does: the pod is removed and an Eviction object is returned.
func (a *API) serveEviction(c *echo.Context, namespace, name string) error {
	if c.Request().Method != http.MethodPost {
		c.Response().Header().Set(echo.HeaderAllow, "POST")
		return a.status(c, http.StatusMethodNotAllowed, "MethodNotAllowed", "only POST is supported for evictions", name)
	}
	key := objectKey{"", "v1", "pods", namespace, name}
	if _, ok := a.store.delete(key); !ok {
		return a.status(c, http.StatusNotFound, "NotFound", fmt.Sprintf("pods %q not found", name), name)
	}
	return c.JSON(http.StatusCreated, map[string]any{
		"apiVersion": "policy/v1", "kind": "Eviction",
		"metadata": map[string]any{"name": name, "namespace": namespace},
	})
}

// serveTokenRequest answers serviceaccounts/<name>/token with a TokenRequest
// bearing a synthetic JWT — `kubectl create token` is a standard recon step.
func (a *API) serveTokenRequest(c *echo.Context, namespace, name string) error {
	if c.Request().Method != http.MethodPost {
		c.Response().Header().Set(echo.HeaderAllow, "POST")
		return a.status(c, http.StatusMethodNotAllowed, "MethodNotAllowed", "only POST is supported for token requests", name)
	}
	if _, exists := a.store.get(objectKey{"", "v1", "serviceaccounts", namespace, name}); !exists {
		return a.status(c, http.StatusNotFound, "NotFound", fmt.Sprintf("serviceaccounts %q not found", name), name)
	}
	token := syntheticJWT(namespace, name)
	return c.JSON(http.StatusCreated, map[string]any{
		"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest",
		"metadata": map[string]any{"name": name, "namespace": namespace, "creationTimestamp": time.Now().UTC().Format(time.RFC3339)},
		"status": map[string]any{
			"token":               token,
			"expirationTimestamp": time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		},
	})
}

// syntheticJWT builds a plausibly-shaped service account token without real
// cryptographic material — three base64url segments like a real JWT.
func syntheticJWT(namespace, name string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"` + suffixFor("kid", 0) + `"}`))
	claims := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(
		`{"iss":"https://kubernetes.default.svc.cluster.local","kubernetes.io/serviceaccount/namespace":"%s","kubernetes.io/serviceaccount/service-account.name":"%s","sub":"system:serviceaccount:%s:%s"}`,
		namespace, name, namespace, name)))
	signature := base64.RawURLEncoding.EncodeToString([]byte(stableUID("sig/" + namespace + "/" + name)))
	return header + "." + claims + "." + signature
}

// serveScale answers the autoscaling/v1 scale subresource so kubectl scale
// reads and writes the parent's spec.replicas like a real apiserver.
func (a *API) serveScale(c *echo.Context, gv groupVersion, namespace, resourceName, name string) error {
	key := objectKey{gv.Group, gv.Version, resourceName, namespace, name}
	object, exists := a.store.get(key)
	if !exists {
		return a.status(c, http.StatusNotFound, "NotFound", fmt.Sprintf("%s %q not found", strings.TrimSuffix(resourceName, "s"), name), name)
	}
	if c.Request().Method == http.MethodGet {
		return c.JSON(http.StatusOK, scaleOf(object))
	}
	if c.Request().Method != http.MethodPut && c.Request().Method != http.MethodPatch {
		c.Response().Header().Set(echo.HeaderAllow, "GET, PUT, PATCH")
		return a.status(c, http.StatusMethodNotAllowed, "MethodNotAllowed", "only GET, PUT, and PATCH are supported for scale", name)
	}
	patch, err := decodeObject(c)
	if err != nil {
		return a.bodyError(c, err, name)
	}
	if replicas, ok := objectMap(patch["spec"])["replicas"]; ok {
		spec := objectMap(object["spec"])
		spec["replicas"] = replicas
		object["spec"] = spec
		if status, exists := object["status"]; exists {
			if statusMap, ok := status.(map[string]any); ok {
				statusMap["replicas"] = replicas
				statusMap["readyReplicas"] = replicas
				statusMap["availableReplicas"] = replicas
				statusMap["updatedReplicas"] = replicas
			}
		}
		if err := a.store.put(key, object, "MODIFIED"); err != nil {
			return a.capacityError(c)
		}
		if description, ok := a.resources[gv][resourceName]; ok && isWorkloadKind(description.Kind) {
			a.materializePods(gv, namespace, name, object)
		}
	}
	return c.JSON(http.StatusOK, scaleOf(object))
}

func scaleOf(object map[string]any) map[string]any {
	metadata := objectMap(object["metadata"])
	spec := objectMap(object["spec"])
	replicas := spec["replicas"]
	return map[string]any{
		"apiVersion": "autoscaling/v1", "kind": "Scale",
		"metadata": map[string]any{
			"name": metadata["name"], "namespace": metadata["namespace"],
			"uid": metadata["uid"], "resourceVersion": metadata["resourceVersion"],
			"creationTimestamp": metadata["creationTimestamp"],
		},
		"spec":   map[string]any{"replicas": replicas},
		"status": map[string]any{"replicas": replicas},
	}
}

func (a *API) servePodLog(c *echo.Context, namespace, name string) error {
	pod, exists := a.store.get(objectKey{"", "v1", "pods", namespace, name})
	if !exists {
		return a.status(c, http.StatusNotFound, "NotFound", fmt.Sprintf("pods %q not found", name), name)
	}
	containers := podContainerNames(pod)
	if len(containers) == 0 {
		containers = []string{"main"}
	}
	requested := c.QueryParam("container")
	if requested != "" {
		found := false
		for _, container := range containers {
			found = found || container == requested
		}
		if !found {
			return a.status(c, http.StatusBadRequest, "BadRequest", fmt.Sprintf("container %q is not valid for pod %q", requested, name), name)
		}
	} else {
		requested = containers[0]
	}
	if c.QueryParam("previous") == "true" {
		return a.status(c, http.StatusBadRequest, "BadRequest", fmt.Sprintf("previous terminated container %q in pod %q not found", requested, name), name)
	}
	lines := syntheticPodLog(pod, requested, a.store.startedAt)
	if raw := c.QueryParam("tailLines"); raw != "" {
		tail, err := strconv.Atoi(raw)
		if err != nil || tail < 0 {
			return a.status(c, http.StatusBadRequest, "BadRequest", fmt.Sprintf("tailLines must be a positive integer: %q", raw), name)
		}
		if tail < len(lines) {
			lines = lines[len(lines)-tail:]
		}
	}
	since := int64(0)
	if raw := c.QueryParam("sinceSeconds"); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil && parsed > 0 {
			since = parsed
		}
	}
	var builder strings.Builder
	now := time.Now().UTC()
	for i, line := range lines {
		at := a.store.startedAt.Add(time.Duration(i) * 2 * time.Second)
		if since > 0 && now.Sub(at) > time.Duration(since)*time.Second {
			continue
		}
		if c.QueryParam("timestamps") == "true" {
			builder.WriteString(at.Format(time.RFC3339Nano))
			builder.WriteByte(' ')
		}
		builder.WriteString(line)
		builder.WriteByte('\n')
	}
	output := builder.String()
	if raw := c.QueryParam("limitBytes"); raw != "" {
		if limit, err := strconv.Atoi(raw); err == nil && limit > 0 && limit < len(output) {
			output = output[:limit]
		}
	}
	c.Response().Header().Set(echo.HeaderContentType, "text/plain; charset=utf-8")
	return c.String(http.StatusOK, output)
}

func podContainerNames(pod map[string]any) []string {
	spec := objectMap(pod["spec"])
	names := make([]string, 0, 4)
	for _, key := range []string{"initContainers", "containers"} {
		if list, ok := spec[key].([]any); ok {
			for _, item := range list {
				if name, ok := objectMap(item)["name"].(string); ok && name != "" {
					names = append(names, name)
				}
			}
		}
	}
	return names
}

func podContainerImage(pod map[string]any, container string) string {
	spec := objectMap(pod["spec"])
	if list, ok := spec["containers"].([]any); ok {
		for _, item := range list {
			entry := objectMap(item)
			if name, _ := entry["name"].(string); name == container {
				image, _ := entry["image"].(string)
				return image
			}
		}
	}
	return ""
}

// syntheticPodLog returns plausible workload output keyed on the container
// image so scanners see image-appropriate text rather than an empty stream.
func syntheticPodLog(pod map[string]any, container string, startedAt time.Time) []string {
	image := podContainerImage(pod, container)
	switch {
	case strings.Contains(image, "coredns"):
		return []string{
			".:53",
			"CoreDNS-1.11.3",
			"linux/amd64, go1.22.5",
			"[INFO] plugin/kubernetes: waiting for Kubernetes API",
			"[INFO] plugin/ready: Still waiting on: \"kubernetes\"",
			"[INFO] plugin/reload: Running configuration SHA512 = 591cfbfcccc34f6c1bb255af4c3b1e31ba8e51be7a9f20d0d5a8d0b0e6a1a4f0",
			"CoreDNS-1.11.3",
			"[INFO] 127.0.0.1:47278 - 36888 \"HINFO IN 5897144097345822150.7841117492784195755.\" udp 57 false 512 -",
			"[INFO] plugin/ready: Still waiting on: \"kubernetes\"",
		}
	case strings.Contains(image, "kube-proxy"):
		return []string{
			"I0924 12:51:02.184634       1 server.go:677] \"Watching pods\" podCIDR=\"\"",
			"I0924 12:51:02.189912       1 node.go:163] Successfully retrieved node IP",
			"I0924 12:51:02.190211       1 server_others.go:190] \"Using iptables proxy\"",
			"I0924 12:51:02.209145       1 server.go:243] \"Kube-proxy is running\" version=\"v1.37.0\"",
			"I0924 12:51:02.212988       1 conntrack.go:60] \"Setting nf_conntrack_max\" nfConntrackMax=131072",
			"I0924 12:51:03.412008       1 proxier.go:802] \"Syncing iptables rules\"",
			"I0924 12:51:03.460114       1 bounded_frequency_runner.go:296] sync-runner: ran, next possible in 0s",
		}
	case strings.Contains(image, "metrics-server"):
		return []string{
			"I0924 12:51:03.022145       1 serving.go:342] \"Generated self-signed cert\"",
			"I0924 12:51:03.732210       1 handler.go:275] \"Adding GroupVersion metrics.k8s.io v1beta1 to ResourceManager\"",
			"I0924 12:51:04.109331       1 secure_serving.go:213] Serving securely on [::]:4443",
			"I0924 12:51:04.117802       1 requestheader_controller.go:169] \"Starting RequestHeaderAuthRequestController\"",
			"I0924 12:51:05.420076       1 scraper.go:149] \"Scraping node\" node=\"control-plane-01\"",
		}
	case strings.Contains(image, "redis"):
		return []string{
			"1:C 24 Sep 2026 12:51:02.005 # oO0OoO0OoO0Oo Redis is starting oO0OoO0OoO0Oo",
			"1:C 24 Sep 2026 12:51:02.006 # Redis version=7.4.0, just started",
			"1:M 24 Sep 2026 12:51:02.031 * monotonic clock: POSIX clock_gettime",
			"1:M 24 Sep 2026 12:51:02.033 * Running mode=standalone, port=6379.",
			"1:M 24 Sep 2026 12:51:02.041 # Server initialized",
			"1:M 24 Sep 2026 12:51:02.043 * Ready to accept connections tcp",
		}
	case strings.Contains(image, "nginx"):
		return []string{
			"/docker-entrypoint.sh: Configuration complete; ready for start up",
			"2026/09/24 12:51:02 [notice] 1#1: using the \"epoll\" event method",
			"2026/09/24 12:51:02 [notice] 1#1: nginx/1.30.5",
			"2026/09/24 12:51:02 [notice] 1#1: start worker processes",
		}
	default:
		return []string{
			"I0924 12:51:02.115512       1 main.go:46] \"Starting\" component=" + container,
			"I0924 12:51:02.188240       1 main.go:88] \"Connected to apiserver\"",
			"I0924 12:51:03.402178       1 server.go:140] \"Listening\" address=\":8080\"",
			"I0924 12:51:04.221905       1 main.go:120] \"Ready\" component=" + container,
		}
	}
}

// serveAccessReview answers authorization.k8s.io review requests with a fully
// permissive result: anonymous subjects appear cluster-admin, which is exactly
// the misconfiguration hunters look for with kubectl auth can-i.
func (a *API) serveAccessReview(c *echo.Context, description apiResource, namespace string) error {
	if c.Request().Method != http.MethodPost {
		c.Response().Header().Set(echo.HeaderAllow, "POST")
		return a.status(c, http.StatusMethodNotAllowed, "MethodNotAllowed", "only POST is supported for access reviews", "")
	}
	object, err := decodeObject(c)
	if err != nil {
		return a.bodyError(c, err, "")
	}
	response := map[string]any{
		"apiVersion": "authorization.k8s.io/v1",
		"kind":       description.Kind,
		"metadata":   map[string]any{"creationTimestamp": time.Now().UTC().Format(time.RFC3339)},
	}
	if spec, exists := object["spec"]; exists {
		response["spec"] = spec
	} else {
		response["spec"] = map[string]any{}
	}
	if description.Name == "selfsubjectrulesreviews" {
		response["status"] = map[string]any{
			"incomplete":       false,
			"resourceRules":    []any{map[string]any{"verbs": []string{"*"}, "apiGroups": []string{"*"}, "resources": []string{"*"}}},
			"nonResourceRules": []any{map[string]any{"verbs": []string{"*"}, "nonResourceURLs": []string{"*"}}},
		}
	} else {
		response["status"] = map[string]any{
			"allowed": true,
			"reason":  `RBAC: allowed by ClusterRoleBinding "system:discovery" of ClusterRole "cluster-admin" to Group "system:unauthenticated"`,
		}
	}
	return c.JSON(http.StatusCreated, response)
}

// serveMetrics synthesizes metrics.k8s.io answers from the in-memory store so
// kubectl top works the way it does on clusters running metrics-server.
func (a *API) serveMetrics(c *echo.Context, description apiResource, namespace, name string) error {
	if c.Request().Method != http.MethodGet {
		c.Response().Header().Set(echo.HeaderAllow, "GET")
		return a.status(c, http.StatusMethodNotAllowed, "MethodNotAllowed", "only GET is supported for metrics", "")
	}
	timestamp := time.Now().UTC().Format(time.RFC3339)
	var items []any
	if description.Name == "nodes" {
		nodes, _, _, err := a.store.listPage(groupVersion{"", "v1"}, "", "nodes", nil, nil, 0, maxListPageItems)
		if err != nil {
			return a.status(c, http.StatusInternalServerError, "InternalError", "metrics are temporarily unavailable", "")
		}
		for _, node := range nodes {
			nodeName, _ := objectMap(node["metadata"])["name"].(string)
			if name != "" && nodeName != name {
				continue
			}
			cpu, memory := syntheticUsage(nodeName)
			items = append(items, map[string]any{
				"apiVersion": "metrics.k8s.io/v1beta1", "kind": "NodeMetrics",
				"metadata":  map[string]any{"name": nodeName},
				"timestamp": timestamp, "window": "30s",
				"usage": map[string]string{"cpu": cpu, "memory": memory},
			})
		}
	} else {
		pods, _, _, err := a.store.listPage(groupVersion{"", "v1"}, namespace, "pods", nil, nil, 0, maxListPageItems)
		if err != nil {
			return a.status(c, http.StatusInternalServerError, "InternalError", "metrics are temporarily unavailable", "")
		}
		for _, pod := range pods {
			metadata := objectMap(pod["metadata"])
			podName, _ := metadata["name"].(string)
			if name != "" && podName != name {
				continue
			}
			containers := make([]any, 0)
			for _, container := range podContainerNames(pod) {
				cpu, memory := syntheticUsage(podName + "/" + container)
				containers = append(containers, map[string]any{"name": container, "usage": map[string]string{"cpu": cpu, "memory": memory}})
			}
			items = append(items, map[string]any{
				"apiVersion": "metrics.k8s.io/v1beta1", "kind": "PodMetrics",
				"metadata":  map[string]any{"name": podName, "namespace": metadata["namespace"]},
				"timestamp": timestamp, "window": "30s", "containers": containers,
			})
		}
	}
	if name != "" {
		if len(items) == 0 {
			return a.status(c, http.StatusNotFound, "NotFound", fmt.Sprintf("%s %q not found", strings.ToLower(description.Kind), name), name)
		}
		return c.JSON(http.StatusOK, items[0])
	}
	return c.JSON(http.StatusOK, map[string]any{
		"apiVersion": "metrics.k8s.io/v1beta1", "kind": description.Kind + "List",
		"metadata": map[string]any{}, "items": items,
	})
}

func syntheticUsage(key string) (string, string) {
	digest := sha256.Sum256([]byte("metrics.k8s.io/" + key))
	cpuMillis := 15 + int(digest[0])%600
	memoryMi := 64 + int(digest[1])%1900
	return strconv.Itoa(cpuMillis) + "m", strconv.Itoa(memoryMi) + "Mi"
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
			return a.status(c, http.StatusGone, "Expired", "The resourceVersion for the provided list is too old", "")
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
	if requestsTable(c) {
		return c.JSON(http.StatusOK, tableResponse(gv, description, items))
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
	if _, hasStatus := object["status"]; !hasStatus {
		if status := syntheticStatus(description.Kind, object); status != nil {
			object["status"] = status
		}
	}
	if description.Kind == "Pod" {
		spec := objectMap(object["spec"])
		applyPodSpecDefaults(spec)
		if node, _ := spec["nodeName"].(string); node == "" {
			// The scheduler binds unscheduled pods — pick a node deterministically.
			spec["nodeName"] = a.nodeName(int(digestByte(namespace+"/"+name)) % a.nodeCount())
		}
		object["spec"] = spec
		status := objectMap(object["status"])
		if phase, _ := status["phase"].(string); phase == "Running" {
			hostIP := serviceAddress(a.ipBase, 10)
			podIP := serviceAddress(a.ipBase, 100+int(digestByte(name))%100)
			if hostNet, _ := spec["hostNetwork"].(bool); hostNet {
				podIP = hostIP // hostNetwork pods share the node's IP
			}
			status["podIP"] = podIP
			status["podIPs"] = []any{map[string]any{"ip": podIP}}
			status["hostIP"] = hostIP
			object["status"] = status
		}
	}
	if description.Kind == "Job" {
		spec := objectMap(object["spec"])
		for key, value := range map[string]any{"completions": 1, "parallelism": 1, "backoffLimit": 6, "suspend": false, "completionMode": "NonIndexed"} {
			if _, ok := spec[key]; !ok {
				spec[key] = value
			}
		}
		template := objectMap(spec["template"])
		if podSpec, ok := template["spec"].(map[string]any); ok {
			applyPodSpecDefaults(podSpec)
			podSpec["restartPolicy"] = "Never"
			template["spec"] = podSpec
			spec["template"] = template
		}
		object["spec"] = spec
	}
	if description.Kind == "Deployment" || description.Kind == "StatefulSet" || description.Kind == "DaemonSet" {
		spec := objectMap(object["spec"])
		applyWorkloadDefaults(description.Kind, spec)
		object["spec"] = spec
	}
	if description.Kind == "Service" {
		spec := objectMap(object["spec"])
		for key, value := range map[string]any{
			"sessionAffinity":       "None",
			"ipFamilyPolicy":        "SingleStack",
			"internalTrafficPolicy": "Cluster",
			"externalTrafficPolicy": "Cluster",
		} {
			if _, ok := spec[key]; !ok {
				spec[key] = value
			}
		}
		if _, ok := spec["type"]; !ok {
			spec["type"] = "ClusterIP"
		}
		if ip, _ := spec["clusterIP"].(string); ip == "" {
			// A real apiserver allocates a clusterIP on create; derive a stable
			// one from the object identity.
			offset := 40 + int(digestByte(namespace+"/"+name))%40
			spec["clusterIP"] = serviceAddress(a.ipBase, offset)
			spec["clusterIPs"] = []any{spec["clusterIP"]}
			spec["ipFamilies"] = []any{"IPv4"}
			object["spec"] = spec
		}
	}
	if err := a.store.put(objectKey{gv.Group, gv.Version, description.Name, namespace, name}, object, "ADDED"); err != nil {
		if errors.Is(err, errObjectAlreadyExists) {
			return a.status(c, http.StatusConflict, "AlreadyExists", fmt.Sprintf("%s %q already exists", strings.ToLower(description.Kind), name), name)
		}
		return a.capacityError(c)
	}
	if isWorkloadKind(description.Kind) && description.Namespaced {
		a.materializePods(gv, namespace, name, object)
		a.syncEndpointsForNamespace(namespace)
	}
	if description.Kind == "Service" {
		a.syncEndpointsForNamespace(namespace)
	}
	if description.Kind == "Namespace" {
		a.seedNamespaceObjects(name)
	}
	c.Response().Header().Set(echo.HeaderLocation, c.Request().URL.Path+"/"+name)
	a.emitMutation(c, "create", object)
	return c.JSON(http.StatusCreated, object)
}

func resourceNameNeedsNamespace(name string) bool { return name != "namespaces" }

// SetEmitter registers the function receiving mutation events — the
// honeypot's record of what an attacker applied, changed, or deleted.
func (a *API) SetEmitter(emit func(model.Event)) {
	a.emit = emit
}

// emitMutation records a mutating API call with a bounded JSON summary of
// the object — the applied manifest is the highest-value signal a
// Kubernetes honeypot can capture.
func (a *API) emitMutation(c *echo.Context, operation string, object map[string]any) {
	if a.emit == nil {
		return
	}
	detail, err := json.Marshal(object)
	if err != nil {
		return
	}
	if len(detail) > 8<<10 {
		detail = append(detail[:8<<10], []byte(`..."truncated":true}`)...)
	}
	path := ""
	if c.Request().URL != nil {
		path = c.Request().URL.Path
	}
	a.emit(model.Event{
		Sensor:     "kubernetes",
		RemoteAddr: c.Request().RemoteAddr,
		Method:     c.Request().Method,
		Path:       path,
		Detail:     operation + " " + string(detail),
	})
}

// syntheticStatus gives freshly created workload objects the healthy status a
// real controller would have written, so kubectl rollout status and describe
// output look inhabited.
// applyWorkloadDefaults fills the fields an apiserver defaults on workload
// specs — describe shows StrategyType/MinReadySeconds from these.
func applyWorkloadDefaults(kind string, spec map[string]any) {
	switch kind {
	case "Deployment":
		if _, ok := spec["strategy"]; !ok {
			spec["strategy"] = map[string]any{
				"type": "RollingUpdate",
				"rollingUpdate": map[string]any{
					"maxUnavailable": "25%", "maxSurge": "25%",
				},
			}
		}
		if _, ok := spec["revisionHistoryLimit"]; !ok {
			spec["revisionHistoryLimit"] = 10
		}
		if _, ok := spec["progressDeadlineSeconds"]; !ok {
			spec["progressDeadlineSeconds"] = 600
		}
	case "StatefulSet":
		if _, ok := spec["updateStrategy"]; !ok {
			spec["updateStrategy"] = map[string]any{"type": "RollingUpdate"}
		}
		if _, ok := spec["podManagementPolicy"]; !ok {
			spec["podManagementPolicy"] = "OrderedReady"
		}
		if _, ok := spec["revisionHistoryLimit"]; !ok {
			spec["revisionHistoryLimit"] = 10
		}
	case "DaemonSet":
		if _, ok := spec["updateStrategy"]; !ok {
			spec["updateStrategy"] = map[string]any{
				"type": "RollingUpdate",
				"rollingUpdate": map[string]any{
					"maxUnavailable": 1, "maxSurge": 0,
				},
			}
		}
		if _, ok := spec["revisionHistoryLimit"]; !ok {
			spec["revisionHistoryLimit"] = 10
		}
	}
	// Pod template gets the same defaults a pod would.
	template := objectMap(spec["template"])
	if podSpec, ok := template["spec"].(map[string]any); ok {
		applyPodSpecDefaults(podSpec)
		template["spec"] = podSpec
		spec["template"] = template
	}
}

func syntheticStatus(kind string, object map[string]any) map[string]any {
	now := time.Now().UTC().Format(time.RFC3339)
	switch kind {
	case "Deployment":
		replicas := desiredReplicas(object)
		return map[string]any{
			"replicas": replicas, "updatedReplicas": replicas, "readyReplicas": replicas,
			"availableReplicas": replicas, "observedGeneration": 1,
			"conditions": []any{
				map[string]any{"type": "Available", "status": "True", "reason": "MinimumReplicasAvailable", "lastUpdateTime": now, "lastTransitionTime": now},
				map[string]any{"type": "Progressing", "status": "True", "reason": "NewReplicaSetAvailable", "lastUpdateTime": now, "lastTransitionTime": now},
			},
		}
	case "ReplicaSet", "ReplicationController":
		replicas := desiredReplicas(object)
		return map[string]any{"replicas": replicas, "readyReplicas": replicas, "availableReplicas": replicas, "observedGeneration": 1}
	case "StatefulSet":
		replicas := desiredReplicas(object)
		return map[string]any{"replicas": replicas, "readyReplicas": replicas, "currentReplicas": replicas, "updatedReplicas": replicas, "observedGeneration": 1}
	case "DaemonSet":
		return map[string]any{"desiredNumberScheduled": 3, "currentNumberScheduled": 3, "numberReady": 3, "numberAvailable": 3, "updatedNumberScheduled": 3, "observedGeneration": 1}
	case "Pod":
		statuses := []any{}
		for _, entry := range objectList(objectMap(object["spec"])["containers"]) {
			container := objectMap(entry)
			statuses = append(statuses, map[string]any{
				"name": stringField(container, "name"), "ready": true, "restartCount": 0,
				"state":       map[string]any{"running": map[string]any{"startedAt": now}},
				"started":     true,
				"image":       stringField(container, "image"),
				"imageID":     "containerd://" + strings.Repeat("a", 64),
				"containerID": "containerd://" + strings.Repeat("b", 64),
			})
		}
		return map[string]any{
			"phase": "Running", "qosClass": "BestEffort",
			"containerStatuses": statuses,
			"startTime":         now,
			"conditions": []any{
				map[string]any{"type": "Ready", "status": "True", "lastTransitionTime": now},
				map[string]any{"type": "PodScheduled", "status": "True", "lastTransitionTime": now},
			},
		}
	case "Job":
		return map[string]any{"active": 1, "startTime": now}
	case "HorizontalPodAutoscaler":
		return map[string]any{
			"currentReplicas": 1, "desiredReplicas": 2,
			"currentMetrics": []any{map[string]any{
				"type": "Resource",
				"resource": map[string]any{
					"name": "cpu",
					"current": map[string]any{
						"averageUtilization": 42, "averageValue": "42m",
					},
				},
			}},
			"lastScaleTime":      now,
			"observedGeneration": 1,
			"conditions":         []any{map[string]any{"type": "AbleToScale", "status": "True", "reason": "ReadyForNewScale", "lastTransitionTime": now}},
		}
	case "Ingress":
		return map[string]any{"loadBalancer": map[string]any{"ingress": []any{map[string]any{"ip": "10.0.0.50"}}}}
	}
	return nil
}

// syncEphemeralContainerStatus mirrors spec.ephemeralContainers into
// status.ephemeralContainerStatuses the way the kubelet reports them —
// `kubectl debug` waits on this status after patching the pod.
func syncEphemeralContainerStatus(pod map[string]any) {
	containers := objectList(objectMap(pod["spec"])["ephemeralContainers"])
	if len(containers) == 0 {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	status := objectMap(pod["status"])
	existing := map[string]bool{}
	for _, entry := range objectList(status["ephemeralContainerStatuses"]) {
		existing[stringField(objectMap(entry), "name")] = true
	}
	statuses := objectList(status["ephemeralContainerStatuses"])
	for _, entry := range containers {
		container := objectMap(entry)
		name := stringField(container, "name")
		if name == "" || existing[name] {
			continue
		}
		statuses = append(statuses, map[string]any{
			"name": name, "ready": false, "restartCount": 0,
			"state":       map[string]any{"running": map[string]any{"startedAt": now}},
			"started":     true,
			"image":       stringField(container, "image"),
			"imageID":     "containerd://" + strings.Repeat("c", 64),
			"containerID": "containerd://" + strings.Repeat("d", 64),
		})
	}
	status["ephemeralContainerStatuses"] = statuses
	pod["status"] = status
}

func desiredReplicas(object map[string]any) any {
	if replicas, ok := objectMap(object["spec"])["replicas"]; ok && replicas != nil {
		return replicas
	}
	return 1
}

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
	if isWorkloadKind(description.Kind) {
		object["status"] = syntheticStatus(description.Kind, object)
	}
	if err := a.store.put(key, object, "MODIFIED"); err != nil {
		return a.capacityError(c)
	}
	if isWorkloadKind(description.Kind) {
		a.materializePods(gv, namespace, name, object)
	}
	a.emitMutation(c, "update", object)
	return c.JSON(http.StatusOK, object)
}

func (a *API) patch(c *echo.Context, gv groupVersion, namespace, resourceName, name string, description apiResource) error {
	key := objectKey{gv.Group, gv.Version, resourceName, namespace, name}
	current, exists := a.store.get(key)
	if !exists {
		return a.status(c, http.StatusNotFound, "NotFound", fmt.Sprintf("%s %q not found", strings.ToLower(description.Kind), name), name)
	}
	if requestMediaType(c) == "application/json-patch+json" {
		operations, err := decodeJSONPatch(c)
		if err != nil {
			return a.bodyError(c, err, name)
		}
		if err := applyJSONPatch(current, operations); err != nil {
			return a.status(c, http.StatusUnprocessableEntity, "Invalid", err.Error(), name)
		}
	} else {
		patch, err := decodeObject(c)
		if err != nil {
			return a.bodyError(c, err, name)
		}
		if err := validateObjectShape(patch, gv, description, true); err != nil {
			return a.status(c, http.StatusUnprocessableEntity, "Invalid", err.Error(), name)
		}
		mergeObject(current, patch)
	}
	metadata := objectMap(current["metadata"])
	metadata["name"] = name
	current["apiVersion"] = apiVersionFor(gv)
	current["kind"] = description.Kind
	current["metadata"] = metadata
	if description.Kind == "Pod" {
		syncEphemeralContainerStatus(current)
	}
	if isWorkloadKind(description.Kind) {
		current["status"] = syntheticStatus(description.Kind, current)
	}
	if err := a.store.put(key, current, "MODIFIED"); err != nil {
		return a.capacityError(c)
	}
	if isWorkloadKind(description.Kind) {
		a.materializePods(gv, namespace, name, current)
	}
	a.emitMutation(c, "patch", current)
	return c.JSON(http.StatusOK, current)
}

func (a *API) delete(c *echo.Context, gv groupVersion, namespace, resourceName, name string, description apiResource) error {
	key := objectKey{gv.Group, gv.Version, resourceName, namespace, name}
	victim, _ := a.store.get(key)
	if _, ok := a.store.delete(key); !ok {
		return a.status(c, http.StatusNotFound, "NotFound", fmt.Sprintf("%s %q not found", strings.ToLower(description.Kind), name), name)
	}
	if isWorkloadKind(description.Kind) && description.Namespaced {
		a.reapOwnedPods(namespace, name)
	}
	if description.Kind == "Pod" {
		a.respawnDeletedPod(namespace, victim)
	}
	if victim != nil {
		a.emitMutation(c, "delete", victim)
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
	// A watch without a resourceVersion replays existing objects as synthetic
	// ADDED events, matching real apiserver semantics.
	if rv := c.QueryParam("resourceVersion"); rv == "" || rv == "0" {
		items, _, _, err := a.store.listPage(gv, namespace, resource, labels, fields, 0, maxListPageItems)
		if err == nil {
			for _, item := range items {
				if err := json.NewEncoder(c.Response()).Encode(watchEvent{Type: "ADDED", Object: item}); err != nil {
					return nil
				}
			}
			flusher.Flush()
		}
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
	data, err := decodeBody(c)
	if err != nil {
		return nil, err
	}
	var object map[string]any
	switch requestMediaType(c) {
	case "application/vnd.kubernetes.protobuf":
		return decodeProtobufObject(data)
	case "application/yaml", "application/x-yaml", "application/apply-patch+yaml", "text/yaml":
		if err := yaml.Unmarshal(data, &object); err != nil {
			return nil, fmt.Errorf("request body must be a YAML object")
		}
	default:
		if err := json.Unmarshal(data, &object); err != nil {
			return nil, fmt.Errorf("request body must be a JSON object")
		}
	}
	if object == nil {
		return nil, fmt.Errorf("request body must be a JSON object")
	}
	return object, nil
}

// client-go sends built-in typed objects (Secret, Deployment, Pod, ...) as the
// Kubernetes protobuf wire format: a 4-byte "k8s\x00" magic followed by a
// runtime.Unknown envelope {typeMeta, raw}. Decoding the raw typed message
// generically is impossible without generated schemas, so this extracts the
// fields that matter to the object store — metadata and the data payloads of
// Secret/ConfigMap — which keeps kubectl create/run/apply working end to end.
func decodeProtobufObject(data []byte) (map[string]any, error) {
	if !bytes.HasPrefix(data, []byte("k8s\x00")) {
		return nil, fmt.Errorf("request body is not a supported Kubernetes object encoding")
	}
	envelope, err := protoBytesFields(data[4:])
	if err != nil {
		return nil, fmt.Errorf("request body is not a valid protobuf object")
	}
	object := map[string]any{}
	if typeMeta := protoNested(envelope, 1); typeMeta != nil {
		object["apiVersion"] = protoString(typeMeta, 1)
		object["kind"] = protoString(typeMeta, 2)
	}
	rawValues := envelope[2]
	if len(rawValues) == 0 {
		return object, nil
	}
	raw, err := protoBytesFields(rawValues[0])
	if err != nil {
		return nil, fmt.Errorf("request body is not a valid protobuf object")
	}
	rawVarints, _ := protoVarintFields(rawValues[0])
	metadata := map[string]any{}
	if meta := protoNested(raw, 1); meta != nil {
		if name := protoString(meta, 1); name != "" {
			metadata["name"] = name
		}
		if generateName := protoString(meta, 2); generateName != "" {
			metadata["generateName"] = generateName
		}
		if namespace := protoString(meta, 3); namespace != "" {
			metadata["namespace"] = namespace
		}
		if labels := protoStringMap(meta, 11); len(labels) > 0 {
			metadata["labels"] = stringMapValues(labels)
		}
		if annotations := protoStringMap(meta, 12); len(annotations) > 0 {
			metadata["annotations"] = stringMapValues(annotations)
		}
	}
	object["metadata"] = metadata
	switch object["kind"] {
	case "Secret":
		if data := protoBytesMap(raw, 2); len(data) > 0 {
			object["data"] = data
		}
		if typ := protoString(raw, 3); typ != "" {
			object["type"] = typ
		}
		if stringData := protoStringMap(raw, 4); len(stringData) > 0 {
			object["stringData"] = stringData
		}
	case "ConfigMap":
		if immutable := rawVarints[2]; immutable != 0 {
			object["immutable"] = immutable == 1
		}
		if data := protoStringMap(raw, 3); len(data) > 0 {
			object["data"] = data
		}
		if binaryData := protoBytesMap(raw, 4); len(binaryData) > 0 {
			object["binaryData"] = binaryData
		}
	case "Pod":
		if specBytes := raw[2]; len(specBytes) > 0 {
			if spec := protoPodSpec(specBytes[0]); len(spec) > 0 {
				object["spec"] = spec
			}
		}
	case "Scale":
		if specBytes := raw[2]; len(specBytes) > 0 {
			if specVarints, err := protoVarintFields(specBytes[0]); err == nil {
				if replicas, ok := specVarints[1]; ok {
					object["spec"] = map[string]any{"replicas": replicas}
				}
			}
		}
	case "Service":
		if specBytes := raw[2]; len(specBytes) > 0 {
			spec := map[string]any{}
			if specFields, err := protoBytesFields(specBytes[0]); err == nil {
				if ports := protoServicePorts(specFields[1]); len(ports) > 0 {
					spec["ports"] = ports
				}
				if selector := protoStringMap(specFields, 2); len(selector) > 0 {
					spec["selector"] = stringMapValues(selector)
				}
				if typ := protoString(specFields, 4); typ != "" {
					spec["type"] = typ
				}
			}
			if len(spec) > 0 {
				object["spec"] = spec
			}
		}
	case "Deployment", "ReplicaSet", "StatefulSet", "ReplicationController":
		if specBytes := raw[2]; len(specBytes) > 0 {
			spec := map[string]any{}
			if specVarints, err := protoVarintFields(specBytes[0]); err == nil {
				if replicas, ok := specVarints[1]; ok {
					spec["replicas"] = replicas
				}
			}
			if specFields, err := protoBytesFields(specBytes[0]); err == nil {
				if selectorBytes := specFields[2]; len(selectorBytes) > 0 {
					if selector, err := protoBytesFields(selectorBytes[0]); err == nil {
						if matchLabels := protoStringMap(selector, 1); len(matchLabels) > 0 {
							spec["selector"] = map[string]any{"matchLabels": stringMapValues(matchLabels)}
						}
					}
				}
				if templateBytes := specFields[3]; len(templateBytes) > 0 {
					if template, err := protoBytesFields(templateBytes[0]); err == nil {
						if podSpecBytes := template[2]; len(podSpecBytes) > 0 {
							if podSpec := protoPodSpec(podSpecBytes[0]); len(podSpec) > 0 {
								spec["template"] = map[string]any{"spec": podSpec}
							}
						}
					}
				}
			}
			if len(spec) > 0 {
				object["spec"] = spec
			}
		}
	}
	return object, nil
}

// protoServicePorts decodes repeated ServicePort entries: name=1, protocol=2,
// port=3 (varint), targetPort=4 (IntOrString {type=1, intVal=2, strVal=3}).
func protoServicePorts(entries [][]byte) []any {
	ports := make([]any, 0, len(entries))
	for _, entryBytes := range entries {
		entry, err := protoBytesFields(entryBytes)
		if err != nil {
			continue
		}
		port := map[string]any{}
		if name := protoString(entry, 1); name != "" {
			port["name"] = name
		}
		if protocol := protoString(entry, 2); protocol != "" {
			port["protocol"] = protocol
		}
		varints, _ := protoVarintFields(entryBytes)
		if number, ok := varints[3]; ok {
			port["port"] = number
		}
		if targetBytes := entry[4]; len(targetBytes) > 0 {
			target, err := protoBytesFields(targetBytes[0])
			targetVarints, _ := protoVarintFields(targetBytes[0])
			if err == nil {
				if kind := targetVarints[1]; kind == 1 {
					if str := protoString(target, 3); str != "" {
						port["targetPort"] = str
					}
				} else if number, ok := targetVarints[2]; ok {
					port["targetPort"] = number
				}
			}
		}
		ports = append(ports, port)
	}
	return ports
}

// protoPodSpec decodes the PodSpec fields that matter for fidelity:
// containers/initContainers (2/20) with env (7), ports (6), and volumeMounts
// (9), plus volumes (1), nodeName (10), restartPolicy (3), and
// serviceAccountName (8). Unknown fields are skipped by the wire parser.
func protoPodSpec(podSpecBytes []byte) map[string]any {
	spec, err := protoBytesFields(podSpecBytes)
	if err != nil {
		return nil
	}
	out := map[string]any{}
	containers := make([]any, 0, len(spec[2])+len(spec[20]))
	for _, field := range []int{20, 2} {
		for _, containerBytes := range spec[field] {
			container, err := protoBytesFields(containerBytes)
			if err != nil {
				continue
			}
			entry := map[string]any{
				"name": protoString(container, 1), "image": protoString(container, 2),
			}
			if command := protoStringList(container[3]); len(command) > 0 {
				entry["command"] = command
			}
			if args := protoStringList(container[4]); len(args) > 0 {
				entry["args"] = args
			}
			if ports := protoContainerPorts(container[6]); len(ports) > 0 {
				entry["ports"] = ports
			}
			if env := protoEnvVars(container[7]); len(env) > 0 {
				entry["env"] = env
			}
			if mounts := protoVolumeMounts(container[9]); len(mounts) > 0 {
				entry["volumeMounts"] = mounts
			}
			containers = append(containers, entry)
		}
	}
	if len(containers) > 0 {
		out["containers"] = containers
	}
	if volumes := protoVolumes(spec[1]); len(volumes) > 0 {
		out["volumes"] = volumes
	}
	if name := protoString(spec, 10); name != "" {
		out["nodeName"] = name
	}
	if policy := protoString(spec, 3); policy != "" {
		out["restartPolicy"] = policy
	}
	if account := protoString(spec, 8); account != "" {
		out["serviceAccountName"] = account
	}
	return out
}

// protoStringList decodes repeated plain string fields (command, args).
func protoStringList(values [][]byte) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return out
}

// protoContainerPorts decodes ContainerPort: name=1, hostPort=2,
// containerPort=3 (varints), protocol=4, hostIP=5.
func protoContainerPorts(entries [][]byte) []any {
	ports := make([]any, 0, len(entries))
	for _, entryBytes := range entries {
		entry, err := protoBytesFields(entryBytes)
		if err != nil {
			continue
		}
		varints, _ := protoVarintFields(entryBytes)
		port := map[string]any{"containerPort": varints[3]}
		if name := protoString(entry, 1); name != "" {
			port["name"] = name
		}
		if protocol := protoString(entry, 4); protocol != "" {
			port["protocol"] = protocol
		} else {
			port["protocol"] = "TCP"
		}
		if hostPort, ok := varints[2]; ok && hostPort > 0 {
			port["hostPort"] = hostPort
		}
		if hostIP := protoString(entry, 5); hostIP != "" {
			port["hostIP"] = hostIP
		}
		ports = append(ports, port)
	}
	return ports
}

// protoEnvVars decodes EnvVar: name=1, value=2, valueFrom=3 (kept opaque).
func protoEnvVars(entries [][]byte) []any {
	env := make([]any, 0, len(entries))
	for _, entryBytes := range entries {
		entry, err := protoBytesFields(entryBytes)
		if err != nil {
			continue
		}
		variable := map[string]any{"name": protoString(entry, 1)}
		if value := protoString(entry, 2); value != "" {
			variable["value"] = value
		}
		env = append(env, variable)
	}
	return env
}

// protoVolumeMounts decodes VolumeMount: name=1, readOnly=2 (varint),
// mountPath=3, subPath=4.
func protoVolumeMounts(entries [][]byte) []any {
	mounts := make([]any, 0, len(entries))
	for _, entryBytes := range entries {
		entry, err := protoBytesFields(entryBytes)
		if err != nil {
			continue
		}
		varints, _ := protoVarintFields(entryBytes)
		mount := map[string]any{
			"name": protoString(entry, 1), "mountPath": protoString(entry, 3),
		}
		if varints[2] == 1 {
			mount["readOnly"] = true
		}
		if subPath := protoString(entry, 4); subPath != "" {
			mount["subPath"] = subPath
		}
		mounts = append(mounts, mount)
	}
	return mounts
}

// protoVolumes decodes the common Volume sources: secret=7, configMap=20,
// persistentVolumeClaim=11, emptyDir=3, hostPath=2, projected=27.
func protoVolumes(entries [][]byte) []any {
	volumes := make([]any, 0, len(entries))
	for _, entryBytes := range entries {
		entry, err := protoBytesFields(entryBytes)
		if err != nil {
			continue
		}
		volume := map[string]any{"name": protoString(entry, 1)}
		if source := entry[7]; len(source) > 0 {
			if secret, err := protoBytesFields(source[0]); err == nil {
				volume["secret"] = map[string]any{"secretName": protoString(secret, 1)}
			}
		} else if source := entry[20]; len(source) > 0 {
			if configMap, err := protoBytesFields(source[0]); err == nil {
				volume["configMap"] = map[string]any{"name": protoString(configMap, 1)}
			}
		} else if source := entry[11]; len(source) > 0 {
			if claim, err := protoBytesFields(source[0]); err == nil {
				volume["persistentVolumeClaim"] = map[string]any{"claimName": protoString(claim, 1)}
			}
		} else if source := entry[3]; len(source) > 0 {
			volume["emptyDir"] = map[string]any{}
		} else if source := entry[2]; len(source) > 0 {
			if hostPath, err := protoBytesFields(source[0]); err == nil {
				volume["hostPath"] = map[string]any{"path": protoString(hostPath, 1)}
			}
		} else if source := entry[27]; len(source) > 0 {
			volume["projected"] = map[string]any{"sources": []any{}}
		}
		volumes = append(volumes, volume)
	}
	return volumes
}

var errProtoEncoding = errors.New("invalid protobuf encoding")

// protoBytesFields parses a protobuf message into field number -> list of
// length-delimited payloads. Varints and fixed-width fields are skipped; the
// callers only need nested messages, strings, and packed bytes.
func protoBytesFields(data []byte) (map[int][][]byte, error) {
	fields := map[int][][]byte{}
	for len(data) > 0 {
		number, wireType, consumed := protowire.ConsumeTag(data)
		if consumed < 0 {
			return nil, errProtoEncoding
		}
		data = data[consumed:]
		if wireType == protowire.BytesType {
			value, length := protowire.ConsumeBytes(data)
			if length < 0 {
				return nil, errProtoEncoding
			}
			fields[int(number)] = append(fields[int(number)], value)
			data = data[length:]
			continue
		}
		value := protowire.ConsumeFieldValue(number, wireType, data)
		if value < 0 {
			return nil, errProtoEncoding
		}
		data = data[value:]
	}
	return fields, nil
}

func protoVarintFields(data []byte) (map[int]uint64, error) {
	fields := map[int]uint64{}
	for len(data) > 0 {
		number, wireType, consumed := protowire.ConsumeTag(data)
		if consumed < 0 {
			return nil, errProtoEncoding
		}
		data = data[consumed:]
		if wireType == protowire.VarintType {
			value, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return nil, errProtoEncoding
			}
			fields[int(number)] = value
			data = data[n:]
			continue
		}
		value := protowire.ConsumeFieldValue(number, wireType, data)
		if value < 0 {
			return nil, errProtoEncoding
		}
		data = data[value:]
	}
	return fields, nil
}

func protoNested(fields map[int][][]byte, number int) map[int][][]byte {
	values := fields[number]
	if len(values) == 0 {
		return nil
	}
	nested, err := protoBytesFields(values[0])
	if err != nil {
		return nil
	}
	return nested
}

func protoString(fields map[int][][]byte, number int) string {
	values := fields[number]
	if len(values) == 0 {
		return ""
	}
	return string(values[0])
}

func stringMapValues(in map[string]string) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

// protoStringMap decodes a protobuf map<string,string> repeated field.
func protoStringMap(fields map[int][][]byte, number int) map[string]string {
	out := map[string]string{}
	for _, entry := range fields[number] {
		pair, err := protoBytesFields(entry)
		if err != nil {
			continue
		}
		out[protoString(pair, 1)] = protoString(pair, 2)
	}
	return out
}

// protoBytesMap decodes a protobuf map<string,bytes> field into the base64
// string map Kubernetes uses for JSON representations of binary fields.
func protoBytesMap(fields map[int][][]byte, number int) map[string]string {
	out := map[string]string{}
	for _, entry := range fields[number] {
		pair, err := protoBytesFields(entry)
		if err != nil {
			continue
		}
		values := pair[2]
		if len(values) == 0 {
			out[protoString(pair, 1)] = ""
			continue
		}
		out[protoString(pair, 1)] = base64.StdEncoding.EncodeToString(values[0])
	}
	return out
}

// decodeJSONPatch decodes a JSON Patch (RFC 6902) document body, used by
// kubectl patch --type=json which submits an array of operations rather than
// a single object.
func decodeJSONPatch(c *echo.Context) ([]map[string]any, error) {
	data, err := decodeBody(c)
	if err != nil {
		return nil, err
	}
	var operations []map[string]any
	if err := json.Unmarshal(data, &operations); err != nil {
		return nil, fmt.Errorf("request body must be a JSON patch array")
	}
	if len(operations) == 0 {
		return nil, fmt.Errorf("request body must be a JSON patch array")
	}
	for _, operation := range operations {
		op, _ := operation["op"].(string)
		patchPath, _ := operation["path"].(string)
		if !validPatchOperation(op) || !strings.HasPrefix(patchPath, "/") {
			return nil, fmt.Errorf("invalid JSON patch operation")
		}
	}
	return operations, nil
}

func validPatchOperation(op string) bool {
	switch op {
	case "add", "remove", "replace", "move", "copy", "test":
		return true
	}
	return false
}

func decodeBody(c *echo.Context) ([]byte, error) {
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
	return data, nil
}

func requestMediaType(c *echo.Context) string {
	contentType := c.Request().Header.Get(echo.HeaderContentType)
	if index := strings.IndexByte(contentType, ';'); index >= 0 {
		contentType = contentType[:index]
	}
	return strings.ToLower(strings.TrimSpace(contentType))
}

var errRequestTooLarge = errors.New("request body exceeds the 64 KiB limit")
var errUnsupportedMediaType = errors.New("the body must be encoded as JSON")

func (a *API) bodyError(c *echo.Context, err error, name string) error {
	if errors.Is(err, errRequestTooLarge) {
		return a.status(c, http.StatusRequestEntityTooLarge, "RequestEntityTooLarge", err.Error(), name)
	}
	if errors.Is(err, errUnsupportedMediaType) {
		return a.status(c, http.StatusUnsupportedMediaType, "UnsupportedMediaType", err.Error(), name)
	}
	return a.status(c, http.StatusBadRequest, "BadRequest", err.Error(), name)
}

func (a *API) capacityError(c *echo.Context) error {
	return a.status(c, http.StatusTooManyRequests, "TooManyRequests", "etcdserver: too many requests", "")
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

// applyJSONPatch applies a bounded subset of RFC 6902 sufficient for kubectl's
// --type=json patches: add/remove/replace/move/copy/test on object keys and
// array indexes. Pointer segments use the standard ~0/~1 escapes.
func applyJSONPatch(document map[string]any, operations []map[string]any) error {
	for i, operation := range operations {
		op, _ := operation["op"].(string)
		target, _ := operation["path"].(string)
		if op == "test" {
			current, _, _, found := resolvePatchTarget(document, target)
			expected, _ := operation["value"]
			if !found || !patchValuesEqual(current, expected) {
				return fmt.Errorf("test operation %d failed", i)
			}
			continue
		}
		if op == "move" || op == "copy" {
			from, _ := operation["from"].(string)
			current, _, _, found := resolvePatchTarget(document, from)
			if !found {
				return fmt.Errorf("operation %d references a missing path", i)
			}
			operation["value"] = current
			if op == "move" {
				if err := patchWrite(document, from, nil, true); err != nil {
					return fmt.Errorf("operation %d: %w", i, err)
				}
			}
			op = "add"
		}
		switch op {
		case "add", "replace":
			if err := patchWrite(document, target, operation["value"], false); err != nil {
				return fmt.Errorf("operation %d: %w", i, err)
			}
		case "remove":
			if err := patchWrite(document, target, nil, true); err != nil {
				return fmt.Errorf("operation %d: %w", i, err)
			}
		}
	}
	return nil
}

func patchPointer(path string) []string {
	if path == "" {
		return nil
	}
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, segment := range segments {
		segments[i] = strings.ReplaceAll(strings.ReplaceAll(segment, "~1", "/"), "~0", "~")
	}
	return segments
}

func resolvePatchTarget(document map[string]any, path string) (any, map[string]any, string, bool) {
	segments := patchPointer(path)
	if len(segments) == 0 {
		return nil, nil, "", false
	}
	current := any(document)
	for _, segment := range segments[:len(segments)-1] {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, nil, "", false
		}
		current, ok = object[segment]
		if !ok {
			return nil, nil, "", false
		}
	}
	parent, ok := current.(map[string]any)
	if !ok {
		return nil, nil, "", false
	}
	leaf := segments[len(segments)-1]
	value, found := parent[leaf]
	return value, parent, leaf, found
}

// patchWrite sets or deletes a value at a JSON pointer inside document. Array
// leaf segments are supported when the immediate parent is a []any held by an
// object key; removal and append rebuild the slice so indexes shift the way
// RFC 6902 requires.
func patchWrite(document map[string]any, path string, value any, remove bool) error {
	segments := patchPointer(path)
	if len(segments) == 0 {
		return fmt.Errorf("document root cannot be modified")
	}
	current := any(document)
	for _, segment := range segments[:len(segments)-1] {
		next, err := patchDescend(current, segment)
		if err != nil {
			return err
		}
		current = next
	}
	leaf := segments[len(segments)-1]
	switch parent := current.(type) {
	case map[string]any:
		if remove {
			delete(parent, leaf)
			return nil
		}
		parent[leaf] = value
		return nil
	case []any:
		if len(segments) < 2 {
			return fmt.Errorf("document root cannot be modified")
		}
		index, err := strconv.Atoi(leaf)
		bound := len(parent)
		if remove {
			bound--
		}
		if err != nil || index < 0 || index > bound {
			return fmt.Errorf("array index %q is out of range", leaf)
		}
		result := make([]any, 0, len(parent)+1)
		result = append(result, parent[:index]...)
		if !remove {
			result = append(result, value)
		}
		result = append(result, parent[index+boolToInt(remove):]...)
		container, err := patchContainer(document, segments[:len(segments)-1])
		if err != nil {
			return err
		}
		container[segments[len(segments)-2]] = result
		return nil
	}
	return fmt.Errorf("patch path is not addressable")
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func patchDescend(current any, segment string) (any, error) {
	object, ok := current.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("patch path is not addressable")
	}
	next, exists := object[segment]
	if !exists {
		created := map[string]any{}
		object[segment] = created
		return created, nil
	}
	return next, nil
}

// patchContainer walks segments (the portion of the pointer above the leaf
// index) and returns the object holding the array being modified.
func patchContainer(document map[string]any, segments []string) (map[string]any, error) {
	current := any(document)
	for _, segment := range segments[:len(segments)-1] {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("patch path is not addressable")
		}
		current = object[segment]
	}
	object, ok := current.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("patch path is not addressable")
	}
	return object, nil
}

func patchValuesEqual(a, b any) bool {
	left, err := json.Marshal(a)
	if err != nil {
		return false
	}
	right, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return bytes.Equal(left, right)
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
		case "involvedObject.name", "regarding.name", "involvedObject.namespace", "regarding.namespace":
			involved := objectMap(object["involvedObject"])
			if len(involved) == 0 {
				involved = objectMap(object["regarding"])
			}
			if strings.HasSuffix(requirement.key, ".name") {
				actual, present = involved["name"].(string)
			} else {
				actual, present = involved["namespace"].(string)
			}
		case "involvedObject.kind", "regarding.kind":
			involved := objectMap(object["involvedObject"])
			if len(involved) == 0 {
				involved = objectMap(object["regarding"])
			}
			actual, present = involved["kind"].(string)
		case "reason", "type", "source.component", "reportingComponent":
			actual, present = object[requirement.key].(string)
			if !present {
				actual, present = objectMap(object["source"])["component"].(string)
			}
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
		case "metadata.name", "metadata.namespace", "status.phase", "spec.nodeName",
			"involvedObject.name", "involvedObject.namespace", "involvedObject.kind",
			"regarding.name", "regarding.namespace", "regarding.kind",
			"reason", "type", "source.component", "reportingComponent":
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
