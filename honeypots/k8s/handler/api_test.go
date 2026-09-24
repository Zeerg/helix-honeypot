package handler

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
	"google.golang.org/protobuf/encoding/protowire"

	"helix-honeypot/config"
)

// kubectl create secret generic test-secret --from-literal=k=v -n default
// emits this exact protobuf wire body (runtime.Unknown envelope around a
// core/v1 Secret).
var kubectlSecretProto = []byte{
	0x6b, 0x38, 0x73, 0x00, 0x0a, 0x0c, 0x0a, 0x02, 0x76, 0x31, 0x12, 0x06,
	0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x12, 0x2e, 0x0a, 0x22, 0x0a, 0x0b,
	0x74, 0x65, 0x73, 0x74, 0x2d, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x12,
	0x00, 0x1a, 0x07, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x22, 0x00,
	0x2a, 0x00, 0x32, 0x00, 0x38, 0x00, 0x42, 0x00, 0x12, 0x06, 0x0a, 0x01,
	0x6b, 0x12, 0x01, 0x76, 0x1a, 0x00, 0x1a, 0x00, 0x22, 0x00,
}

func testContext(t *testing.T, method, target, contentType string, body []byte) (*echo.Context, *httptest.ResponseRecorder) {
	t.Helper()
	var request *http.Request
	if body != nil {
		request = httptest.NewRequest(method, target, strings.NewReader(string(body)))
	} else {
		request = httptest.NewRequest(method, target, nil)
	}
	if contentType != "" {
		request.Header.Set(echo.HeaderContentType, contentType)
	}
	recorder := httptest.NewRecorder()
	return echo.New().NewContext(request, recorder), recorder
}

func TestDecodeProtobufObjectRoundTripsSecret(t *testing.T) {
	c, _ := testContext(t, http.MethodPost, "/api/v1/namespaces/default/secrets",
		"application/vnd.kubernetes.protobuf", kubectlSecretProto)
	object, err := decodeObject(c)
	if err != nil {
		t.Fatalf("decodeObject() error = %v", err)
	}
	if object["kind"] != "Secret" || object["apiVersion"] != "v1" {
		t.Fatalf("decoded type = %v/%v, want v1 Secret", object["apiVersion"], object["kind"])
	}
	metadata := objectMap(object["metadata"])
	if metadata["name"] != "test-secret" || metadata["namespace"] != "default" {
		t.Fatalf("metadata = %#v, want test-secret in default", metadata)
	}
	data, ok := object["data"].(map[string]string)
	if !ok || data["k"] != base64.StdEncoding.EncodeToString([]byte("v")) {
		t.Fatalf("data = %#v, want k=base64(v)", object["data"])
	}
}

func TestDecodeObjectRejectsGarbage(t *testing.T) {
	c, _ := testContext(t, http.MethodPost, "/api/v1/namespaces/default/secrets",
		"application/vnd.kubernetes.protobuf", []byte("k8s\x00\xff\xff\xff"))
	if _, err := decodeObject(c); err == nil {
		t.Fatal("decodeObject() accepted malformed protobuf")
	}
	c, _ = testContext(t, http.MethodPost, "/api/v1/namespaces/default/secrets",
		"application/json", []byte(`{"kind":"Secret"`))
	if _, err := decodeObject(c); err == nil {
		t.Fatal("decodeObject() accepted truncated JSON")
	}
}

func TestDecodeObjectAcceptsYAML(t *testing.T) {
	c, _ := testContext(t, http.MethodPost, "/api/v1/namespaces/default/secrets",
		"application/yaml", []byte("kind: Secret\napiVersion: v1\nmetadata:\n  name: y\n"))
	object, err := decodeObject(c)
	if err != nil {
		t.Fatalf("decodeObject() error = %v", err)
	}
	if objectMap(object["metadata"])["name"] != "y" {
		t.Fatalf("metadata = %#v, want name=y", object["metadata"])
	}
}

func TestApplyJSONPatch(t *testing.T) {
	document := map[string]any{
		"spec": map[string]any{
			"replicas": float64(1),
			"items":    []any{"a", "b"},
		},
	}
	operations := []map[string]any{
		{"op": "replace", "path": "/spec/replicas", "value": float64(3)},
		{"op": "add", "path": "/metadata/labels/app", "value": "web"},
		{"op": "remove", "path": "/spec/items/0"},
	}
	if err := applyJSONPatch(document, operations); err != nil {
		t.Fatalf("applyJSONPatch() error = %v", err)
	}
	if got := objectMap(document["spec"])["replicas"]; got != float64(3) {
		t.Fatalf("replicas = %#v, want 3", got)
	}
	items, _ := objectMap(document["spec"])["items"].([]any)
	if len(items) != 1 || items[0] != "b" {
		t.Fatalf("items = %#v, want [b]", items)
	}
	labels := objectMap(objectMap(document["metadata"])["labels"])
	if labels["app"] != "web" {
		t.Fatalf("labels = %#v, want app=web", labels)
	}
}

func TestSeedsClusterBasics(t *testing.T) {
	cfg := config.Defaults()
	api, err := NewAPI(&cfg)
	if err != nil {
		t.Fatalf("NewAPI() error = %v", err)
	}
	checks := []objectKey{
		{group: "", version: "v1", resource: "services", namespace: "default", name: "kubernetes"},
		{group: "", version: "v1", resource: "endpoints", namespace: "default", name: "kubernetes"},
		{group: "coordination.k8s.io", version: "v1", resource: "leases", namespace: "kube-node-lease", name: "worker-01"},
		{group: "", version: "v1", resource: "serviceaccounts", namespace: "default", name: "default"},
		{group: "", version: "v1", resource: "configmaps", namespace: "default", name: "kube-root-ca.crt"},
	}
	for _, key := range checks {
		if _, exists := api.store.get(key); !exists {
			t.Fatalf("expected seeded object %s/%s/%s missing", key.resource, key.namespace, key.name)
		}
	}
}

func TestServePodLog(t *testing.T) {
	cfg := config.Defaults()
	api, err := NewAPI(&cfg)
	if err != nil {
		t.Fatalf("NewAPI() error = %v", err)
	}
	c, recorder := testContext(t, http.MethodGet,
		"/api/v1/namespaces/kube-system/pods/coredns-6d8b4f6b7f-k7m2p/log", "", nil)
	if err := api.servePodLog(c, "kube-system", "coredns-6d8b4f6b7f-k7m2p"); err != nil {
		t.Fatalf("servePodLog() error = %v", err)
	}
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "CoreDNS") {
		t.Fatalf("log response = %d %q, want CoreDNS output", recorder.Code, recorder.Body.String())
	}
	c, recorder = testContext(t, http.MethodGet,
		"/api/v1/namespaces/default/pods/missing/log", "", nil)
	_ = api.servePodLog(c, "default", "missing")
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("missing pod log = %d, want 404", recorder.Code)
	}
	c, recorder = testContext(t, http.MethodGet,
		"/api/v1/namespaces/kube-system/pods/coredns-6d8b4f6b7f-k7m2p/log?container=bogus", "", nil)
	_ = api.servePodLog(c, "kube-system", "coredns-6d8b4f6b7f-k7m2p")
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("bad container log = %d, want 400", recorder.Code)
	}
}

func TestServeAccessReviewAllowsEverything(t *testing.T) {
	cfg := config.Defaults()
	api, err := NewAPI(&cfg)
	if err != nil {
		t.Fatalf("NewAPI() error = %v", err)
	}
	body := []byte(`{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":"create","resource":"secrets"}}}`)
	c, recorder := testContext(t, http.MethodPost,
		"/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", "application/json", body)
	description := api.resources[authorizationGroupVersion]["selfsubjectaccessreviews"]
	if err := api.serveAccessReview(c, description, ""); err != nil {
		t.Fatalf("serveAccessReview() error = %v", err)
	}
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", recorder.Code)
	}
	var review map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &review); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if objectMap(review["status"])["allowed"] != true {
		t.Fatalf("status = %#v, want allowed", review["status"])
	}
}

func TestServeMetricsListsNodesAndPods(t *testing.T) {
	cfg := config.Defaults()
	api, err := NewAPI(&cfg)
	if err != nil {
		t.Fatalf("NewAPI() error = %v", err)
	}
	c, recorder := testContext(t, http.MethodGet, "/apis/metrics.k8s.io/v1beta1/nodes", "", nil)
	description := api.resources[metricsGroupVersion]["nodes"]
	if err := api.serveMetrics(c, description, "", ""); err != nil {
		t.Fatalf("serveMetrics() error = %v", err)
	}
	var list map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &list); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if list["kind"] != "NodeMetricsList" {
		t.Fatalf("kind = %#v, want NodeMetricsList", list["kind"])
	}
	if items, ok := list["items"].([]any); !ok || len(items) != 3 {
		t.Fatalf("items = %#v, want 3 nodes", list["items"])
	}
	c, recorder = testContext(t, http.MethodGet, "/apis/metrics.k8s.io/v1beta1/namespaces/kube-system/pods", "", nil)
	description = api.resources[metricsGroupVersion]["pods"]
	if err := api.serveMetrics(c, description, "kube-system", ""); err != nil {
		t.Fatalf("serveMetrics() error = %v", err)
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &list); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if items, ok := list["items"].([]any); !ok || len(items) != 3 {
		t.Fatalf("items = %#v, want 3 kube-system pods", list["items"])
	}
}

// appendField encodes a length-delimited protobuf field.
func appendField(buf []byte, number protowire.Number, payload []byte) []byte {
	buf = protowire.AppendTag(buf, number, protowire.BytesType)
	return protowire.AppendBytes(buf, payload)
}

func appendString(buf []byte, number protowire.Number, value string) []byte {
	return appendField(buf, number, []byte(value))
}

func appendVarint(buf []byte, number protowire.Number, value uint64) []byte {
	buf = protowire.AppendTag(buf, number, protowire.VarintType)
	return protowire.AppendVarint(buf, value)
}

// Build a PodSpec wire message the way client-go serializes it: containers
// (field 2) with env/ports/volumeMounts, volumes (field 1), nodeName (10).
func TestProtoPodSpecDecodesEnvPortsAndVolumes(t *testing.T) {
	var envVar []byte
	envVar = appendString(envVar, 1, "DB_HOST")
	envVar = appendString(envVar, 2, "postgres")

	var port []byte
	port = appendString(port, 1, "http")
	port = appendVarint(port, 3, 8080)
	port = appendString(port, 4, "TCP")

	var mount []byte
	mount = appendString(mount, 1, "data")
	mount = appendString(mount, 3, "/data")

	var container []byte
	container = appendString(container, 1, "app")
	container = appendString(container, 2, "nginx")
	container = appendField(container, 7, envVar)
	container = appendField(container, 6, port)
	container = appendField(container, 9, mount)

	var secretSource []byte
	secretSource = appendString(secretSource, 1, "synthetic-api-token")
	var volume []byte
	volume = appendString(volume, 1, "data")
	volume = appendField(volume, 7, secretSource)

	var podSpec []byte
	podSpec = appendField(podSpec, 1, volume)
	podSpec = appendField(podSpec, 2, container)
	podSpec = appendString(podSpec, 10, "worker-01")

	spec := protoPodSpec(podSpec)
	containers, ok := spec["containers"].([]any)
	if !ok || len(containers) != 1 {
		t.Fatalf("containers = %#v", spec["containers"])
	}
	entry := containers[0].(map[string]any)
	if entry["name"] != "app" || entry["image"] != "nginx" {
		t.Fatalf("container = %#v", entry)
	}
	env := entry["env"].([]any)
	if env[0].(map[string]any)["name"] != "DB_HOST" || env[0].(map[string]any)["value"] != "postgres" {
		t.Fatalf("env = %#v", entry["env"])
	}
	ports := entry["ports"].([]any)
	if ports[0].(map[string]any)["containerPort"] != uint64(8080) {
		t.Fatalf("ports = %#v", entry["ports"])
	}
	mounts := entry["volumeMounts"].([]any)
	if mounts[0].(map[string]any)["mountPath"] != "/data" {
		t.Fatalf("volumeMounts = %#v", entry["volumeMounts"])
	}
	volumes := spec["volumes"].([]any)
	vol := volumes[0].(map[string]any)
	if vol["name"] != "data" || vol["secret"].(map[string]any)["secretName"] != "synthetic-api-token" {
		t.Fatalf("volumes = %#v", spec["volumes"])
	}
	if spec["nodeName"] != "worker-01" {
		t.Fatalf("nodeName = %#v", spec["nodeName"])
	}
}
