package handler

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"helix-honeypot/model"
)

const (
	maxStoredObjects     = 4096
	maxStoredBytes       = 32 << 20
	maxStoredObjectBytes = 256 << 10
	maxSeedObjects       = 512
	maxSeedNamespaces    = 128
	maxSeedSecrets       = 128
	maxLegacySeedTokens  = 128
	maxSecretDataKeys    = 512
)

var errStoreCapacity = errors.New("simulated API object store capacity reached")
var errObjectAlreadyExists = errors.New("simulated API object already exists")
var errGeneratedNameCapacity = errors.New("simulated API generated-name capacity reached")
var errInvalidGeneratedName = errors.New("metadata.generateName cannot produce a valid object name")

type objectKey struct {
	group, version, resource, namespace, name string
}

type watchEvent struct {
	Type   string         `json:"type"`
	Object map[string]any `json:"object"`
}

type watcher struct {
	id        uint64
	group     string
	version   string
	resource  string
	namespace string
	labels    []selectorRequirement
	fields    []selectorRequirement
	ch        chan watchEvent
}

type objectStore struct {
	mu             sync.RWMutex
	objects        map[objectKey]map[string]any
	watchers       map[uint64]*watcher
	nextWatcher    uint64
	resourceRev    uint64
	storedBytes    int64
	generatedNames uint64
	startedAt      time.Time
}

func newObjectStore() *objectStore {
	return &objectStore{
		objects:     make(map[objectKey]map[string]any),
		watchers:    make(map[uint64]*watcher),
		startedAt:   time.Now().UTC().Truncate(time.Second),
		resourceRev: 1000,
	}
}

func (s *objectStore) put(key objectKey, object map[string]any, eventType string) error {
	s.mu.Lock()
	metadata := objectMap(object["metadata"])
	s.resourceRev++
	metadata["resourceVersion"] = strconv.FormatUint(s.resourceRev, 10)
	object["metadata"] = metadata
	encoded, err := json.Marshal(object)
	if err != nil || len(encoded) > maxStoredObjectBytes {
		s.resourceRev--
		s.mu.Unlock()
		return errStoreCapacity
	}
	oldBytes := int64(0)
	previous, exists := s.objects[key]
	if exists && eventType == "ADDED" {
		s.resourceRev--
		s.mu.Unlock()
		return errObjectAlreadyExists
	}
	if exists {
		if previousEncoded, marshalErr := json.Marshal(previous); marshalErr == nil {
			oldBytes = int64(len(previousEncoded))
		}
	} else if len(s.objects) >= maxStoredObjects {
		s.resourceRev--
		s.mu.Unlock()
		return errStoreCapacity
	}
	newTotal := s.storedBytes - oldBytes + int64(len(encoded))
	if newTotal > maxStoredBytes {
		s.resourceRev--
		s.mu.Unlock()
		return errStoreCapacity
	}
	copyOfObject := cloneObject(object)
	s.objects[key] = copyOfObject
	s.storedBytes = newTotal
	s.publishLocked(key, eventType, copyOfObject)
	s.mu.Unlock()
	return nil
}

func (s *objectStore) get(key objectKey) (map[string]any, bool) {
	s.mu.RLock()
	object, exists := s.objects[key]
	if exists {
		object = cloneObject(object)
	}
	s.mu.RUnlock()
	return object, exists
}

func (s *objectStore) listPage(gv groupVersion, namespace, resource string, labels, fields []selectorRequirement, offset, limit int) ([]map[string]any, int, int, error) {
	type candidate struct {
		key    objectKey
		object map[string]any
	}
	s.mu.RLock()
	candidates := make([]candidate, 0)
	for key, object := range s.objects {
		if key.group != gv.Group || key.version != gv.Version || key.resource != resource {
			continue
		}
		if namespace != "" && key.namespace != namespace {
			continue
		}
		if objectMatches(object, labels, fields) {
			candidates = append(candidates, candidate{key: key, object: object})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].key.namespace != candidates[j].key.namespace {
			return candidates[i].key.namespace < candidates[j].key.namespace
		}
		return candidates[i].key.name < candidates[j].key.name
	})
	total := len(candidates)
	if offset < 0 || offset > total {
		s.mu.RUnlock()
		return nil, total, 0, fmt.Errorf("continue token offset is invalid")
	}
	if limit <= 0 || limit > maxListPageItems {
		limit = maxListPageItems
	}
	items := make([]map[string]any, 0, limit)
	usedBytes := 0
	index := offset
	for ; index < total && len(items) < limit; index++ {
		encoded, err := json.Marshal(candidates[index].object)
		if err != nil {
			s.mu.RUnlock()
			return nil, total, 0, fmt.Errorf("stored object could not be encoded")
		}
		if usedBytes+len(encoded) > maxListPageBytes && len(items) > 0 {
			break
		}
		usedBytes += len(encoded)
		items = append(items, cloneObject(candidates[index].object))
	}
	s.mu.RUnlock()
	return items, total, index, nil
}

func (s *objectStore) delete(key objectKey) (map[string]any, bool) {
	s.mu.Lock()
	object, exists := s.objects[key]
	if exists {
		delete(s.objects, key)
		if encoded, err := json.Marshal(object); err == nil {
			s.storedBytes -= int64(len(encoded))
		}
		s.resourceRev++
		copyOfObject := cloneObject(object)
		s.publishLocked(key, "DELETED", copyOfObject)
	}
	s.mu.Unlock()
	return cloneObject(object), exists
}

func (s *objectStore) deleteMatching(gv groupVersion, namespace, resource, labelSelector, fieldSelector string) int {
	labels, _ := parseSelector(labelSelector)
	fields, _ := parseSelector(fieldSelector)
	s.mu.RLock()
	keys := make([]objectKey, 0)
	for key, object := range s.objects {
		if key.group == gv.Group && key.version == gv.Version && key.resource == resource && (namespace == "" || key.namespace == namespace) && objectMatches(object, labels, fields) {
			keys = append(keys, key)
		}
	}
	s.mu.RUnlock()
	deleted := 0
	for _, key := range keys {
		if _, exists := s.delete(key); exists {
			deleted++
		}
	}
	return deleted
}

func (s *objectStore) resourceVersion() string {
	s.mu.RLock()
	version := strconv.FormatUint(s.resourceRev, 10)
	s.mu.RUnlock()
	return version
}

func (s *objectStore) nextName(prefix string) (string, error) {
	s.mu.Lock()
	if s.generatedNames == ^uint64(0) {
		s.mu.Unlock()
		return "", errGeneratedNameCapacity
	}
	next := s.generatedNames + 1
	// A fixed-width suffix keeps distinct prefixes unambiguous without retaining
	// attacker-controlled prefixes in an unbounded counter map.
	name := fmt.Sprintf("%s%020d", prefix, next)
	if !validObjectName(name) {
		s.mu.Unlock()
		return "", errInvalidGeneratedName
	}
	s.generatedNames = next
	s.mu.Unlock()
	return name, nil
}

func (s *objectStore) namespaceExists(namespace string) bool {
	_, exists := s.get(objectKey{group: "", version: "v1", resource: "namespaces", name: namespace})
	return exists
}

func (s *objectStore) watch(gv groupVersion, namespace, resource string, labels, fields []selectorRequirement) *watcher {
	s.mu.Lock()
	s.nextWatcher++
	watcher := &watcher{
		id: s.nextWatcher, group: gv.Group, version: gv.Version,
		resource: resource, namespace: namespace, labels: labels, fields: fields, ch: make(chan watchEvent, 4),
	}
	s.watchers[watcher.id] = watcher
	s.mu.Unlock()
	return watcher
}

func (s *objectStore) unwatch(watcher *watcher) {
	s.mu.Lock()
	if _, exists := s.watchers[watcher.id]; exists {
		delete(s.watchers, watcher.id)
		close(watcher.ch)
	}
	s.mu.Unlock()
}

func (s *objectStore) publishLocked(key objectKey, eventType string, object map[string]any) {
	for id, watcher := range s.watchers {
		if watcher.group != key.group || watcher.version != key.version || watcher.resource != key.resource {
			continue
		}
		if watcher.namespace != "" && watcher.namespace != key.namespace {
			continue
		}
		if !objectMatches(object, watcher.labels, watcher.fields) {
			continue
		}
		select {
		case watcher.ch <- watchEvent{Type: eventType, Object: cloneObject(object)}:
		default:
			delete(s.watchers, id)
			close(watcher.ch)
		}
	}
}

func (s *objectStore) seed(gv groupVersion, resource, namespace, name string, object map[string]any) bool {
	metadata := objectMap(object["metadata"])
	metadata["name"] = name
	if namespace != "" {
		metadata["namespace"] = namespace
	}
	metadata["uid"] = stableUID(apiVersionFor(gv) + "/" + namespace + "/" + resource + "/" + name)
	if _, exists := metadata["creationTimestamp"]; !exists {
		metadata["creationTimestamp"] = s.startedAt.Format(time.RFC3339)
	}
	object["apiVersion"] = apiVersionFor(gv)
	if kind, ok := sKind(gv, resource); ok {
		object["kind"] = kind
	}
	object["metadata"] = metadata
	return s.put(objectKey{gv.Group, gv.Version, resource, namespace, name}, object, "ADDED") == nil
}

func sKind(gv groupVersion, resourceName string) (string, bool) {
	for _, resource := range apiCatalog[gv] {
		if resource.Name == resourceName {
			return resource.Kind, true
		}
	}
	return "", false
}

func cloneObject(object map[string]any) map[string]any {
	if object == nil {
		return nil
	}
	encoded, err := json.Marshal(object)
	if err != nil {
		return map[string]any{}
	}
	copyOfObject := make(map[string]any)
	if err := json.Unmarshal(encoded, &copyOfObject); err != nil {
		return map[string]any{}
	}
	return copyOfObject
}

func (a *API) seed(cfg *model.Config) {
	if a == nil || a.store == nil || cfg == nil {
		return
	}
	store := a.store
	seededObjects := 0
	seed := func(gv groupVersion, resource, namespace, name string, object map[string]any) bool {
		if seededObjects >= maxSeedObjects {
			return false
		}
		if store.seed(gv, resource, namespace, name, object) {
			seededObjects++
			return true
		}
		return false
	}

	seededNamespaces := make(map[string]struct{}, maxSeedNamespaces)
	namespaceOrder := make([]string, 0, maxSeedNamespaces)
	addNamespace := func(namespace string) {
		if len(seededNamespaces) >= maxSeedNamespaces || !validNamespaceName(namespace) {
			return
		}
		if _, exists := seededNamespaces[namespace]; exists {
			return
		}
		seededNamespaces[namespace] = struct{}{}
		namespaceOrder = append(namespaceOrder, namespace)
	}
	for _, namespace := range []string{"default", "kube-system", "kube-public", "kube-node-lease"} {
		addNamespace(namespace)
	}
	// Prioritize namespaces needed by custom secrets before optional configured
	// namespaces so every accepted honeytoken has a matching Namespace object.
	for index, honeytoken := range cfg.K8S.Honeytokens {
		if index >= maxSeedSecrets {
			break
		}
		if !validObjectName(honeytoken.Name) {
			continue
		}
		namespace := strings.TrimSpace(honeytoken.Namespace)
		if namespace == "" {
			namespace = "default"
		}
		addNamespace(namespace)
	}
	for index, namespace := range cfg.K8S.Namespaces {
		if index >= maxSeedObjects {
			break
		}
		addNamespace(strings.TrimSpace(namespace))
	}
	for _, namespace := range namespaceOrder {
		seed(groupVersion{"", "v1"}, "namespaces", "", namespace, map[string]any{
			"metadata": map[string]any{"labels": map[string]string{"kubernetes.io/metadata.name": namespace}},
			"status":   map[string]any{"phase": "Active"},
		})
	}

	controlPlane := []struct{ name, role string }{
		{"control-plane-01", "control-plane"},
		{"worker-01", "worker"},
		{"worker-02", "worker"},
	}
	for i, node := range controlPlane {
		address := nodeAddress(cfg.K8S.IPBase, 10+i)
		seed(groupVersion{"", "v1"}, "nodes", "", node.name, map[string]any{
			"metadata": map[string]any{"labels": map[string]string{
				"kubernetes.io/hostname":               node.name,
				"node-role.kubernetes.io/" + node.role: "",
			}},
			"spec": map[string]any{"podCIDR": podCIDR(cfg.K8S.IPBase, i), "taints": []any{}},
			"status": map[string]any{
				"capacity":    map[string]string{"cpu": "4", "memory": "16Gi", "pods": "110"},
				"allocatable": map[string]string{"cpu": "3900m", "memory": "15Gi", "pods": "110"},
				"addresses":   []any{map[string]string{"type": "InternalIP", "address": address}, map[string]any{"type": "Hostname", "address": node.name}},
				"nodeInfo":    map[string]string{"containerRuntimeVersion": "containerd://2.1.0", "kubeletVersion": a.version + ".0", "kubeProxyVersion": a.version + ".0", "operatingSystem": "linux", "architecture": "amd64", "osImage": "Linux", "kernelVersion": "6.8.0"},
				"conditions":  []any{map[string]any{"type": "Ready", "status": "True", "reason": "KubeletReady", "lastHeartbeatTime": store.startedAt.Format(time.RFC3339), "lastTransitionTime": store.startedAt.Format(time.RFC3339)}}},
		})
		seed(groupVersion{"coordination.k8s.io", "v1"}, "leases", "kube-node-lease", node.name, map[string]any{
			"spec": map[string]any{
				"holderIdentity":       node.name,
				"leaseDurationSeconds": 40,
				"renewTime":            store.startedAt.Format("2006-01-02T15:04:05.000000Z07:00"),
				"acquireTime":          store.startedAt.Format("2006-01-02T15:04:05.000000Z07:00"),
				"leaseTransitions":     0,
			},
		})
	}

	// Every real cluster exposes the apiserver's own Service and Endpoints in
	// the default namespace, independent of the optional workload generators.
	seed(groupVersion{"", "v1"}, "services", "default", "kubernetes", map[string]any{
		"spec": map[string]any{"clusterIP": serviceAddress(cfg.K8S.IPBase, 20), "ports": []any{map[string]any{"name": "https", "port": 443, "protocol": "TCP", "targetPort": 6443}}, "type": "ClusterIP"},
	})
	seed(groupVersion{"", "v1"}, "endpoints", "default", "kubernetes", map[string]any{
		"subsets": []any{map[string]any{
			"addresses": []any{map[string]any{"ip": nodeAddress(cfg.K8S.IPBase, 10)}},
			"ports":     []any{map[string]any{"name": "https", "port": 6443, "protocol": "TCP"}},
		}},
	})

	if cfg.K8S.GenerateKubeSys {
		for i, pod := range []struct{ name, image string }{
			{"coredns-6d8b4f6b7f-k7m2p", "registry.k8s.io/coredns/coredns:v1.14.7"},
			{"kube-proxy-2k9jv", "registry.k8s.io/kube-proxy:v1.37.0"},
			{"metrics-server-7db5f8d5b9-5c2tx", "registry.k8s.io/metrics-server/metrics-server:v0.9.0"},
		} {
			seed(groupVersion{"", "v1"}, "pods", "kube-system", pod.name, podObject(pod.name, "kube-system", pod.image, podAddress(cfg.K8S.IPBase, 2, 30+i), "worker-01", "k8s-app", "system", nodeAddress(cfg.K8S.IPBase, 11)))
		}
		seed(groupVersion{"", "v1"}, "services", "kube-system", "kube-dns", map[string]any{
			"spec":   map[string]any{"clusterIP": serviceAddress(cfg.K8S.IPBase, 21), "ports": []any{map[string]any{"name": "dns", "port": 53, "protocol": "UDP"}, map[string]any{"name": "dns-tcp", "port": 53, "protocol": "TCP"}}, "selector": map[string]string{"k8s-app": "system"}, "type": "ClusterIP"},
			"status": map[string]any{"loadBalancer": map[string]any{}},
		})
	}

	if cfg.K8S.GenerateRand {
		for i, pod := range []struct{ name, image string }{
			{"api-6d7949c6d7-vzd8q", "registry.k8s.io/pause:3.10"},
			{"web-7f5cb9d59c-hk6qn", "nginx:1.30.5"},
			{"redis-0", "redis:7.4"},
		} {
			seed(groupVersion{"", "v1"}, "pods", "default", pod.name, podObject(pod.name, "default", pod.image, podAddress(cfg.K8S.IPBase, 2, 40+i), "worker-01", "app", strings.Split(pod.name, "-")[0], nodeAddress(cfg.K8S.IPBase, 11)))
		}
		seed(groupVersion{"apps", "v1"}, "deployments", "default", "web", map[string]any{
			"spec":   map[string]any{"replicas": 1, "selector": map[string]any{"matchLabels": map[string]string{"app": "web"}}, "template": map[string]any{"metadata": map[string]any{"labels": map[string]string{"app": "web"}}, "spec": map[string]any{"containers": []any{map[string]any{"name": "web", "image": "nginx:1.30.5", "ports": []any{map[string]any{"containerPort": 80}}}}}}},
			"status": map[string]any{"availableReplicas": 1, "readyReplicas": 1, "replicas": 1, "updatedReplicas": 1},
		})
	}

	for index, honeytoken := range cfg.K8S.Honeytokens {
		if index >= maxSeedSecrets {
			break
		}
		if !validObjectName(honeytoken.Name) {
			continue
		}
		namespace := strings.TrimSpace(honeytoken.Namespace)
		if namespace == "" {
			namespace = "default"
		}
		if !validNamespaceName(namespace) {
			continue
		}
		if _, exists := seededNamespaces[namespace]; !exists {
			continue
		}
		data, ok := encodeSecretData(honeytoken.Data)
		if !ok {
			continue
		}
		secretType := strings.TrimSpace(honeytoken.Type)
		if secretType == "" {
			secretType = "Opaque"
		}
		if len(secretType) > 256 {
			continue
		}
		seed(groupVersion{"", "v1"}, "secrets", namespace, honeytoken.Name, map[string]any{
			"type": secretType,
			"data": data,
		})
	}

	// Keep the older token fields working for existing configurations. Custom
	// honeytokens take precedence when both configurations use the same Secret key.
	if len(cfg.K8S.TokenValues) > 0 {
		for i, token := range cfg.K8S.TokenValues {
			if i >= maxLegacySeedTokens {
				break
			}
			if len(token) > 4096 {
				continue
			}
			name := fmt.Sprintf("decoy-credential-%02d", i+1)
			if i < len(cfg.K8S.TokenNames) && strings.TrimSpace(cfg.K8S.TokenNames[i]) != "" {
				name = cfg.K8S.TokenNames[i]
			}
			seed(groupVersion{"", "v1"}, "secrets", "default", name, map[string]any{
				"type": "Opaque", "data": map[string]string{"token": base64.StdEncoding.EncodeToString([]byte(token))},
			})
		}
	}

	// Every namespace on a real cluster carries a default ServiceAccount and
	// the kube-root-ca.crt ConfigMap. These run last so configured honeytokens
	// always win the bounded seed budget.
	for _, namespace := range namespaceOrder {
		seed(groupVersion{"", "v1"}, "serviceaccounts", namespace, "default", map[string]any{})
		seed(groupVersion{"", "v1"}, "configmaps", namespace, "kube-root-ca.crt", map[string]any{
			"data": map[string]string{"ca.crt": rootCAPEM},
		})
	}

	// A real cluster registers one APIService per served group/version, all
	// satisfied by the local apiserver; metrics.k8s.io points at the
	// metrics-server Service instead.
	available := map[string]any{"type": "Available", "status": "True", "reason": "Passed", "lastTransitionTime": store.startedAt.Format(time.RFC3339)}
	for gv := range apiCatalog {
		name := gv.Version + "."
		if gv.Group == "" {
			name = gv.Version
		} else {
			name += gv.Group
		}
		spec := map[string]any{"group": gv.Group, "version": gv.Version, "groupPriorityMinimum": 1000, "versionPriority": 15}
		if gv.Group == "metrics.k8s.io" {
			spec["service"] = map[string]any{"name": "metrics-server", "namespace": "kube-system", "port": 443}
		}
		seed(groupVersion{"apiregistration.k8s.io", "v1"}, "apiservices", "", name, map[string]any{
			"spec":   spec,
			"status": map[string]any{"conditions": []any{available}},
		})
	}

	// The cert-manager CRDs imply its webhook is registered too.
	seed(groupVersion{"admissionregistration.k8s.io", "v1"}, "validatingwebhookconfigurations", "", "cert-manager-webhook", map[string]any{
		"webhooks": []any{map[string]any{
			"name":                    "webhook.cert-manager.io",
			"admissionReviewVersions": []string{"v1"},
			"sideEffects":             "None",
			"failurePolicy":           "Fail",
			"clientConfig":            map[string]any{"service": map[string]any{"name": "cert-manager-webhook", "namespace": "cert-manager", "path": "/validate"}},
			"rules": []any{map[string]any{
				"apiGroups": []string{"cert-manager.io"}, "apiVersions": []string{"v1"},
				"operations": []string{"CREATE", "UPDATE"}, "resources": []string{"*/*"},
			}},
		}},
	})

	// A cluster that's been running a while accumulates third-party CRDs.
	for _, crd := range []struct{ name, group, plural, kind string }{
		{"prometheusrules.monitoring.coreos.com", "monitoring.coreos.com", "prometheusrules", "PrometheusRule"},
		{"certificates.cert-manager.io", "cert-manager.io", "certificates", "Certificate"},
		{"ingressroutes.traefik.io", "traefik.io", "ingressroutes", "IngressRoute"},
	} {
		seed(groupVersion{"apiextensions.k8s.io", "v1"}, "customresourcedefinitions", "", crd.name, map[string]any{
			"spec": map[string]any{
				"group": crd.group,
				"names": map[string]any{"plural": crd.plural, "singular": strings.ToLower(crd.kind), "kind": crd.kind, "listKind": crd.kind + "List"},
				"scope": "Namespaced",
				"versions": []any{map[string]any{
					"name": "v1", "served": true, "storage": true,
					"schema": map[string]any{"openAPIV3Schema": map[string]any{"type": "object", "x-kubernetes-preserve-unknown-fields": true}},
				}},
			},
			"status": map[string]any{
				"acceptedNames": map[string]any{"plural": crd.plural, "kind": crd.kind},
				"conditions":    []any{map[string]any{"type": "Established", "status": "True", "reason": "InitialNamesAccepted", "lastTransitionTime": store.startedAt.Format(time.RFC3339)}},
			},
		})
	}
	for _, role := range []string{
		"cluster-admin", "admin", "edit", "view",
		"system:aggregate-to-admin", "system:aggregate-to-edit", "system:aggregate-to-view",
		"system:basic-user", "system:discovery", "system:public-info-viewer",
		"system:auth-delegator", "system:kube-controller-manager", "system:kube-scheduler",
		"system:controller:attachdetach-controller", "system:controller:deployment-controller",
		"system:kube-dns", "system:kube-proxy", "system:node", "system:node-proxier",
		"system:metrics-server",
	} {
		seed(groupVersion{"rbac.authorization.k8s.io", "v1"}, "clusterroles", "", role, map[string]any{
			"rules": []any{},
		})
	}
	for _, binding := range []string{
		"cluster-admin", "system:basic-user", "system:discovery", "system:public-info-viewer",
		"system:kube-controller-manager", "system:kube-scheduler", "system:metrics-server",
	} {
		seed(groupVersion{"rbac.authorization.k8s.io", "v1"}, "clusterrolebindings", "", binding, map[string]any{
			"roleRef":  map[string]string{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": binding},
			"subjects": []any{},
		})
	}
}

const rootCAPEM = `-----BEGIN CERTIFICATE-----
MIIDBTCCAe2gAwIBAgIIRg9i3sQzLw4wDQYJKoZIhvcNAQELBQAwFTETMBEGA1UE
AxMKa3ViZXJuZXRlczAeFw0yNjA5MjQxMjUxMDdaFw0zNjA5MjIxMjUxMDdaMBUx
EzARBgNVBAMTCmt1YmVybmV0ZXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDczvdV7kY+GxXMJgX0hC8z3mJzNbxqSxP4uKqJjZ0dYkL4WQ1fK0mHv7nG
k7Hj9hZ9Kp2WvQpZJ8q7x0h0p9uF3kY6gZqJ0z2m7YvB0cH9k4wQ4uK1y9z2H8v
n0Xb7Q0mD2gP1vY4z5iH8gN7kX0wM3tL9cF1bV6xK8jH2dP5sA4fG9nQ0wE7rT3
yU6iO1pA8sD4fG7hJ0kL2zX5cV8bN1mQ4wR7tY3uI6oP9aS2dF5gH8jK1lZ4xC7
vB0nM3qW6eR9tY2uI5oP8aS1dF4gH7jK0lZ3xC6vB9nM2qW5eR8tY1uI4oP7aS0
dF3gH6jK9lZ2xC5vB8nM1qW4eR7tY0uI3oP6aS9dF2gH5jK8lZ1xC4vB7nM0qW
AgMBAAGjRjBEMA4GA1UdDwEB/wQEAwICpDAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud
DgQWBBQ0bW9ja2VkLWNhLWZvci10ZXN0MA0GCSqGSIb3DQEBCwUAA4IBAQCqK3z8
pV7jQ0dY2mF8hN5sK1xW9rT4uI6oP3aS7dG0fJ4kL9zX2cV5bN8mQ1wR4tY7uI0
-----END CERTIFICATE-----`

func encodeSecretData(data map[string]string) (map[string]string, bool) {
	if len(data) > maxSecretDataKeys {
		return nil, false
	}
	encoded := make(map[string]string, len(data))
	encodedBytes := 0
	for key, value := range data {
		if !validSecretDataKey(key) || len(value) > maxStoredObjectBytes {
			return nil, false
		}
		valueBytes := base64.StdEncoding.EncodedLen(len(value))
		if encodedBytes+len(key)+valueBytes > maxStoredObjectBytes {
			return nil, false
		}
		encodedBytes += len(key) + valueBytes
		encoded[key] = base64.StdEncoding.EncodeToString([]byte(value))
	}
	return encoded, true
}

func validSecretDataKey(key string) bool {
	if key == "" || len(key) > 253 {
		return false
	}
	for _, character := range key {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func podObject(name, namespace, image, ip, node, labelKey, labelValue, hostIP string) map[string]any {
	return map[string]any{
		"metadata": map[string]any{
			"name": name, "namespace": namespace,
			"labels": map[string]string{labelKey: labelValue},
		},
		"spec": map[string]any{
			"nodeName":   node,
			"containers": []any{map[string]any{"name": "main", "image": image, "imagePullPolicy": "IfNotPresent"}},
		},
		"status": map[string]any{
			"phase": "Running", "podIP": ip,
			"hostIP":            hostIP,
			"conditions":        []any{map[string]any{"type": "Ready", "status": "True", "reason": "PodReady"}},
			"containerStatuses": []any{map[string]any{"name": "main", "ready": true, "restartCount": 0, "image": image, "imageID": "containerd://sha256:0000000000000000", "state": map[string]any{"running": map[string]any{"startedAt": time.Now().UTC().Format(time.RFC3339)}}}},
		},
		"apiVersion": "v1", "kind": "Pod",
	}
}

func nodeAddress(base string, offset int) string {
	parts := addressParts(base)
	return fmt.Sprintf("%d.%d.%d.%d", parts[0], parts[1], parts[2], offset)
}

func podAddress(base string, subnetOffset, hostOffset int) string {
	parts := addressParts(base)
	thirdOctet := (parts[2] + subnetOffset) % 256
	return fmt.Sprintf("%d.%d.%d.%d", parts[0], parts[1], thirdOctet, hostOffset)
}

func podCIDR(base string, subnetOffset int) string {
	return podAddress(base, subnetOffset+1, 0) + "/24"
}

func serviceAddress(base string, hostOffset int) string {
	return nodeAddress(base, hostOffset)
}

func addressParts(base string) [4]int {
	parts := strings.Split(base, ".")
	if len(parts) != 4 {
		return [4]int{10, 42, 0, 0}
	}
	var address [4]int
	for i, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 || value > 255 {
			return [4]int{10, 42, 0, 0}
		}
		address[i] = value
	}
	return address
}

// seedNamespaceObjects provisions what the namespace controller and root CA
// publisher create in every new namespace: a default ServiceAccount and the
// kube-root-ca.crt ConfigMap.
func (a *API) seedNamespaceObjects(namespace string) {
	now := time.Now().UTC().Format(time.RFC3339)
	_ = a.store.put(objectKey{"", "v1", "serviceaccounts", namespace, "default"}, map[string]any{
		"apiVersion": "v1", "kind": "ServiceAccount",
		"metadata": map[string]any{"name": "default", "namespace": namespace, "creationTimestamp": now,
			"uid": stableUID("serviceaccount/" + namespace + "/default")},
	}, "ADDED")
	_ = a.store.put(objectKey{"", "v1", "configmaps", namespace, "kube-root-ca.crt"}, map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{"name": "kube-root-ca.crt", "namespace": namespace, "creationTimestamp": now,
			"uid": stableUID("configmap/" + namespace + "/kube-root-ca.crt")},
		"data": map[string]any{"ca.crt": rootCAPEM},
	}, "ADDED")
}
