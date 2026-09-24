package handler

import (
	"testing"

	"helix-honeypot/config"
)

func TestSyncEndpoints(t *testing.T) {
	cfg, _ := config.NewConfig("")
	api, _ := NewAPI(cfg)
	gv := groupVersion{"apps", "v1"}
	deploy := map[string]any{
		"kind":     "Deployment",
		"metadata": map[string]any{"name": "web", "uid": "u1"},
		"spec": map[string]any{
			"replicas": 2,
			"selector": map[string]any{"matchLabels": map[string]any{"app": "web"}},
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": "web"}},
				"spec":     map[string]any{"containers": []any{map[string]any{"name": "nginx", "image": "nginx"}}},
			},
		},
	}
	deploy["status"] = syntheticStatus("Deployment", deploy)
	api.store.put(objectKey{"apps", "v1", "deployments", "default", "web"}, deploy, "ADDED")
	api.materializePods(gv, "default", "web", deploy)

	svc := map[string]any{
		"kind":     "Service",
		"metadata": map[string]any{"name": "web", "namespace": "default"},
		"spec":     map[string]any{"selector": map[string]any{"app": "web"}, "ports": []any{map[string]any{"port": 80}}},
	}
	api.store.put(objectKey{"", "v1", "services", "default", "web"}, svc, "ADDED")
	api.syncEndpointsForNamespace("default")

	ep, ok := api.store.get(objectKey{"", "v1", "endpoints", "default", "web"})
	if !ok {
		t.Fatal("endpoints not created")
	}
	subsets := objectList(ep["subsets"])
	if len(subsets) == 0 {
		t.Fatalf("no subsets: %#v", ep)
	}
	addrs := objectList(objectMap(subsets[0])["addresses"])
	t.Logf("addresses: %d", len(addrs))
	if len(addrs) != 2 {
		t.Fatalf("addresses = %d, want 2", len(addrs))
	}
}
