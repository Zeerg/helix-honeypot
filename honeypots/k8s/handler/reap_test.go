package handler

import (
	"testing"

	"helix-honeypot/config"
)

// materializePods is the controller emulation: workload creates should
// produce pods, scaling should add/reap them, and the pods must carry the
// workload's pod template. For Deployments the pods belong to a
// materialized ReplicaSet — Deployment → RS → Pod like a real cluster.
func TestMaterializePodsLifecycle(t *testing.T) {
	cfg, err := config.NewConfig("")
	if err != nil {
		t.Fatal(err)
	}
	api, err := NewAPI(cfg)
	if err != nil {
		t.Fatal(err)
	}
	gv := groupVersion{"apps", "v1"}
	deploy := map[string]any{
		"kind":     "Deployment",
		"metadata": map[string]any{"name": "web", "uid": "u1"},
		"spec": map[string]any{
			"replicas": 2,
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": "web"}},
				"spec":     map[string]any{"containers": []any{map[string]any{"name": "nginx", "image": "nginx:1.25"}}},
			},
		},
	}
	// materializeDeployment writes status back to the deployment object in
	// the store, so seed it the way the create path would.
	deploy["status"] = syntheticStatus("Deployment", deploy)
	if err := api.store.put(objectKey{"apps", "v1", "deployments", "default", "web"}, deploy, "ADDED"); err != nil {
		t.Fatal(err)
	}
	api.materializePods(gv, "default", "web", deploy)

	rsName := "web-" + templateHash(deploy)

	count := func() int {
		_, total, _, err := api.store.listPage(groupVersion{"", "v1"}, "default", "pods", nil, nil, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		return total
	}
	if got := count(); got != 2 {
		t.Fatalf("pods after create = %d, want 2", got)
	}
	if _, ok := api.store.get(objectKey{"apps", "v1", "replicasets", "default", rsName}); !ok {
		t.Fatalf("expected ReplicaSet %s missing", rsName)
	}
	pod, ok := api.store.get(objectKey{"", "v1", "pods", "default", rsName + "-" + suffixFor(rsName, 0)})
	if !ok {
		t.Fatalf("expected pod %s missing", rsName+"-"+suffixFor(rsName, 0))
	}
	owners := objectList(objectMap(pod["metadata"])["ownerReferences"])
	if len(owners) != 1 || stringField(objectMap(owners[0]), "name") != rsName || stringField(objectMap(owners[0]), "kind") != "ReplicaSet" {
		t.Fatalf("ownerReferences = %#v, want ReplicaSet %s", owners, rsName)
	}
	if stringField(objectMap(pod["status"]), "phase") != "Running" {
		t.Fatalf("phase = %v, want Running", objectMap(pod["status"])["phase"])
	}

	deploy["spec"].(map[string]any)["replicas"] = 5
	api.materializePods(gv, "default", "web", deploy)
	if got := count(); got != 5 {
		t.Fatalf("pods after scale up = %d, want 5", got)
	}
	deploy["spec"].(map[string]any)["replicas"] = 1
	api.materializePods(gv, "default", "web", deploy)
	if got := count(); got != 1 {
		t.Fatalf("pods after scale down = %d, want 1", got)
	}

	api.reapOwnedPods("default", "web")
	if got := count(); got != 0 {
		t.Fatalf("pods after workload delete = %d, want 0", got)
	}
	if _, total, _, err := api.store.listPage(groupVersion{"apps", "v1"}, "default", "replicasets", nil, nil, 0, 100); err != nil || total != 0 {
		t.Fatalf("replicasets after workload delete = %d, want 0", total)
	}
}

// A template change (e.g. kubectl set image) must roll out a new ReplicaSet
// with new pod names, retiring the old RS to zero like a real rollout.
func TestDeploymentRollsOnTemplateChange(t *testing.T) {
	cfg, err := config.NewConfig("")
	if err != nil {
		t.Fatal(err)
	}
	api, err := NewAPI(cfg)
	if err != nil {
		t.Fatal(err)
	}
	gv := groupVersion{"apps", "v1"}
	deploy := map[string]any{
		"kind":     "Deployment",
		"metadata": map[string]any{"name": "web", "uid": "u1"},
		"spec": map[string]any{
			"replicas": 1,
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": "web"}},
				"spec":     map[string]any{"containers": []any{map[string]any{"name": "nginx", "image": "nginx:1.25"}}},
			},
		},
	}
	deploy["status"] = syntheticStatus("Deployment", deploy)
	if err := api.store.put(objectKey{"apps", "v1", "deployments", "default", "web"}, deploy, "ADDED"); err != nil {
		t.Fatal(err)
	}
	api.materializePods(gv, "default", "web", deploy)
	oldRS := "web-" + templateHash(deploy)

	containers := objectMap(deploy["spec"])["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)
	containers[0].(map[string]any)["image"] = "nginx:1.26"
	api.materializePods(gv, "default", "web", deploy)
	newRS := "web-" + templateHash(deploy)

	if oldRS == newRS {
		t.Fatal("template change produced identical ReplicaSet name")
	}
	pods, _, _, err := api.store.listPage(groupVersion{"", "v1"}, "default", "pods", nil, nil, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(pods) != 1 || stringField(objectMap(pods[0]["metadata"]), "name") != newRS+"-"+suffixFor(newRS, 0) {
		names := []string{}
		for _, pod := range pods {
			names = append(names, stringField(objectMap(pod["metadata"]), "name"))
		}
		t.Fatalf("pods after image change = %v, want one pod under %s", names, newRS)
	}
	oldRSObject, ok := api.store.get(objectKey{"apps", "v1", "replicasets", "default", oldRS})
	if !ok {
		t.Fatalf("old ReplicaSet %s should be retained for rollout history", oldRS)
	}
	if got := intField(objectMap(oldRSObject["spec"]), "replicas"); got != 0 {
		t.Fatalf("old ReplicaSet replicas = %d, want 0", got)
	}
}
