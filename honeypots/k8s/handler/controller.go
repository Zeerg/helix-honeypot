package handler

// Controller emulation: when a workload object (Deployment, StatefulSet,
// DaemonSet, ReplicaSet, Job) is created or scaled, a real cluster's
// controllers materialize Pods. This synthesizes those pods so `kubectl get
// pods`, `logs`, and `describe` see an inhabited cluster rather than a bare
// workload shell. Deleting the workload reaps the owned pods, matching
// cascading delete semantics.

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const maxControllerPods = 64 // cap pods materialized per workload

// isWorkloadKind reports whether the kind's controller materializes pods.
func isWorkloadKind(kind string) bool {
	switch kind {
	case "Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "Job":
		return true
	}
	return false
}

// workloadPods returns the pod names a controller would maintain for the
// given workload object.
func workloadPodNames(kind, name string, replicas, nodeCount int) []string {
	names := make([]string, 0, replicas)
	switch kind {
	case "StatefulSet":
		for i := 0; i < replicas; i++ {
			names = append(names, fmt.Sprintf("%s-%d", name, i))
		}
	case "DaemonSet":
		for i := 0; i < nodeCount && i < replicas; i++ {
			names = append(names, fmt.Sprintf("%s-%s", name, suffixFor(name, i)))
		}
	case "Deployment", "ReplicaSet":
		rs := suffixFor(name+"-rs", 0)
		for i := 0; i < replicas; i++ {
			names = append(names, fmt.Sprintf("%s-%s-%s", name, rs, suffixFor(name, i+1)))
		}
	case "Job":
		names = append(names, fmt.Sprintf("%s-%s", name, suffixFor(name, 0)))
	}
	return names
}

// suffixFor derives a stable 5-char alphanumeric suffix the way controller
// name generation looks (FNV hash → base-32-ish). Deterministic so repeated
// reconciles target the same pods.
func suffixFor(seed string, index int) string {
	sum := fnv32(seed + "/" + fmt.Sprint(index))
	const alphabet = "bcdfghjklmnpqrstvwxz2456789"
	out := make([]byte, 5)
	for i := range out {
		out[i] = alphabet[sum%26]
		sum /= 26
	}
	return string(out)
}

func fnv32(value string) uint32 {
	hash := uint32(2166136261)
	for i := 0; i < len(value); i++ {
		hash = (hash ^ uint32(value[i])) * 16777619
	}
	return hash
}

// templateHash produces the pod-template-hash a deployment controller would
// stamp — it changes when the pod template changes, so `kubectl set image`
// rolls out a new ReplicaSet with new pod names.
func templateHash(object map[string]any) string {
	template := objectMap(objectMap(object["spec"])["template"])
	encoded, err := json.Marshal(template["spec"])
	if err != nil {
		return suffixFor("empty", 0)
	}
	return suffixFor(fmt.Sprintf("%x", fnv32(string(encoded))), 0)
}

// materializePods creates (or tops up) the pods a controller would run for a
// workload. Deployments route through a materialized ReplicaSet so the
// Deployment → ReplicaSet → Pod ownership chain matches a real cluster —
// `kubectl get rs`, `rollout history`, and template-hash rollouts all work.
// Other workloads own their pods directly.
func (a *API) materializePods(gv groupVersion, namespace, workloadName string, object map[string]any) {
	kind, _ := object["kind"].(string)
	if kind == "Deployment" {
		a.materializeDeployment(namespace, workloadName, object)
		return
	}
	desired := intField(objectMap(object["spec"]), "replicas")
	switch kind {
	case "DaemonSet":
		desired = a.nodeCount()
	case "Job":
		desired = 1
	}
	if desired > maxControllerPods {
		desired = maxControllerPods
	}
	if desired < 0 {
		return
	}
	owner := a.ownerRef(object, kind, workloadName, apiVersionFor(gv))
	wanted := map[string]bool{}
	for _, podName := range workloadPodNames(kind, workloadName, desired, a.nodeCount()) {
		wanted[podName] = true
	}
	existing := a.ownedPodNames(namespace, workloadName)
	for podName := range existing {
		if !wanted[podName] {
			a.store.delete(objectKey{"", "v1", "pods", namespace, podName})
		}
	}
	for i, podName := range workloadPodNames(kind, workloadName, desired, a.nodeCount()) {
		if _, exists := existing[podName]; exists {
			continue
		}
		pod := a.controllerPod(kind, namespace, workloadName, podName, owner, object, i, templateHash(object))
		if err := a.store.put(objectKey{"", "v1", "pods", namespace, podName}, pod, "ADDED"); err == nil {
			a.emitPodLifecycleEvents(namespace, pod)
		}
	}
	a.emitWorkloadEvents(kind, namespace, workloadName, object)
}

// materializeDeployment reconciles the ReplicaSet chain for a Deployment: a
// new ReplicaSet per pod-template-hash (so `set image` rolls like a real
// rollout), old ReplicaSets scaled to zero with their pods reaped.
func (a *API) materializeDeployment(namespace, name string, deployment map[string]any) {
	spec := objectMap(deployment["spec"])
	desired := intField(spec, "replicas")
	if desired > maxControllerPods {
		desired = maxControllerPods
	}
	if desired < 0 {
		return
	}
	rsName := name + "-" + templateHash(deployment)
	rsKey := objectKey{"apps", "v1", "replicasets", namespace, rsName}
	rs, exists := a.store.get(rsKey)
	if !exists {
		revision := a.nextDeploymentRevision(namespace, name)
		rs = map[string]any{
			"apiVersion": "apps/v1", "kind": "ReplicaSet",
			"metadata": map[string]any{
				"name":              rsName,
				"namespace":         namespace,
				"uid":               stableUID("replicaset/" + namespace + "/" + rsName),
				"creationTimestamp": time.Now().UTC().Format(time.RFC3339),
				"ownerReferences":   []any{a.ownerRef(deployment, "Deployment", name, "apps/v1")},
				"labels":            mergeLabels(objectMap(objectMap(spec["template"])["metadata"])["labels"], "Deployment", templateHash(deployment)),
				"annotations": map[string]any{
					"deployment.kubernetes.io/desired-replicas": fmt.Sprint(desired),
					"deployment.kubernetes.io/max-replicas":     fmt.Sprint(desired + desired/4),
					"deployment.kubernetes.io/revision":         fmt.Sprint(revision),
				},
			},
			"spec": map[string]any{
				"replicas": desired,
				"selector": spec["selector"],
				"template": spec["template"],
			},
			"status": map[string]any{
				"replicas": desired, "readyReplicas": desired, "availableReplicas": desired,
				"fullyLabeledReplicas": desired, "observedGeneration": 1,
			},
		}
		if err := a.store.put(rsKey, rs, "ADDED"); err != nil {
			return
		}
		a.emitEvent(namespace, objectMap(deployment["metadata"])["uid"], "Deployment", "apps/v1", name,
			"ScalingReplicaSet", fmt.Sprintf("Scaled up replica set %s to %d", rsName, desired), "deployment-controller")
		a.emitEvent(namespace, stableUID("replicaset/"+namespace+"/"+rsName), "ReplicaSet", "apps/v1", rsName,
			"SuccessfulCreate", fmt.Sprintf("Created pod: %s", rsName+"-"+suffixFor(rsName, 0)), "replicaset-controller")
	} else {
		rsSpec := objectMap(rs["spec"])
		if intField(rsSpec, "replicas") != desired {
			rsSpec["replicas"] = desired
			rs["spec"] = rsSpec
			rsStatus := objectMap(rs["status"])
			rsStatus["replicas"] = desired
			rsStatus["readyReplicas"] = desired
			rsStatus["availableReplicas"] = desired
			rs["status"] = rsStatus
			_ = a.store.put(rsKey, rs, "MODIFIED")
		}
	}
	// Pods are owned by the current ReplicaSet and named <rs>-<suffix>.
	wanted := map[string]bool{}
	for i := 0; i < desired; i++ {
		wanted[fmt.Sprintf("%s-%s", rsName, suffixFor(rsName, i))] = true
	}
	existing := a.ownedPodNames(namespace, rsName)
	for podName := range existing {
		if !wanted[podName] {
			a.store.delete(objectKey{"", "v1", "pods", namespace, podName})
		}
	}
	for i := 0; i < desired; i++ {
		podName := fmt.Sprintf("%s-%s", rsName, suffixFor(rsName, i))
		if existing[podName] {
			continue
		}
		owner := a.ownerRef(rs, "ReplicaSet", rsName, "apps/v1")
		pod := a.controllerPod("Deployment", namespace, rsName, podName, owner, deployment, i, templateHash(deployment))
		if err := a.store.put(objectKey{"", "v1", "pods", namespace, podName}, pod, "ADDED"); err == nil {
			a.emitPodLifecycleEvents(namespace, pod)
		}
	}
	// Retire old ReplicaSets of this Deployment: scale to zero, reap pods —
	// the RS objects stay for `rollout history`, matching real clusters.
	for _, oldRS := range a.deploymentReplicaSets(namespace, name) {
		oldName := stringField(objectMap(oldRS["metadata"]), "name")
		if oldName == rsName {
			continue
		}
		oldSpec := objectMap(oldRS["spec"])
		if intField(oldSpec, "replicas") != 0 {
			oldSpec["replicas"] = 0
			oldRS["spec"] = oldSpec
			oldStatus := objectMap(oldRS["status"])
			oldStatus["replicas"] = 0
			oldStatus["readyReplicas"] = 0
			oldStatus["availableReplicas"] = 0
			oldRS["status"] = oldStatus
			_ = a.store.put(objectKey{"apps", "v1", "replicasets", namespace, oldName}, oldRS, "MODIFIED")
		}
		for podName := range a.ownedPodNames(namespace, oldName) {
			a.store.delete(objectKey{"", "v1", "pods", namespace, podName})
		}
	}
	a.syncDeploymentStatus(namespace, name, desired)
}

// deploymentReplicaSets lists ReplicaSets owned by the Deployment.
func (a *API) deploymentReplicaSets(namespace, deployName string) []map[string]any {
	items, _, _, err := a.store.listPage(groupVersion{"apps", "v1"}, namespace, "replicasets", nil, nil, 0, maxListPageItems)
	if err != nil {
		return nil
	}
	owned := []map[string]any{}
	for _, item := range items {
		for _, ref := range objectList(objectMap(item["metadata"])["ownerReferences"]) {
			if stringField(objectMap(ref), "name") == deployName {
				owned = append(owned, item)
			}
		}
	}
	return owned
}

// nextDeploymentRevision counts existing ReplicaSets for the Deployment —
// each new template bumps the revision like the real controller.
func (a *API) nextDeploymentRevision(namespace, deployName string) int {
	return len(a.deploymentReplicaSets(namespace, deployName)) + 1
}

// syncDeploymentStatus converges the Deployment's status replica counts to
// the desired count — a real cluster's deployment controller does this
// asynchronously; we converge immediately so `rollout status` completes.
func (a *API) syncDeploymentStatus(namespace, name string, desired int) {
	key := objectKey{"apps", "v1", "deployments", namespace, name}
	deployment, exists := a.store.get(key)
	if !exists {
		return
	}
	status := objectMap(deployment["status"])
	status["replicas"] = desired
	status["updatedReplicas"] = desired
	status["readyReplicas"] = desired
	status["availableReplicas"] = desired
	deployment["status"] = status
	_ = a.store.put(key, deployment, "MODIFIED")
}

// reapOwnedPods deletes pods owned by the workload — cascading delete. For
// Deployments the pods belong to ReplicaSets, so those are reaped too.
func (a *API) reapOwnedPods(namespace, workloadName string) {
	for podName := range a.ownedPodNames(namespace, workloadName) {
		a.store.delete(objectKey{"", "v1", "pods", namespace, podName})
	}
	for _, rs := range a.deploymentReplicaSets(namespace, workloadName) {
		rsName := stringField(objectMap(rs["metadata"]), "name")
		for podName := range a.ownedPodNames(namespace, rsName) {
			a.store.delete(objectKey{"", "v1", "pods", namespace, podName})
		}
		a.store.delete(objectKey{"apps", "v1", "replicasets", namespace, rsName})
	}
}

// syncEndpointsForNamespace maintains Endpoints objects the way the
// endpoints controller does: for each Service with a selector, an Endpoints
// listing the matching pods' IPs and ports.
func (a *API) syncEndpointsForNamespace(namespace string) {
	services, _, _, err := a.store.listPage(groupVersion{"", "v1"}, namespace, "services", nil, nil, 0, maxListPageItems)
	if err != nil {
		return
	}
	pods, _, _, err := a.store.listPage(groupVersion{"", "v1"}, namespace, "pods", nil, nil, 0, maxListPageItems)
	if err != nil {
		return
	}
	for _, service := range services {
		serviceMeta := objectMap(service["metadata"])
		serviceName := stringField(serviceMeta, "name")
		spec := objectMap(service["spec"])
		selector := objectMap(spec["selector"])
		if len(selector) == 0 {
			continue // selectorless services have no managed endpoints
		}
		addresses := []any{}
		for _, pod := range pods {
			podMeta := objectMap(pod["metadata"])
			labels := objectMap(podMeta["labels"])
			match := true
			for key, value := range selector {
				if fmt.Sprint(labels[key]) != fmt.Sprint(value) {
					match = false
					break
				}
			}
			if !match {
				continue
			}
			ip := stringField(objectMap(pod["status"]), "podIP")
			if ip == "" {
				continue
			}
			addresses = append(addresses, map[string]any{
				"ip":        ip,
				"targetRef": map[string]any{"kind": "Pod", "namespace": namespace, "name": stringField(podMeta, "name"), "uid": podMeta["uid"]},
			})
		}
		ports := []any{}
		for _, entry := range objectList(spec["ports"]) {
			port := objectMap(entry)
			ports = append(ports, map[string]any{
				"name":     port["name"],
				"port":     port["port"],
				"protocol": "TCP",
			})
		}
		subsets := []any{}
		if len(addresses) > 0 {
			subsets = append(subsets, map[string]any{"addresses": addresses, "ports": ports})
		}
		endpoints := map[string]any{
			"apiVersion": "v1", "kind": "Endpoints",
			"metadata": map[string]any{
				"name":              serviceName,
				"namespace":         namespace,
				"uid":               stableUID("endpoints/" + namespace + "/" + serviceName),
				"creationTimestamp": serviceMeta["creationTimestamp"],
				"labels":            map[string]any{"kubernetes.io/service-name": serviceName},
			},
			"subsets": subsets,
		}
		key := objectKey{"", "v1", "endpoints", namespace, serviceName}
		if _, exists := a.store.get(key); exists {
			_ = a.store.put(key, endpoints, "MODIFIED")
		} else {
			_ = a.store.put(key, endpoints, "ADDED")
		}
		a.syncEndpointSlice(namespace, serviceName, serviceMeta, addresses, ports)
	}
}

// syncEndpointSlice maintains the discovery.k8s.io EndpointSlice modern
// clients (kubectl describe, ingress controllers) read instead of Endpoints.
func (a *API) syncEndpointSlice(namespace, serviceName string, serviceMeta map[string]any, addresses, ports []any) {
	sliceName := serviceName + "-" + suffixFor(serviceName, 0)
	sliceEndpoints := []any{}
	for _, entry := range addresses {
		address := objectMap(entry)
		sliceEndpoints = append(sliceEndpoints, map[string]any{
			"addresses":  []any{address["ip"]},
			"conditions": map[string]any{"ready": true, "serving": true, "terminating": false},
			"targetRef":  address["targetRef"],
		})
	}
	slicePorts := []any{}
	for _, entry := range ports {
		port := objectMap(entry)
		name := port["name"]
		if name == nil {
			name = ""
		}
		slicePorts = append(slicePorts, map[string]any{
			"name": name, "port": port["port"], "protocol": port["protocol"],
		})
	}
	slice := map[string]any{
		"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice",
		"addressType": "IPv4",
		"metadata": map[string]any{
			"name":              sliceName,
			"namespace":         namespace,
			"uid":               stableUID("endpointslice/" + namespace + "/" + sliceName),
			"creationTimestamp": serviceMeta["creationTimestamp"],
			"labels": map[string]any{
				"kubernetes.io/service-name":             serviceName,
				"endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io",
			},
			"ownerReferences": []any{map[string]any{
				"apiVersion": "v1", "kind": "Service", "name": serviceName,
				"uid": serviceMeta["uid"], "controller": true, "blockOwnerDeletion": true,
			}},
		},
		"endpoints": sliceEndpoints,
		"ports":     slicePorts,
	}
	key := objectKey{"discovery.k8s.io", "v1", "endpointslices", namespace, sliceName}
	if _, exists := a.store.get(key); exists {
		_ = a.store.put(key, slice, "MODIFIED")
	} else {
		_ = a.store.put(key, slice, "ADDED")
	}
}

// respawnDeletedPod recreates a pod its controller would immediately
// replace — a real cluster's controllers notice the deletion and respawn.
func (a *API) respawnDeletedPod(namespace string, pod map[string]any) {
	if pod == nil {
		return
	}
	var ownerKind, ownerName, ownerAPIVersion string
	for _, ref := range objectList(objectMap(pod["metadata"])["ownerReferences"]) {
		owner := objectMap(ref)
		if controlled, _ := owner["controller"].(bool); controlled {
			ownerKind = stringField(owner, "kind")
			ownerName = stringField(owner, "name")
			ownerAPIVersion = stringField(owner, "apiVersion")
			break
		}
	}
	if ownerName == "" {
		return
	}
	group, version, found := strings.Cut(ownerAPIVersion, "/")
	if !found {
		version = group
		group = ""
	}
	gv := groupVersion{group, version}
	if ownerKind == "ReplicaSet" {
		// ReplicaSet pods respawn through the owning Deployment when there is
		// one; bare ReplicaSets respawn directly.
		rs, exists := a.store.get(objectKey{"apps", "v1", "replicasets", namespace, ownerName})
		if !exists {
			return
		}
		for _, ref := range objectList(objectMap(rs["metadata"])["ownerReferences"]) {
			owner := objectMap(ref)
			if stringField(owner, "kind") == "Deployment" {
				deployName := stringField(owner, "name")
				if deployment, ok := a.store.get(objectKey{"apps", "v1", "deployments", namespace, deployName}); ok {
					a.materializeDeployment(namespace, deployName, deployment)
					return
				}
			}
		}
		if isWorkloadKind("ReplicaSet") {
			a.materializePods(gv, namespace, ownerName, rs)
		}
		return
	}
	if !isWorkloadKind(ownerKind) {
		return
	}
	for resourceName, description := range a.resources[gv] {
		if description.Kind == ownerKind {
			if workload, ok := a.store.get(objectKey{gv.Group, gv.Version, resourceName, namespace, ownerName}); ok {
				a.materializePods(gv, namespace, ownerName, workload)
			}
			return
		}
	}
}

// ownedPodNames indexes pods in a namespace by their controller
// ownerReference name.
func (a *API) ownedPodNames(namespace, ownerName string) map[string]bool {
	pods, _, _, err := a.store.listPage(groupVersion{"", "v1"}, namespace, "pods", nil, nil, 0, maxListPageItems)
	if err != nil {
		return map[string]bool{}
	}
	owned := map[string]bool{}
	for _, pod := range pods {
		for _, ref := range objectList(objectMap(pod["metadata"])["ownerReferences"]) {
			if stringField(objectMap(ref), "name") == ownerName {
				owned[stringField(objectMap(pod["metadata"]), "name")] = true
			}
		}
	}
	return owned
}

// controllerPod builds a Running pod from the workload's pod template.
func (a *API) controllerPod(kind, namespace, workloadName, podName string, owner, workload map[string]any, ordinal int, hashSeed string) map[string]any {
	now := time.Now().UTC().Format(time.RFC3339)
	template := objectMap(objectMap(workload["spec"])["template"])
	spec := cloneObject(objectMap(template["spec"]))
	if len(spec) == 0 {
		spec = map[string]any{"containers": []any{map[string]any{"name": workloadName, "image": "busybox"}}}
	}
	spec["nodeName"] = a.nodeName(ordinal)
	spec["restartPolicy"] = "Always"
	if kind == "Job" {
		spec["restartPolicy"] = "Never"
	}
	applyPodSpecDefaults(spec)
	templateMeta := objectMap(template["metadata"])
	meta := map[string]any{
		"name":              podName,
		"namespace":         namespace,
		"uid":               stableUID("pod/" + namespace + "/" + podName),
		"creationTimestamp": now,
		"ownerReferences":   []any{owner},
		"labels":            mergeLabels(templateMeta["labels"], kind, hashSeed),
	}
	if kind == "Job" {
		labels := objectMap(meta["labels"])
		labels["job-name"] = workloadName
		labels["batch.kubernetes.io/job-name"] = workloadName
		labels["controller-uid"] = stableUID("job/" + namespace + "/" + workloadName)
		labels["batch.kubernetes.io/controller-uid"] = stableUID("job/" + namespace + "/" + workloadName)
		meta["labels"] = labels
	}
	podIP := serviceAddress(a.ipBase, 100+ordinal)
	containerNames := podContainerNames(map[string]any{"spec": spec})
	statuses := make([]any, 0, len(containerNames))
	for _, name := range containerNames {
		statuses = append(statuses, map[string]any{
			"name": name, "ready": true, "restartCount": 0,
			"state":       map[string]any{"running": map[string]any{"startedAt": now}},
			"started":     true,
			"image":       imageForContainer(spec, name),
			"imageID":     "containerd://" + strings.Repeat("a", 64),
			"containerID": "containerd://" + strings.Repeat("b", 64),
		})
	}
	return map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": meta, "spec": spec,
		"status": map[string]any{
			"phase": "Running", "podIP": podIP,
			"podIPs":            []any{map[string]any{"ip": podIP}},
			"hostIP":            serviceAddress(a.ipBase, 10),
			"startTime":         now,
			"qosClass":          "BestEffort",
			"containerStatuses": statuses,
			"conditions": []any{
				map[string]any{"type": "Ready", "status": "True", "lastTransitionTime": now},
				map[string]any{"type": "PodScheduled", "status": "True", "lastTransitionTime": now},
			},
		},
	}
}

// applyPodSpecDefaults fills the fields an apiserver defaults on every Pod —
// kubectl debug and friends dereference spec.securityContext unconditionally.
func applyPodSpecDefaults(spec map[string]any) {
	defaults := map[string]any{
		"securityContext":               map[string]any{},
		"dnsPolicy":                     "ClusterFirst",
		"schedulerName":                 "default-scheduler",
		"terminationGracePeriodSeconds": 30,
		"enableServiceLinks":            true,
		"preemptionPolicy":              "PreemptLowerPriority",
		"priority":                      0,
	}
	for key, value := range defaults {
		if _, ok := spec[key]; !ok {
			spec[key] = value
		}
	}
	// Apiserver also defaults fields inside each container — kubectl's
	// strategic merges produce these, so hashes match only if we emit them.
	for _, entry := range objectList(spec["containers"]) {
		container := objectMap(entry)
		for key, value := range map[string]any{
			"resources":                map[string]any{},
			"terminationMessagePath":   "/dev/termination-log",
			"terminationMessagePolicy": "File",
			"imagePullPolicy":          "IfNotPresent",
		} {
			if _, ok := container[key]; !ok {
				container[key] = value
			}
		}
	}
}

func imageForContainer(spec map[string]any, name string) string {
	for _, entry := range objectList(spec["containers"]) {
		container := objectMap(entry)
		if stringField(container, "name") == name {
			return stringField(container, "image")
		}
	}
	return ""
}

// ownerRef builds the controller ownerReference pods and ReplicaSets carry.
func (a *API) ownerRef(object map[string]any, kind, name, apiVersion string) map[string]any {
	return map[string]any{
		"apiVersion":         apiVersion,
		"kind":               kind,
		"name":               name,
		"uid":                objectMap(object["metadata"])["uid"],
		"controller":         true,
		"blockOwnerDeletion": true,
	}
}

// emitEvent stores a core v1 Event so `kubectl get events` and `describe`
// show controller activity instead of an eerily quiet cluster.
func (a *API) emitEvent(namespace string, involvedUID any, involvedKind, involvedAPIVersion, involvedName, reason, message, source string) {
	now := time.Now().UTC().Format(time.RFC3339)
	eventName := fmt.Sprintf("%s.%x", involvedName, fnv32(involvedName+reason+now))
	event := map[string]any{
		"apiVersion": "v1", "kind": "Event",
		"metadata": map[string]any{
			"name":              eventName,
			"namespace":         namespace,
			"uid":               stableUID("event/" + namespace + "/" + eventName),
			"creationTimestamp": now,
		},
		"involvedObject": map[string]any{
			"kind": involvedKind, "namespace": namespace, "name": involvedName,
			"uid": involvedUID, "apiVersion": involvedAPIVersion, "resourceVersion": "",
		},
		"reason":         reason,
		"message":        message,
		"type":           "Normal",
		"source":         map[string]any{"component": source},
		"firstTimestamp": now, "lastTimestamp": now,
		"count":              1,
		"reportingComponent": source, "reportingInstance": a.nodeName(0),
	}
	_ = a.store.put(objectKey{"", "v1", "events", namespace, eventName}, event, "ADDED")
}

// emitPodLifecycleEvents emits the Scheduled/Pulled/Created/Started sequence
// a kubelet reports for a new pod.
func (a *API) emitPodLifecycleEvents(namespace string, pod map[string]any) {
	meta := objectMap(pod["metadata"])
	name := stringField(meta, "name")
	uid := meta["uid"]
	node := stringField(objectMap(pod["spec"]), "nodeName")
	image := "image"
	for _, entry := range objectList(objectMap(pod["spec"])["containers"]) {
		image = stringField(objectMap(entry), "image")
		break
	}
	a.emitEvent(namespace, uid, "Pod", "v1", name, "Scheduled",
		fmt.Sprintf("Successfully assigned %s/%s to %s", namespace, name, node), "default-scheduler")
	a.emitEvent(namespace, uid, "Pod", "v1", name, "Pulled",
		fmt.Sprintf("Container image %q already present on machine", image), "kubelet")
	a.emitEvent(namespace, uid, "Pod", "v1", name, "Created",
		fmt.Sprintf("Created container %s", name), "kubelet")
	a.emitEvent(namespace, uid, "Pod", "v1", name, "Started",
		fmt.Sprintf("Started container %s", name), "kubelet")
}

// emitWorkloadEvents emits the SuccessfulCreate events workload controllers
// report for pod creation.
func (a *API) emitWorkloadEvents(kind, namespace, workloadName string, object map[string]any) {
	uid := objectMap(object["metadata"])["uid"]
	controller := map[string]string{
		"StatefulSet": "statefulset-controller", "DaemonSet": "daemonset-controller",
		"ReplicaSet": "replicaset-controller", "Job": "job-controller",
	}[kind]
	if controller == "" {
		return
	}
	for _, podName := range workloadPodNames(kind, workloadName, intField(objectMap(object["spec"]), "replicas"), a.nodeCount()) {
		a.emitEvent(namespace, uid, kind, "", workloadName, "SuccessfulCreate",
			fmt.Sprintf("Created pod: %s", podName), controller)
	}
}

// mergeLabels keeps template labels and adds the controller's pod-template
// hash label conventions (pod-template-hash for Deployments/RS).
func mergeLabels(templateLabels any, kind, templateHashSeed string) map[string]any {
	labels := map[string]any{}
	for key, value := range objectMap(templateLabels) {
		labels[key] = value
	}
	if kind == "Deployment" || kind == "ReplicaSet" {
		labels["pod-template-hash"] = templateHashSeed
	}
	return labels
}

// nodeCount returns the seeded node count for DaemonSet fan-out.
func (a *API) nodeCount() int {
	nodes, total, _, err := a.store.listPage(groupVersion{"", "v1"}, "", "nodes", nil, nil, 0, 8)
	if err != nil || total == 0 {
		return 1
	}
	_ = nodes
	return total
}

// nodeName returns a deterministic node for pod assignment, round-robin
// across seeded nodes.
func (a *API) nodeName(ordinal int) string {
	nodes, total, _, err := a.store.listPage(groupVersion{"", "v1"}, "", "nodes", nil, nil, 0, 8)
	if err != nil || total == 0 {
		return "worker-01"
	}
	meta := objectMap(nodes[ordinal%len(nodes)]["metadata"])
	return stringField(meta, "name")
}
