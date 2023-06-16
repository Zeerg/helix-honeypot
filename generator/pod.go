package generator

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/google/uuid"
	"helix-honeypot/config"
)

func RandomIP(ipBase string) string {
	splitIP := strings.Split(ipBase, ".")

	// Generate the last two octets
	octet3 := rand.Intn(255)
	octet4 := rand.Intn(255)

	return fmt.Sprintf("%s.%d.%d", strings.Join(splitIP[:2], "."), octet3, octet4)
}

func GenerateColumnDefinitions() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"name":        "Name",
			"type":        "string",
			"format":      "name",
			"description": "Name must be unique within a namespace. Is required when creating resources, although some resources may allow a client to request the generation of an appropriate name automatically. Name is primarily intended for creation idempotence and configuration definition. Cannot be updated. More info: http://kubernetes.io/docs/user-guide/identifiers#names",
			"priority":    0,
		},
		{
			"name":        "Ready",
			"type":        "string",
			"format":      "",
			"description": "The aggregate readiness state of this pod for accepting traffic.",
			"priority":    0,
		},
		{
			"name":        "Status",
			"type":        "string",
			"format":      "",
			"description": "The aggregate status of the containers in this pod.",
			"priority":    0,
		},
		{
			"name":        "Restarts",
			"type":        "string",
			"format":      "",
			"description": "The number of times the containers in this pod have been restarted and when the last container in this pod has restarted.",
			"priority":    0,
		},
		{
			"name":        "Age",
			"type":        "string",
			"format":      "",
			"description": "CreationTimestamp is a timestamp representing the server time when this object was created. It is not guaranteed to be set in happens-before order across separate operations. Clients may not set this value. It is represented in RFC3339 form and is in UTC. Populated by the system. Read-only. Null for lists. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata",
			"priority":    0,
		},
		{
			"name":        "IP",
			"type":        "string",
			"format":      "",
			"description": "IP address allocated to the pod. Routable at least within the cluster. Empty if not yet allocated.",
			"priority":    1,
		},
		{
			"name":        "Node",
			"type":        "string",
			"format":      "",
			"description": "NodeName is a request to schedule this pod onto a specific node. If it is non-empty, the scheduler simply schedules this pod onto that node, assuming that it fits resource requirements.",
			"priority":    1,
		},
		{
			"name":        "Nominated Node",
			"type":        "string",
			"format":      "",
			"description": "nominatedNodeName is set only when this pod preempts other pods on the node, but it cannot be scheduled right away as preemption victims receive their graceful termination periods. This field does not guarantee that the pod will be scheduled on this node. Scheduler may decide to place the pod elsewhere if other nodes become available sooner. Scheduler may also decide to give the resources on this node to a higher priority pod that is created after preemption. As a result, this field may be different than PodSpec.nodeName when the pod is scheduled.",
			"priority":    1,
		},
		{
			"name":        "Readiness Gates",
			"type":        "string",
			"format":      "",
			"description": "If specified, all readiness gates will be evaluated for pod readiness. A pod is ready when all its containers are ready AND all conditions specified in the readiness gates have status equal to \"True\" More info: https://git.k8s.io/enhancements/keps/sig-network/580-pod-readiness-gates",
			"priority":    1,
		},
	}
}

func GeneratePod(cfg *config.Config) map[string]interface{} {
	podTypes := []string{"kube-api-server", "kube-controller-manager", "kube-proxy", "kube-scheduler", "storage-provisioner", "vpnkit-controller"}
	podType := podTypes[rand.Intn(len(podTypes))]
	uuid := uuid.New().String()
	ip := RandomIP(cfg.IPBase)
	creationTimestamp := time.Now().Add(-time.Duration(rand.Intn(48)) * time.Hour) // Random time in last 48 hours
	age := fmt.Sprintf("%dh", int(time.Since(creationTimestamp).Hours()))          // Age in hours

	pod := map[string]interface{}{
		"cells": []string{
			podType,   // Name
			"1/1",     // Ready: 1 out of 1 pods are ready
			"Running", // Status
			"0",       // Restarts
			age,       // Age
			ip,        // IP
			"node1",   // Node
			"<none>",  // Nominated Node
			"<none>",  // Readiness Gates
		},
		"object": map[string]interface{}{
			"kind":       "PartialObjectMetadata",
			"apiVersion": "meta.k8s.io/v1",
			"metadata": map[string]interface{}{
				"name":              podType,                                       // Pod name
				"creationTimestamp": creationTimestamp.Format("2006-01-02T15:04Z"), // Convert time to string in RFC3339 format, less precise
				"uid":               uuid,
			},
		},
	}
	return pod
}
