package handler

// Server-side Table conversion for `kubectl get`. When the client sends
// Accept: application/json;as=Table;v=v1;g=meta.k8s.io the apiserver returns
// a meta.k8s.io Table with pre-rendered cells instead of raw objects — that
// is how kubectl prints READY/STATUS/RESTARTS columns.

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
)

type tableColumn struct {
	name        string
	columnType  string
	format      string
	description string
	priority    int // >0 columns render only with -o wide
}

func col(name, description string) tableColumn {
	return tableColumn{name: name, columnType: "string", description: description}
}

func wideCol(name, description string) tableColumn {
	c := col(name, description)
	c.priority = 1
	return c
}

// requestsTable reports whether the client negotiated a Table response.
func requestsTable(c *echo.Context) bool {
	for _, clause := range strings.Split(c.Request().Header.Get(echo.HeaderAccept), ",") {
		parts := strings.Split(clause, ";")
		if strings.TrimSpace(parts[0]) != "application/json" {
			continue
		}
		params := map[string]string{}
		for _, part := range parts[1:] {
			if key, value, found := strings.Cut(strings.TrimSpace(part), "="); found {
				params[strings.ToLower(key)] = value
			}
		}
		if params["as"] == "Table" {
			return true
		}
	}
	return false
}

// tableResponse renders list items as a meta.k8s.io/v1 Table. Every row
// carries the full object so kubectl can still expand --show-labels and
// custom columns client-side.
func tableResponse(gv groupVersion, description apiResource, items []map[string]any) map[string]any {
	columns, rowCells := tableSpec(gv, description)
	definitions := make([]any, 0, len(columns))
	for _, column := range columns {
		definitions = append(definitions, map[string]any{
			"name":        column.name,
			"type":        column.columnType,
			"format":      column.format,
			"description": column.description,
			"priority":    column.priority,
		})
	}
	rows := make([]any, 0, len(items))
	for _, item := range items {
		rows = append(rows, map[string]any{
			"cells":  rowCells(item),
			"object": item,
		})
	}
	return map[string]any{
		"apiVersion":        "meta.k8s.io/v1",
		"kind":              "Table",
		"columnDefinitions": definitions,
		"rows":              rows,
	}
}

func tableSpec(gv groupVersion, description apiResource) ([]tableColumn, func(map[string]any) []any) {
	switch description.Kind {
	case "Pod":
		return []tableColumn{
				col("NAME", "Name"), col("READY", "Ready containers"), col("STATUS", "Status"),
				col("RESTARTS", "Restarts"), col("AGE", "Age"),
				wideCol("IP", "Pod IP"), wideCol("NODE", "Node"), wideCol("NOMINATED NODE", "Nominated node"), wideCol("READINESS GATES", "Readiness gates"),
			}, func(object map[string]any) []any {
				meta := objectMap(object["metadata"])
				status := objectMap(object["status"])
				ready, total, restarts := podReadiness(object)
				node, _ := objectMap(object["spec"])["nodeName"].(string)
				if node == "" {
					node = "<none>"
				}
				ip, _ := status["podIP"].(string)
				if ip == "" {
					ip = "<none>"
				}
				return []any{meta["name"], fmt.Sprintf("%d/%d", ready, total), podPhase(object), restarts,
					objectAge(meta), ip, node, "<none>", "<none>"}
			}
	case "Service":
		return []tableColumn{
				col("NAME", "Name"), col("TYPE", "Service type"), col("CLUSTER-IP", "Cluster IP"),
				col("EXTERNAL-IP", "External IP"), col("PORT(S)", "Ports"), col("AGE", "Age"),
				wideCol("SELECTOR", "Selector"),
			}, func(object map[string]any) []any {
				meta := objectMap(object["metadata"])
				spec := objectMap(object["spec"])
				serviceType, _ := spec["type"].(string)
				if serviceType == "" {
					serviceType = "ClusterIP"
				}
				external := "<none>"
				if serviceType == "LoadBalancer" {
					external = "<pending>"
				}
				return []any{meta["name"], serviceType, spec["clusterIP"], external, servicePorts(spec), objectAge(meta), selectorString(spec)}
			}
	case "Deployment":
		return []tableColumn{
				col("NAME", "Name"), col("READY", "Ready replicas"), col("UP-TO-DATE", "Updated replicas"),
				col("AVAILABLE", "Available replicas"), col("AGE", "Age"),
				wideCol("CONTAINERS", "Containers"), wideCol("IMAGES", "Images"), wideCol("SELECTOR", "Selector"),
			}, func(object map[string]any) []any {
				meta := objectMap(object["metadata"])
				spec := objectMap(object["spec"])
				status := objectMap(object["status"])
				desired := intField(spec, "replicas")
				containers, images := podTemplateContainers(object)
				return []any{meta["name"], fmt.Sprintf("%d/%d", intField(status, "readyReplicas"), desired),
					intField(status, "updatedReplicas"), intField(status, "availableReplicas"),
					objectAge(meta), strings.Join(containers, ","), strings.Join(images, ","), selectorString(spec)}
			}
	case "ReplicaSet":
		return []tableColumn{
				col("NAME", "Name"), col("DESIRED", "Desired"), col("CURRENT", "Current"),
				col("READY", "Ready"), col("AGE", "Age"),
			}, func(object map[string]any) []any {
				spec := objectMap(object["spec"])
				status := objectMap(object["status"])
				return []any{objectMap(object["metadata"])["name"], intField(spec, "replicas"),
					intField(status, "replicas"), intField(status, "readyReplicas"), objectAge(objectMap(object["metadata"]))}
			}
	case "StatefulSet":
		return []tableColumn{
				col("NAME", "Name"), col("READY", "Ready replicas"), col("AGE", "Age"),
			}, func(object map[string]any) []any {
				spec := objectMap(object["spec"])
				status := objectMap(object["status"])
				return []any{objectMap(object["metadata"])["name"],
					fmt.Sprintf("%d/%d", intField(status, "readyReplicas"), intField(spec, "replicas")),
					objectAge(objectMap(object["metadata"]))}
			}
	case "DaemonSet":
		return []tableColumn{
				col("NAME", "Name"), col("DESIRED", "Desired"), col("CURRENT", "Current"),
				col("READY", "Ready"), col("UP-TO-DATE", "Updated"), col("AVAILABLE", "Available"),
				col("NODE SELECTOR", "Node selector"), col("AGE", "Age"),
			}, func(object map[string]any) []any {
				status := objectMap(object["status"])
				return []any{objectMap(object["metadata"])["name"], intField(status, "desiredNumberScheduled"),
					intField(status, "currentNumberScheduled"), intField(status, "numberReady"),
					intField(status, "updatedNumberScheduled"), intField(status, "numberAvailable"),
					"<none>", objectAge(objectMap(object["metadata"]))}
			}
	case "Job":
		return []tableColumn{
				col("NAME", "Name"), col("COMPLETIONS", "Completions"), col("DURATION", "Duration"), col("AGE", "Age"),
			}, func(object map[string]any) []any {
				spec := objectMap(object["spec"])
				status := objectMap(object["status"])
				completions := intField(spec, "completions")
				return []any{objectMap(object["metadata"])["name"], fmt.Sprintf("%d/%d", intField(status, "succeeded"), completions),
					jobDuration(objectMap(object["metadata"]), status), objectAge(objectMap(object["metadata"]))}
			}
	case "CronJob":
		return []tableColumn{
				col("NAME", "Name"), col("SCHEDULE", "Schedule"), col("SUSPEND", "Suspended"),
				col("ACTIVE", "Active jobs"), col("LAST SCHEDULE", "Last scheduled"), col("AGE", "Age"),
			}, func(object map[string]any) []any {
				spec := objectMap(object["spec"])
				status := objectMap(object["status"])
				suspend := "False"
				if suspendFlag, ok := spec["suspend"].(bool); ok && suspendFlag {
					suspend = "True"
				}
				last := "<none>"
				if scheduled, ok := status["lastScheduleTime"].(string); ok {
					last = shortAgo(scheduled)
				}
				return []any{objectMap(object["metadata"])["name"], spec["schedule"], suspend,
					len(objectList(status["active"])), last, objectAge(objectMap(object["metadata"]))}
			}
	case "Node":
		return []tableColumn{
				col("NAME", "Name"), col("STATUS", "Status"), col("ROLES", "Roles"),
				col("AGE", "Age"), col("VERSION", "Kubelet version"),
			}, func(object map[string]any) []any {
				meta := objectMap(object["metadata"])
				return []any{meta["name"], nodeReady(object), nodeRoles(meta), objectAge(meta), kubeletVersion(object)}
			}
	case "Namespace":
		return []tableColumn{
				col("NAME", "Name"), col("STATUS", "Status"), col("AGE", "Age"),
			}, func(object map[string]any) []any {
				phase, _ := objectMap(object["status"])["phase"].(string)
				if phase == "" {
					phase = "Active"
				}
				return []any{objectMap(object["metadata"])["name"], phase, objectAge(objectMap(object["metadata"]))}
			}
	case "Secret":
		return []tableColumn{
				col("NAME", "Name"), col("TYPE", "Type"), col("DATA", "Keys"), col("AGE", "Age"),
			}, func(object map[string]any) []any {
				secretType, _ := object["type"].(string)
				if secretType == "" {
					secretType = "Opaque"
				}
				return []any{objectMap(object["metadata"])["name"], secretType,
					len(objectMap(object["data"])) + len(objectMap(object["stringData"])), objectAge(objectMap(object["metadata"]))}
			}
	case "ConfigMap":
		return []tableColumn{
				col("NAME", "Name"), col("DATA", "Keys"), col("AGE", "Age"),
			}, func(object map[string]any) []any {
				return []any{objectMap(object["metadata"])["name"], len(objectMap(object["data"])), objectAge(objectMap(object["metadata"]))}
			}
	case "ServiceAccount":
		return []tableColumn{
				col("NAME", "Name"), col("SECRETS", "Secret count"), col("AGE", "Age"),
			}, func(object map[string]any) []any {
				return []any{objectMap(object["metadata"])["name"], len(objectList(object["secrets"])), objectAge(objectMap(object["metadata"]))}
			}
	case "Event":
		return []tableColumn{
				col("LAST SEEN", "Last seen"), col("TYPE", "Type"), col("REASON", "Reason"),
				col("OBJECT", "Involved object"), col("MESSAGE", "Message"),
			}, func(object map[string]any) []any {
				involved := objectMap(object["involvedObject"])
				return []any{eventLastSeen(object), object["type"], object["reason"],
					fmt.Sprintf("%s/%s", strings.ToLower(stringField(involved, "kind")), stringField(involved, "name")),
					object["message"]}
			}
	case "PersistentVolumeClaim":
		return []tableColumn{
				col("NAME", "Name"), col("STATUS", "Status"), col("VOLUME", "Bound volume"),
				col("CAPACITY", "Capacity"), col("ACCESS MODES", "Access modes"), col("STORAGECLASS", "Storage class"), col("AGE", "Age"),
			}, func(object map[string]any) []any {
				meta := objectMap(object["metadata"])
				spec := objectMap(object["spec"])
				status := objectMap(object["status"])
				capacity := ""
				if resources := objectMap(status["capacity"]); len(resources) > 0 {
					capacity = stringField(resources, "storage")
				}
				return []any{meta["name"], orDefault(stringField(status, "phase"), "Bound"), orDefault(stringField(spec, "volumeName"), "<none>"),
					orDefault(capacity, "1Gi"), "RWO", orDefault(stringField(spec, "storageClassName"), "standard"), objectAge(meta)}
			}
	case "PersistentVolume":
		return []tableColumn{
				col("NAME", "Name"), col("CAPACITY", "Capacity"), col("ACCESS MODES", "Access modes"),
				col("RECLAIM POLICY", "Reclaim policy"), col("STATUS", "Status"), col("CLAIM", "Bound claim"),
				col("STORAGECLASS", "Storage class"), col("AGE", "Age"),
			}, func(object map[string]any) []any {
				meta := objectMap(object["metadata"])
				spec := objectMap(object["spec"])
				status := objectMap(object["status"])
				claim := "<none>"
				if ref := objectMap(spec["claimRef"]); len(ref) > 0 {
					claim = fmt.Sprintf("%s/%s", stringField(ref, "namespace"), stringField(ref, "name"))
				}
				return []any{meta["name"], orDefault(stringField(objectMap(spec["capacity"]), "storage"), "1Gi"), "RWO",
					orDefault(stringField(spec, "persistentVolumeReclaimPolicy"), "Retain"),
					orDefault(stringField(status, "phase"), "Available"), claim,
					orDefault(stringField(spec, "storageClassName"), "standard"), objectAge(meta)}
			}
	case "Ingress":
		return []tableColumn{
				col("NAME", "Name"), col("CLASS", "Ingress class"), col("HOSTS", "Hosts"),
				col("ADDRESS", "Address"), col("PORTS", "Ports"), col("AGE", "Age"),
			}, func(object map[string]any) []any {
				meta := objectMap(object["metadata"])
				spec := objectMap(object["spec"])
				hosts := make([]string, 0)
				for _, rule := range objectList(spec["rules"]) {
					if host := stringField(objectMap(rule), "host"); host != "" {
						hosts = append(hosts, host)
					}
				}
				return []any{meta["name"], orDefault(stringField(spec, "ingressClassName"), "nginx"),
					orDefault(strings.Join(hosts, ","), "*"), "", "80", objectAge(meta)}
			}
	case "NetworkPolicy":
		return []tableColumn{
				col("NAME", "Name"), col("POD-SELECTOR", "Pod selector"), col("AGE", "Age"),
			}, func(object map[string]any) []any {
				spec := objectMap(object["spec"])
				return []any{objectMap(object["metadata"])["name"], matchLabelsString(objectMap(spec["podSelector"])), objectAge(objectMap(object["metadata"]))}
			}
	case "PodDisruptionBudget":
		return []tableColumn{
				col("NAME", "Name"), col("MIN AVAILABLE", "Min available"), col("MAX UNAVAILABLE", "Max unavailable"),
				col("ALLOWED DISRUPTIONS", "Allowed disruptions"), col("AGE", "Age"),
			}, func(object map[string]any) []any {
				spec := objectMap(object["spec"])
				status := objectMap(object["status"])
				return []any{objectMap(object["metadata"])["name"], orDefault(anyString(spec["minAvailable"]), "N/A"),
					orDefault(anyString(spec["maxUnavailable"]), "N/A"), intField(status, "disruptionsAllowed"), objectAge(objectMap(object["metadata"]))}
			}
	case "HorizontalPodAutoscaler":
		return []tableColumn{
				col("NAME", "Name"), col("REFERENCE", "Scale target"), col("TARGETS", "Targets"),
				col("MINPODS", "Min replicas"), col("MAXPODS", "Max replicas"), col("REPLICAS", "Current"), col("AGE", "Age"),
			}, func(object map[string]any) []any {
				spec := objectMap(object["spec"])
				status := objectMap(object["status"])
				target := objectMap(spec["scaleTargetRef"])
				return []any{objectMap(object["metadata"])["name"],
					fmt.Sprintf("%s/%s", strings.ToLower(stringField(target, "kind")), stringField(target, "name")),
					"<unknown>/50%", intField(spec, "minReplicas"), intField(spec, "maxReplicas"),
					intField(status, "currentReplicas"), objectAge(objectMap(object["metadata"]))}
			}
	case "CustomResourceDefinition":
		return []tableColumn{
				col("NAME", "Name"), col("CREATED AT", "Created"),
			}, func(object map[string]any) []any {
				meta := objectMap(object["metadata"])
				return []any{meta["name"], meta["creationTimestamp"]}
			}
	case "APIService":
		return []tableColumn{
				col("NAME", "Name"), col("SERVICE", "Backend service"), col("AVAILABLE", "Availability"), col("AGE", "Age"),
			}, func(object map[string]any) []any {
				spec := objectMap(object["spec"])
				service := "Local"
				if backend := objectMap(spec["service"]); len(backend) > 0 {
					service = fmt.Sprintf("%s/%s", stringField(backend, "namespace"), stringField(backend, "name"))
				}
				available := "True"
				for _, condition := range objectList(objectMap(object["status"])["conditions"]) {
					if stringField(objectMap(condition), "type") == "Available" {
						available = stringField(objectMap(condition), "status")
					}
				}
				return []any{objectMap(object["metadata"])["name"], service, available + " (Local)", objectAge(objectMap(object["metadata"]))}
			}
	case "Lease":
		return []tableColumn{
				col("NAME", "Name"), col("HOLDER", "Holder"), col("AGE", "Age"),
			}, func(object map[string]any) []any {
				spec := objectMap(object["spec"])
				return []any{objectMap(object["metadata"])["name"], orDefault(stringField(spec, "holderIdentity"), "<none>"), objectAge(objectMap(object["metadata"]))}
			}
	case "CertificateSigningRequest":
		return []tableColumn{
				col("NAME", "Name"), col("AGE", "Age"), col("SIGNERNAME", "Signer"), col("REQUESTOR", "Requestor"), col("REQUESTEDDURATION", "Duration"), col("CONDITION", "Condition"),
			}, func(object map[string]any) []any {
				spec := objectMap(object["spec"])
				return []any{objectMap(object["metadata"])["name"], objectAge(objectMap(object["metadata"])),
					orDefault(stringField(spec, "signerName"), "kubernetes.io/kube-apiserver-client"),
					orDefault(stringField(spec, "username"), "system:node:worker-01"), "<none>", "Approved"}
			}
	case "StorageClass", "IngressClass", "CSIDriver", "ClusterRole", "ClusterRoleBinding", "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding", "ComponentStatus":
		return []tableColumn{
				col("NAME", "Name"), col("CREATED AT", "Created"),
			}, func(object map[string]any) []any {
				meta := objectMap(object["metadata"])
				return []any{meta["name"], meta["creationTimestamp"]}
			}
	case "Endpoints":
		return []tableColumn{
				col("NAME", "Name"), col("ENDPOINTS", "Addresses"), col("AGE", "Age"),
			}, func(object map[string]any) []any {
				return []any{objectMap(object["metadata"])["name"], endpointAddresses(object), objectAge(objectMap(object["metadata"]))}
			}
	case "EndpointSlice":
		return []tableColumn{
				col("NAME", "Name"), col("ADDRESSTYPE", "Address type"), col("PORTS", "Ports"), col("ENDPOINTS", "Endpoints"), col("AGE", "Age"),
			}, func(object map[string]any) []any {
				return []any{objectMap(object["metadata"])["name"], orDefault(stringField(object, "addressType"), "IPv4"),
					"443", len(objectList(object["endpoints"])), objectAge(objectMap(object["metadata"]))}
			}
	case "Role", "RoleBinding":
		return []tableColumn{
				col("NAME", "Name"), col("CREATED AT", "Created"),
			}, func(object map[string]any) []any {
				meta := objectMap(object["metadata"])
				return []any{meta["name"], meta["creationTimestamp"]}
			}
	case "ReplicationController":
		return []tableColumn{
				col("NAME", "Name"), col("DESIRED", "Desired"), col("CURRENT", "Current"), col("READY", "Ready"), col("AGE", "Age"),
			}, func(object map[string]any) []any {
				spec := objectMap(object["spec"])
				status := objectMap(object["status"])
				return []any{objectMap(object["metadata"])["name"], intField(spec, "replicas"),
					intField(status, "replicas"), intField(status, "readyReplicas"), objectAge(objectMap(object["metadata"]))}
			}
	}
	return []tableColumn{
			col("NAME", "Name"), col("AGE", "Age"),
		}, func(object map[string]any) []any {
			return []any{objectMap(object["metadata"])["name"], objectAge(objectMap(object["metadata"]))}
		}
}

// podReadiness reports ready/total containers and summed restarts.
func podReadiness(object map[string]any) (int, int, int) {
	spec := objectMap(object["spec"])
	status := objectMap(object["status"])
	total := len(objectList(spec["containers"]))
	ready, restarts := 0, 0
	for _, entry := range objectList(status["containerStatuses"]) {
		container := objectMap(entry)
		if readyFlag, ok := container["ready"].(bool); ok && readyFlag {
			ready++
		}
		restarts += intField(container, "restartCount")
	}
	return ready, total, restarts
}

func podPhase(object map[string]any) string {
	if phase := stringField(objectMap(object["status"]), "phase"); phase != "" {
		return phase
	}
	return "Running"
}

func podTemplateContainers(object map[string]any) ([]string, []string) {
	template := objectMap(objectMap(object["spec"])["template"])
	spec := objectMap(template["spec"])
	names, images := []string{}, []string{}
	for _, entry := range objectList(spec["containers"]) {
		container := objectMap(entry)
		names = append(names, stringField(container, "name"))
		images = append(images, stringField(container, "image"))
	}
	return names, images
}

func servicePorts(spec map[string]any) string {
	ports := make([]string, 0)
	for _, entry := range objectList(spec["ports"]) {
		port := objectMap(entry)
		out := anyString(port["port"])
		if target := anyString(port["targetPort"]); target != "" && target != out {
			out += "/" + target
		}
		if protocol := stringField(port, "protocol"); protocol != "" && protocol != "TCP" {
			out += "/" + protocol
		}
		ports = append(ports, out)
	}
	return strings.Join(ports, ",")
}

func selectorString(spec map[string]any) string {
	return matchLabelsString(objectMap(spec["selector"]))
}

func matchLabelsString(selector map[string]any) string {
	if len(selector) == 0 {
		return "<none>"
	}
	labels := objectMap(selector["matchLabels"])
	if len(labels) == 0 {
		labels = selector
	}
	parts := make([]string, 0, len(labels))
	for key, value := range labels {
		parts = append(parts, key+"="+anyString(value))
	}
	return strings.Join(parts, ",")
}

func endpointAddresses(object map[string]any) string {
	addresses := make([]string, 0)
	for _, subset := range objectList(object["subsets"]) {
		for _, address := range objectList(objectMap(subset)["addresses"]) {
			if ip := stringField(objectMap(address), "ip"); ip != "" {
				addresses = append(addresses, ip)
			}
		}
	}
	return strings.Join(addresses, ",")
}

func nodeReady(object map[string]any) string {
	for _, condition := range objectList(objectMap(object["status"])["conditions"]) {
		entry := objectMap(condition)
		if stringField(entry, "type") == "Ready" {
			if stringField(entry, "status") == "True" {
				return "Ready"
			}
			return "NotReady"
		}
	}
	return "Ready"
}

func nodeRoles(meta map[string]any) string {
	roles := make([]string, 0)
	for key := range objectMap(meta["labels"]) {
		if role, found := strings.CutPrefix(key, "node-role.kubernetes.io/"); found {
			roles = append(roles, role)
		}
	}
	if len(roles) == 0 {
		return "<none>"
	}
	return strings.Join(roles, ",")
}

func kubeletVersion(object map[string]any) string {
	return orDefault(stringField(objectMap(objectMap(object["status"])["nodeInfo"]), "kubeletVersion"), "v1.37.0")
}

func jobDuration(meta, status map[string]any) string {
	start, ok := status["startTime"].(string)
	if !ok {
		return ""
	}
	started, err := time.Parse(time.RFC3339, start)
	if err != nil {
		return ""
	}
	end := time.Now()
	if finished, ok := status["completionTime"].(string); ok {
		if parsed, err := time.Parse(time.RFC3339, finished); err == nil {
			end = parsed
		}
	}
	return formatAge(end.Sub(started))
}

func eventLastSeen(object map[string]any) string {
	for _, key := range []string{"lastTimestamp", "eventTime", "firstTimestamp"} {
		if value, ok := object[key].(string); ok && value != "" {
			return shortAgo(value)
		}
	}
	return "<unknown>"
}

// objectAge renders kubectl-style relative ages: 45s, 5m, 3h, 2d, 1y45d.
func objectAge(meta map[string]any) string {
	raw, _ := meta["creationTimestamp"].(string)
	return shortAgo(raw)
}

func shortAgo(raw string) string {
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return "<unknown>"
	}
	return formatAge(time.Since(parsed))
}

func formatAge(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < 2*time.Minute:
		return strconv.Itoa(int(d.Seconds())) + "s"
	case d < 2*time.Hour:
		return strconv.Itoa(int(d.Minutes())) + "m"
	case d < 48*time.Hour:
		return strconv.Itoa(int(d.Hours())) + "h"
	case d < 365*24*time.Hour:
		return strconv.Itoa(int(d.Hours()/24)) + "d"
	default:
		years := int(d.Hours() / 24 / 365)
		days := int(d.Hours()/24) - years*365
		return fmt.Sprintf("%dy%dd", years, days)
	}
}

func objectList(value any) []any {
	if list, ok := value.([]any); ok && list != nil {
		return list
	}
	return []any{}
}

func intField(object map[string]any, key string) int {
	switch value := object[key].(type) {
	case int:
		return value
	case int64:
		return int(value)
	case uint64:
		return int(value)
	case float64:
		return int(value)
	}
	return 0
}

func stringField(object map[string]any, key string) string {
	value, _ := object[key].(string)
	return value
}

func anyString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case uint64:
		return strconv.FormatUint(typed, 10)
	case int:
		return strconv.Itoa(typed)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", typed)
	}
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
