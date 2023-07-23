package generator

import (
	"math/rand"
	"sort"
	"time"

	"helix-honeypot/model"
)

func generatePodConfig(cfg *model.Config, namespace string, podNames []string, resourceVersion string) map[string]interface{} {
	rand.Seed(time.Now().UnixNano()) // Seeding the random number generator
	pods := make([]interface{}, rand.Intn(110)+10)
	for i := range pods {
		pods[i] = GeneratePod(cfg, namespace, podNames)
	}

	// Sort pods
	sort.SliceStable(pods, func(i, j int) bool {
		iPod := pods[i].(map[string]interface{})
		jPod := pods[j].(map[string]interface{})
		iName := iPod["object"].(map[string]interface{})["metadata"].(map[string]interface{})["name"].(string)
		jName := jPod["object"].(map[string]interface{})["metadata"].(map[string]interface{})["name"].(string)
		return iName < jName
	})

	config := map[string]interface{}{
		"kind":       "Table",
		"apiVersion": "meta.k8s.io/v1",
		"metadata": map[string]interface{}{
			"resourceVersion": resourceVersion,
		},
		"columnDefinitions": GenerateColumnDefinitions(),
		"rows":              pods,
	}

	return config
}

func GenerateKubeSystemConfig(cfg *model.Config, namespace string) map[string]interface{} {
	podNames := []string{
		"kube-apiserver", "kube-controller-manager", "kube-scheduler",
		"kube-proxy", "etcd", "coredns", "kube-addon-manager",
		"kube-flannel", "kube-calico", "kube-dns", "kube-sidecar",
		"kube-state-metrics", "kube-ingress-controller", "kube-dashboard",
		"kube-metrics-scraper", "kube-network-manager", "kube-node-exporter",
		"kube-persistent-storage", "kube-csi", "kubelet", "kube-proxy",
		"kube-vpnkit-controller", "kube-storage-provisioner",
	}
	return generatePodConfig(cfg, namespace, podNames, "1110")
}


func GenerateDefaultNamespaceConfig(cfg *model.Config, namespace string) map[string]interface{} {
	podNames := []string{
		"database", "message-queue", "cache", "nginx", "apache", "tomcat",
		"redis", "elasticsearch", "rabbitmq", "kafka", "memcached", "mysql",
		"postgres", "mongo", "cassandra", "influxdb", "grafana", "prometheus",
		"wordpress", "jenkins", "gitlab", "drupal", "magento", "django",
		"laravel", "nodejs", "express", "flask", "spring-boot", "react",
		"angular", "vuejs", "emberjs", "kubernetes", "docker", "minio",
		"jupyter", "tensorflow", "spark", "git", "consul", "vault",
		"kibana", "haproxy", "traefik", "graylog", "sonarqube", "nexus",
		"zookeeper", "etcd", "nextcloud", "ghost", "owncloud", "clickhouse",
		"metabase", "nginx-ingress", "kong", "keycloak", "rancher", "logstash",
		"aws-lambda", "aws-s3", "aws-dynamodb", "aws-rds", "aws-sqs", "aws-sns",
		"gcp-cloud-run", "gcp-datastore", "gcp-pubsub", "azure-functions", "azure-storage", "azure-cosmosdb",
		"azure-service-bus", "kafka", "rabbitmq", "hadoop", "couchbase", "couchdb",
		"neo4j", "clickhouse", "varnish", "traefik", "gitlab-runner", "nats",
		"apollo", "jitsi", "rocketmq", "deno", "glusterfs", "prometheus-operator",
		"rancher", "knative", "fluentd", "openfaas", "loki", "istio",
		"redis-cache", "postgresql", "mongodb", "couchbase", "apache-kafka", "nginx-ingress-controller",
		"jenkins-x", "drone", "openshift", "gitlab-ci", "bitbucket-pipelines", "teamcity",
		"spinnaker", "artifactory", "nexus-repository", "kong-api-gateway", "tyk-api-gateway", "azure-apim",
		"consul-service-mesh", "linkerd", "kuma", "flannel", "weave", "cilium",
		"argocd", "fluxcd", "istio", "knative", "keda", "helm",
		"tekton", "argo-workflows", "falco", "sysdig", "calico", "openshift-sdn",
		"fluent-bit", "logstash", "telegraf", "papertrail", "logentries", "logdna",
	}
	return generatePodConfig(cfg, namespace, podNames, "3572")
}
