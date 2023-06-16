package generator

import (
	"math/rand"
	"sort"
	"time"

	"helix-honeypot/config"
)

func GenerateKubeSystemConfig(cfg *config.Config) map[string]interface{} {
	// Generate Config
	rand.Seed(time.Now().UnixNano())              // Seeding the random number generator
	pods := make([]interface{}, rand.Intn(11)+10) // between 10 and 20 pods
	for i := range pods {
		pods[i] = GeneratePod(cfg)
	}

	// Sort pods
	sort.SliceStable(pods, func(i, j int) bool {
		iPod := pods[i].(map[string]interface{})
		jPod := pods[j].(map[string]interface{})
		iName := iPod["object"].(map[string]interface{})["metadata"].(map[string]interface{})["name"].(string)
		jName := jPod["object"].(map[string]interface{})["metadata"].(map[string]interface{})["name"].(string)
		return iName < jName
	})

	kubeSystemConfig := map[string]interface{}{
		"kind":       "Table",
		"apiVersion": "meta.k8s.io/v1",
		"metadata": map[string]interface{}{
			"resourceVersion": "1110",
		},
		"columnDefinitions": GenerateColumnDefinitions(),
		"rows":              pods,
	}

	return kubeSystemConfig
}
