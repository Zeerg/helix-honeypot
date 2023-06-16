package config

import (
	"os"
	"strings"
)

type Config struct {
	HTTP               HTTPConfig
	K8SAPIVersion      string
	IPBase             string
	GenerateKubeSystem bool
	GenerateRandomness bool
	LogDestination     string
}

// If env vars are empty set a default
func GetEnv(key, defaultValue string) string {
	value := os.Getenv(key) // try to get the env var
	if len(value) == 0 {
		return defaultValue // if empty set default
	}
	return value // if not empty return env var
}

// GetEnvAsBool gets environment variables as boolean values. It returns false if the value is not "true" (case-insensitive), otherwise it returns true
func GetEnvAsBool(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return strings.ToLower(value) == "true"
}

func NewConfig() *Config {
	return &Config{
		HTTP:               LoadHTTPConfig(),
		K8SAPIVersion:      GetEnv("K8SAPI_VERSION", "v1.19"), // Default value is v1.19
		IPBase:             GetEnv("IP_BASE", "192.168"),      // Default value is 192.168
		GenerateKubeSystem: GetEnvAsBool("GENERATE_KUBE_SYSTEM", true), // Default is true
		GenerateRandomness: GetEnvAsBool("GENERATE_RANDOMNESS", true), // Default is true
		LogDestination:     GetEnv("LOG_DESTINATION", "./logs"), // Default is "./logs"
	}
}
