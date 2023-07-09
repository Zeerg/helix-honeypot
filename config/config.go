package config

import (
	"fmt"
	"os"
	"strings"

	"helix-honeypot/model"
)

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

func LoadHTTPConfig() model.HTTPConfig {
	return model.HTTPConfig{
		Host: GetEnv("HELIX_HOST", "localhost"), // Default value is localhost
		Port: GetEnv("HELIX_PORT", "80"),        // Default value is 80
	}
}

func LoadUDPConfig() model.UDPConfig {
	return model.UDPConfig{
		Host: GetEnv("HELIX_UDP_HOST", "localhost"), // Default value is localhost
		Port: GetEnv("HELIX_UDP_PORT", "53"),        // Default value is 80
	}
}
func LoadTCPConfig() model.TCPConfig {
	return model.TCPConfig{
		Host: GetEnv("HELIX_TCP_HOST", "localhost"), // Default value is localhost
		Port: GetEnv("HELIX_TCP_PORT", "443"),        // Default value is 80
	}
}
func LoadMongoDBConfig() model.MongoDBConfig {
	username := GetEnv("MONGODB_USERNAME", "helix")
	password := GetEnv("MONGODB_PASSWORD", "")
	host := GetEnv("MONGODB_HOST", "")
	database := GetEnv("MONGODB_DATABASE", "honeypot-data")
	collection := GetEnv("MONGODB_COLLECTION", "k8s-data")

	// Format the MongoDB URI
	uri := fmt.Sprintf("mongodb+srv://%s:%s@%s/", username, password, host)

	return model.MongoDBConfig{
		Username:       username,
		Password:       password,
		Host:           host,
		Database:       database,
		Collection:     collection,
		URI:            uri,
		LogToMongoDB:   GetEnvAsBool("LOG_TO_MONGODB", false),
	}
}

func NewConfig() *model.Config {
	return &model.Config{
		HTTP:               LoadHTTPConfig(),
		UDP:				LoadUDPConfig(),
		TCP:				LoadTCPConfig(),
		K8SAPIVersion:      GetEnv("K8SAPI_VERSION", "v1.19"), // Default value is v1.19
		IPBase:             GetEnv("IP_BASE", "192.168"),      // Default value is 192.168
		GenerateKubeSystem: GetEnvAsBool("GENERATE_KUBE_SYSTEM", true), // Default is true
		GenerateRandomness: GetEnvAsBool("GENERATE_RANDOMNESS", true), // Default is true
		MongoDB:            LoadMongoDBConfig(),
		RunMode:            GetEnv("RUN_MODE", "k8s"), // Default value is "ad"
	}
}
