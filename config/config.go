package config

import (
	"fmt"
	"os"
	"io/ioutil"
	"strings"

	"helix-honeypot/model"
	"github.com/BurntSushi/toml"
)

// GetEnvAsBool gets environment variables as boolean values. It returns false if the value is not "true" (case-insensitive), otherwise it returns true
func GetEnvAsBool(key string) bool {
	value := os.Getenv(key)
	return strings.ToLower(value) == "true"
}

func LoadK8SConfig(cfg *model.K8SConfig) model.K8SConfig {
    apiVersion := os.Getenv("K8SAPI_VERSION")
    ipBase := os.Getenv("IP_BASE")
    host := os.Getenv("K8S_HOST")
    port := os.Getenv("K8S_PORT")

    if apiVersion != "" {
        cfg.APIVersion = apiVersion
    }
    if ipBase != "" {
        cfg.IPBase = ipBase
    }
    if host != "" {
        cfg.Host = host
    }
    if port != "" {
        cfg.Port = port
    }

    // Since the zero value for a boolean in Go is `false`, 
    // we only need to check if the environment variable is "true".
    if strings.ToLower(os.Getenv("GENERATE_KUBE_SYSTEM")) == "true" {
        cfg.GenerateKubeSys = true
    }
    if strings.ToLower(os.Getenv("GENERATE_RANDOMNESS")) == "true" {
        cfg.GenerateRand = true
    }

    return *cfg
}

func LoadHTTPConfig(cfg *model.HTTPConfig) model.HTTPConfig {
    host := os.Getenv("HELIX_HTTP_HOST")
    port := os.Getenv("HELIX_HTTP_PORT")

    if host != "" {
        cfg.Host = host
    }
    if port != "" {
        cfg.Port = port
    }

    return *cfg
}

func LoadUDPConfig(cfg *model.UDPConfig) model.UDPConfig {
    host := os.Getenv("HELIX_UDP_HOST")
    port := os.Getenv("HELIX_UDP_PORT")

    if host != "" {
        cfg.Host = host
    }
    if port != "" {
        cfg.Port = port
    }

    return *cfg
}

func LoadTCPConfig(cfg *model.TCPConfig) model.TCPConfig {
    host := os.Getenv("HELIX_TCP_HOST")
    port := os.Getenv("HELIX_TCP_PORT")

    if host != "" {
        cfg.Host = host
    }
    if port != "" {
        cfg.Port = port
    }

    return *cfg
}

func LoadMongoDBConfig(cfg *model.MongoDBConfig) model.MongoDBConfig {
	username := os.Getenv("MONGODB_USERNAME")
	password := os.Getenv("MONGODB_PASSWORD")
	host := os.Getenv("MONGODB_HOST")
	database := os.Getenv("MONGODB_DATABASE")
	collection := os.Getenv("MONGODB_COLLECTION")

	if username != "" {
		cfg.Username = username
	}
	if password != "" {
		cfg.Password = password
	}
	if host != "" {
		cfg.Host = host
	}
	if database != "" {
		cfg.Database = database
	}
	if collection != "" {
		cfg.Collection = collection
	}

	// Format the MongoDB URI
	uri := fmt.Sprintf("mongodb+srv://%s:%s@%s/", cfg.Username, cfg.Password, cfg.Host)
	cfg.URI = uri

	if strings.ToLower(os.Getenv("LOG_TO_MONGODB")) == "true" {
		cfg.LogToMongoDB = true
	}

	return *cfg
}

func LoadRunModeConfig(cfg *model.RunModeConfig) model.RunModeConfig {
    runMode := os.Getenv("RUN_MODE")
    location := os.Getenv("HELIX_LOCATION")

    if runMode != "" {
        cfg.RunMode = runMode
    }
    if location != "" {
        cfg.Location = location
    }

    return *cfg
}

func NewConfig(configFile string) (*model.Config, error) {
    // Load default values from TOML file
    var cfg model.Config
    data, err := ioutil.ReadFile(configFile)
    if err != nil {
        return nil, err
    }
    _, err = toml.Decode(string(data), &cfg)
    if err != nil {
        return nil, err
    }

    // Override with environment variables
    cfg.HTTP = LoadHTTPConfig(&cfg.HTTP)
    cfg.UDP = LoadUDPConfig(&cfg.UDP)
    cfg.TCP = LoadTCPConfig(&cfg.TCP)
    cfg.K8S = LoadK8SConfig(&cfg.K8S)
    cfg.MongoDB = LoadMongoDBConfig(&cfg.MongoDB)
    cfg.RunMode = LoadRunModeConfig(&cfg.RunMode)

    return &cfg, nil
}
