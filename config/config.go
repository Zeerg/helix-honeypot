package config

import (
	"os"
)

type Config struct {
	HTTP HTTPConfig
}

// If env vars are empty set a default
func GetEnv(key, defaultValue string) string {
	value := os.Getenv(key) // try to get the env var
	if len(value) == 0 {
		return defaultValue // if empty set default
	}
	return value // if not empty return env var
}

func NewConfig() *Config {
	return &Config{
		HTTP: LoadHTTPConfig(),
	}
}
