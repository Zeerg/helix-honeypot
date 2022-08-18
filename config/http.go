package config

type HTTPConfig struct {
	Host string
	Port string
}

func LoadHTTPConfig() HTTPConfig {
	return HTTPConfig{
		Host: GetEnv("HELIX_HOST", "0.0.0.0"),
		Port: GetEnv("HELIX_PORT", "80"),
	}
}
