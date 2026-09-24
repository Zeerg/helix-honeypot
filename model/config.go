package model

type HTTPConfig struct {
	Host string `toml:"host"`
	Port string `toml:"port"`
}

type UDPConfig struct {
	Host string `toml:"host"`
	Port string `toml:"port"`
}

type TCPConfig struct {
	Host string `toml:"host"`
	Port string `toml:"port"`
}

type KubeletConfig struct {
	Host        string `toml:"host"`
	Port        string `toml:"port"`
	NodeName    string `toml:"node_name"`
	TLSEnabled  *bool  `toml:"tls_enabled"`
	TLSCertFile string `toml:"tls_cert_file"`
	TLSKeyFile  string `toml:"tls_key_file"`
}

type RunModeConfig struct {
	RunMode string `toml:"mode"`
}

type K8SConfig struct {
	APIVersion      string          `toml:"api_version"`
	IPBase          string          `toml:"ip_base"`
	GenerateKubeSys bool            `toml:"generate_kube_system"`
	GenerateRand    bool            `toml:"generate_randomness"`
	Host            string          `toml:"host"`
	Port            string          `toml:"port"`
	TLSEnabled      bool            `toml:"tls_enabled"`
	TLSCertFile     string          `toml:"tls_cert_file"`
	TLSKeyFile      string          `toml:"tls_key_file"`
	Namespaces      []string        `toml:"namespaces"`
	Honeytokens     []K8SHoneytoken `toml:"honeytokens"`
	// TokenNames and TokenValues remain for compatibility with older configs.
	TokenValues []string `toml:"token_values"`
	TokenNames  []string `toml:"token_names"`
}

type K8SHoneytoken struct {
	Name      string            `toml:"name"`
	Namespace string            `toml:"namespace"`
	Type      string            `toml:"type"`
	Data      map[string]string `toml:"data"`
}

type LoggingConfig struct {
	Format            string          `toml:"format"`
	IncludeUserAgent  bool            `toml:"include_user_agent"`
	TrustedProxyCIDRs []string        `toml:"trusted_proxy_cidrs"`
	Sinks             []LogSinkConfig `toml:"sinks"`
}

// LogSinkConfig describes one additional destination for honeypot events.
// The local event output remains the primary record; sinks are best-effort
// fan-out and must never block or delay event capture.
type LogSinkConfig struct {
	Type       string            `toml:"type"`
	URL        string            `toml:"url"`
	Path       string            `toml:"path"`
	Index      string            `toml:"index"`
	Source     string            `toml:"source"`
	Sourcetype string            `toml:"sourcetype"`
	Token      string            `toml:"token"`
	Username   string            `toml:"username"`
	Password   string            `toml:"password"`
	Headers    map[string]string `toml:"headers"`
}

type Config struct {
	HTTP    HTTPConfig    `toml:"http"`
	UDP     UDPConfig     `toml:"udp"`
	TCP     TCPConfig     `toml:"tcp"`
	Kubelet KubeletConfig `toml:"kubelet"`
	K8S     K8SConfig     `toml:"k8s"`
	RunMode RunModeConfig `toml:"run_mode"`
	Logging LoggingConfig `toml:"logging"`
}

// SensitiveValues returns a bounded copy of all configured credential material
// for exact event-log redaction. Values are never emitted by this method.
func (c Config) SensitiveValues() []string {
	return mergeSensitive(c.K8S.SensitiveValues(), c.Logging.SensitiveValues())
}

// SensitiveValues returns configured sink credentials for event-log redaction.
// Header values are included because they commonly carry API keys.
func (l LoggingConfig) SensitiveValues() []string {
	const (
		maxValues = 64
		maxBytes  = 16 << 10
	)
	values := make([]string, 0, maxValues)
	totalBytes := 0
	add := func(value string) bool {
		if value == "" || len(values) >= maxValues || totalBytes+len(value) > maxBytes {
			return false
		}
		values = append(values, value)
		totalBytes += len(value)
		return true
	}
	for _, sink := range l.Sinks {
		if !add(sink.Token) || !add(sink.Password) {
			return values
		}
		for _, value := range sink.Headers {
			if !add(value) {
				return values
			}
		}
	}
	return values
}

func mergeSensitive(base, extra []string) []string {
	const maxValues = 320
	if len(base)+len(extra) > maxValues {
		if keep := maxValues - len(base); keep > 0 {
			extra = extra[:keep]
		} else {
			return base
		}
	}
	return append(base, extra...)
}

// SensitiveValues returns a bounded copy of configured credential material for
// exact event-log redaction. Values are never emitted by this method.
func (k K8SConfig) SensitiveValues() []string {
	const (
		maxValues = 320
		maxBytes  = 16 << 10
	)
	values := make([]string, 0, maxValues)
	totalBytes := 0
	add := func(value string) bool {
		if value == "" || len(values) >= maxValues || totalBytes+len(value) > maxBytes {
			return false
		}
		values = append(values, value)
		totalBytes += len(value)
		return true
	}
	for _, value := range k.TokenValues {
		if !add(value) && len(values) >= maxValues {
			return values
		}
	}
	for _, honeytoken := range k.Honeytokens {
		for _, value := range honeytoken.Data {
			if !add(value) && len(values) >= maxValues {
				return values
			}
		}
	}
	return values
}
