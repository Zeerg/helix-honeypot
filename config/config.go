// Package config loads the honeypot's local configuration.
package config

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"helix-honeypot/model"
)

const (
	defaultConfigFile             = "config.toml"
	maxConfigBytes                = 1 << 20
	maxTokenCount                 = 64
	maxTokenBytes                 = 256
	maxTokenTotal                 = 16 << 10
	maxNamespaceCount             = 64
	maxNamespaceBytes             = 63
	maxHoneytokenCount            = 64
	maxHoneytokenDataEntries      = 16
	maxTotalHoneytokenDataEntries = 256
	maxHoneytokenValueBytes       = 4 << 10
	maxSecretPayloadBytes         = 16 << 10
	maxTrustedProxyCIDRs          = 16
	maxTrustedProxyCIDRBytes      = 64
	maxSinkCount                  = 8
	maxSinkURLBytes               = 2048
	maxSinkPathBytes              = 1024
	maxSinkFieldBytes             = 256
	maxSinkCredentialBytes        = 2048
	maxSinkIndexBytes             = 255
	maxSinkHeaders                = 16
	maxSinkHeaderNameBytes        = 128
	maxSinkHeaderValueBytes       = 2048
)

// Defaults returns an explicitly configured, loopback-only setup. Operators
// must opt in to binding on a network interface reachable by other machines.
func Defaults() model.Config {
	return model.Config{
		HTTP: model.HTTPConfig{Host: "127.0.0.1", Port: "8081"},
		UDP:  model.UDPConfig{Host: "127.0.0.1", Port: "9053"},
		TCP:  model.TCPConfig{Host: "127.0.0.1", Port: "9022"},
		Kubelet: model.KubeletConfig{
			Host:     "127.0.0.1",
			Port:     "10250",
			NodeName: "worker-01",
		},
		K8S: model.K8SConfig{
			APIVersion:      "v1.37",
			IPBase:          "10.42.0.0",
			GenerateKubeSys: true,
			GenerateRand:    false,
			Host:            "127.0.0.1",
			Port:            "8080",
			Namespaces:      []string{},
			Honeytokens:     []model.K8SHoneytoken{},
			TokenValues:     []string{},
			TokenNames:      []string{},
		},
		// Kubernetes is the primary façade. The additional listeners remain
		// independently selectable and retain safe, non-privileged defaults.
		RunMode: model.RunModeConfig{RunMode: "k8s"},
		Logging: model.LoggingConfig{
			Format:            "json",
			IncludeUserAgent:  false,
			TrustedProxyCIDRs: []string{},
		},
	}
}

// NewConfig loads optional TOML configuration, overlays environment variables,
// and validates the selected mode before any network listener is opened.
// An empty path uses HELIX_CONFIG when set, otherwise config.toml. A missing
// config file is allowed so the explicit defaults work out of the box.
func NewConfig(configFile string) (*model.Config, error) {
	cfg := Defaults()
	if configFile == "" {
		configFile = firstEnv("HELIX_CONFIG")
	}
	if configFile == "" {
		configFile = defaultConfigFile
	}

	file, err := os.Open(configFile)
	if err == nil {
		data, readErr := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
		closeErr := file.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read config file %q: %w", configFile, readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close config file %q: %w", configFile, closeErr)
		}
		if len(data) > maxConfigBytes {
			return nil, fmt.Errorf("config file %q exceeds the %d-byte limit", configFile, maxConfigBytes)
		}
		if _, err := toml.Decode(string(data), &cfg); err != nil {
			// TOML errors can include offending values. Keep credentials and
			// honeytoken payloads out of startup logs.
			return nil, fmt.Errorf("decode config file %q: invalid TOML configuration", configFile)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read config file %q: %w", configFile, err)
	}

	if err := applyEnvironment(&cfg); err != nil {
		return nil, err
	}
	normalize(&cfg)
	if err := Validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func applyEnvironment(cfg *model.Config) error {
	setString(&cfg.RunMode.RunMode, "HELIX_RUN_MODE", "RUN_MODE")
	setString(&cfg.K8S.APIVersion, "HELIX_K8S_API_VERSION", "K8SAPI_VERSION")
	setString(&cfg.K8S.IPBase, "HELIX_K8S_IP_BASE", "IP_BASE")
	setString(&cfg.K8S.Host, "HELIX_K8S_HOST", "K8S_HOST")
	setString(&cfg.K8S.Port, "HELIX_K8S_PORT", "K8S_PORT")
	setString(&cfg.HTTP.Host, "HELIX_HTTP_HOST")
	setString(&cfg.HTTP.Port, "HELIX_HTTP_PORT")
	setString(&cfg.TCP.Host, "HELIX_TCP_HOST")
	setString(&cfg.TCP.Port, "HELIX_TCP_PORT")
	setString(&cfg.UDP.Host, "HELIX_UDP_HOST")
	setString(&cfg.UDP.Port, "HELIX_UDP_PORT")
	setString(&cfg.Kubelet.Host, "HELIX_KUBELET_HOST")
	setString(&cfg.Kubelet.Port, "HELIX_KUBELET_PORT")
	setString(&cfg.Kubelet.NodeName, "HELIX_KUBELET_NODE_NAME")

	if value, ok := firstSetEnv("HELIX_K8S_GENERATE_KUBE_SYSTEM", "GENERATE_KUBE_SYSTEM"); ok {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid boolean for HELIX_K8S_GENERATE_KUBE_SYSTEM")
		}
		cfg.K8S.GenerateKubeSys = parsed
	}
	if value, ok := firstSetEnv("HELIX_K8S_GENERATE_RANDOMNESS", "GENERATE_RANDOMNESS"); ok {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid boolean for HELIX_K8S_GENERATE_RANDOMNESS")
		}
		cfg.K8S.GenerateRand = parsed
	}
	if value, ok := firstSetEnv("HELIX_K8S_TOKEN_VALUES"); ok {
		values, err := splitList(value, "HELIX_K8S_TOKEN_VALUES", maxTokenCount, maxTokenBytes, maxTokenTotal+maxTokenCount-1)
		if err != nil {
			return err
		}
		cfg.K8S.TokenValues = values
	}
	if value, ok := firstSetEnv("HELIX_K8S_TOKEN_NAMES"); ok {
		values, err := splitList(value, "HELIX_K8S_TOKEN_NAMES", maxTokenCount, maxTokenBytes, maxTokenTotal+maxTokenCount-1)
		if err != nil {
			return err
		}
		cfg.K8S.TokenNames = values
	}
	if value, ok := firstSetEnv("HELIX_K8S_NAMESPACES"); ok {
		values, err := splitList(value, "HELIX_K8S_NAMESPACES", maxNamespaceCount, maxNamespaceBytes, maxNamespaceCount*(maxNamespaceBytes+1))
		if err != nil {
			return err
		}
		cfg.K8S.Namespaces = values
	}
	if value, ok := firstSetEnv("HELIX_K8S_HONEYTOKENS"); ok {
		honeytokens, err := parseEnvHoneytokens(value)
		if err != nil {
			return err
		}
		cfg.K8S.Honeytokens = append(cfg.K8S.Honeytokens, honeytokens...)
	}
	setString(&cfg.Logging.Format, "HELIX_LOG_FORMAT")
	if value, ok := firstSetEnv("HELIX_LOG_INCLUDE_USER_AGENT"); ok {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid boolean for HELIX_LOG_INCLUDE_USER_AGENT")
		}
		cfg.Logging.IncludeUserAgent = parsed
	}
	if value, ok := firstSetEnv("HELIX_LOG_TRUSTED_PROXY_CIDRS"); ok {
		values, err := splitList(value, "HELIX_LOG_TRUSTED_PROXY_CIDRS", maxTrustedProxyCIDRs, maxTrustedProxyCIDRBytes, maxTrustedProxyCIDRs*(maxTrustedProxyCIDRBytes+1))
		if err != nil {
			return err
		}
		cfg.Logging.TrustedProxyCIDRs = values
	}
	return applyEnvSinks(cfg)
}

// applyEnvSinks lets a container or shell-only deployment attach one sink of
// each type without writing a TOML file. The anchor variable (URL or path)
// enables the sink; the remaining variables fill its fields. TOML stays the
// way to express multiple sinks of one type.
func applyEnvSinks(cfg *model.Config) error {
	if path, ok := firstSetEnv("HELIX_LOG_FILE"); ok {
		cfg.Logging.Sinks = append(cfg.Logging.Sinks, model.LogSinkConfig{Type: "file", Path: path})
	}
	if url, ok := firstSetEnv("HELIX_SPLUNK_URL"); ok {
		cfg.Logging.Sinks = append(cfg.Logging.Sinks, model.LogSinkConfig{
			Type:       "splunk",
			URL:        url,
			Token:      firstEnv("HELIX_SPLUNK_TOKEN"),
			Index:      firstEnv("HELIX_SPLUNK_INDEX"),
			Source:     firstEnv("HELIX_SPLUNK_SOURCE"),
			Sourcetype: firstEnv("HELIX_SPLUNK_SOURCETYPE"),
		})
	}
	if url, ok := firstSetEnv("HELIX_ELASTICSEARCH_URL", "HELIX_ELK_URL"); ok {
		cfg.Logging.Sinks = append(cfg.Logging.Sinks, model.LogSinkConfig{
			Type:     "elasticsearch",
			URL:      url,
			Index:    firstEnv("HELIX_ELASTICSEARCH_INDEX"),
			Token:    firstEnv("HELIX_ELASTICSEARCH_TOKEN"),
			Username: firstEnv("HELIX_ELASTICSEARCH_USERNAME"),
			Password: firstEnv("HELIX_ELASTICSEARCH_PASSWORD"),
		})
	}
	if url, ok := firstSetEnv("HELIX_HTTP_SINK_URL"); ok {
		sink := model.LogSinkConfig{Type: "http", URL: url, Token: firstEnv("HELIX_HTTP_SINK_TOKEN")}
		if value, ok := firstSetEnv("HELIX_HTTP_SINK_HEADERS"); ok {
			headers, err := parseEnvHeaders(value, "HELIX_HTTP_SINK_HEADERS")
			if err != nil {
				return err
			}
			sink.Headers = headers
		}
		cfg.Logging.Sinks = append(cfg.Logging.Sinks, sink)
	}
	return nil
}

// parseEnvHoneytokens decodes HELIX_K8S_HONEYTOKENS entries of the form
// "name[@namespace]:key=value[,key=value]" separated by semicolons. Names and
// keys follow Kubernetes Secret rules; values may not contain ',' or ';'
// (use TOML for those). Data values are secret material, so errors reference
// entry indexes only and never echo entry contents.
func parseEnvHoneytokens(value string) ([]model.K8SHoneytoken, error) {
	const maxBytes = 64 << 10
	if len(value) > maxBytes {
		return nil, fmt.Errorf("HELIX_K8S_HONEYTOKENS exceeds the %d-byte limit", maxBytes)
	}
	var tokens []model.K8SHoneytoken
	for _, entry := range strings.Split(value, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if len(tokens) >= maxHoneytokenCount {
			return nil, fmt.Errorf("HELIX_K8S_HONEYTOKENS may contain at most %d entries", maxHoneytokenCount)
		}
		index := len(tokens) + 1
		head, data, found := strings.Cut(entry, ":")
		if !found {
			return nil, fmt.Errorf("HELIX_K8S_HONEYTOKENS entry %d lacks a 'name:key=value' separator", index)
		}
		name, namespace, _ := strings.Cut(strings.TrimSpace(head), "@")
		fields := map[string]string{}
		for _, pair := range strings.Split(data, ",") {
			key, fieldValue, ok := strings.Cut(pair, "=")
			key = strings.TrimSpace(key)
			if !ok || key == "" {
				return nil, fmt.Errorf("HELIX_K8S_HONEYTOKENS entry %d contains a malformed key=value pair", index)
			}
			if _, dup := fields[key]; dup {
				return nil, fmt.Errorf("HELIX_K8S_HONEYTOKENS entry %d repeats a data key", index)
			}
			fields[key] = fieldValue
		}
		tokens = append(tokens, model.K8SHoneytoken{Name: name, Namespace: namespace, Data: fields})
	}
	if len(tokens) == 0 {
		return nil, fmt.Errorf("HELIX_K8S_HONEYTOKENS contains no entries")
	}
	return tokens, nil
}

// parseEnvHeaders decodes "Name:Value;Name2:Value2" header lists. Header
// values may carry secrets, so errors stay index-only like honeytoken errors.
func parseEnvHeaders(value, variable string) (map[string]string, error) {
	const maxBytes = 64 << 10
	if len(value) > maxBytes {
		return nil, fmt.Errorf("%s exceeds the %d-byte limit", variable, maxBytes)
	}
	headers := map[string]string{}
	for _, entry := range strings.Split(value, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if len(headers) >= maxSinkHeaders {
			return nil, fmt.Errorf("%s may contain at most %d headers", variable, maxSinkHeaders)
		}
		name, headerValue, ok := strings.Cut(entry, ":")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return nil, fmt.Errorf("%s contains a malformed 'Name:Value' entry", variable)
		}
		headers[name] = strings.TrimSpace(headerValue)
	}
	if err := validateSinkHeaders(headers); err != nil {
		return nil, fmt.Errorf("%s: %w", variable, err)
	}
	return headers, nil
}

func setString(target *string, keys ...string) {
	if value, ok := firstSetEnv(keys...); ok {
		*target = value
	}
}

func firstEnv(keys ...string) string {
	value, _ := firstSetEnv(keys...)
	return value
}

func firstSetEnv(keys ...string) (string, bool) {
	for _, key := range keys {
		if value, ok := os.LookupEnv(key); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value), true
		}
	}
	return "", false
}

func splitList(value, variable string, maxCount, maxEntryBytes, maxInputBytes int) ([]string, error) {
	if len(value) > maxInputBytes {
		return nil, fmt.Errorf("%s exceeds the token-list size limit", variable)
	}
	values := make([]string, 0, maxCount)
	for start := 0; start <= len(value); {
		end := strings.IndexByte(value[start:], ',')
		if end < 0 {
			end = len(value)
		} else {
			end += start
		}
		part := strings.TrimSpace(value[start:end])
		if part != "" {
			if len(values) == maxCount {
				return nil, fmt.Errorf("%s may contain at most %d entries", variable, maxCount)
			}
			if len(part) > maxEntryBytes {
				return nil, fmt.Errorf("%s entries may be at most %d bytes", variable, maxEntryBytes)
			}
			values = append(values, part)
		}
		if end == len(value) {
			break
		}
		start = end + 1
	}
	return values, nil
}

func normalize(cfg *model.Config) {
	cfg.RunMode.RunMode = strings.ToLower(strings.TrimSpace(cfg.RunMode.RunMode))
	cfg.K8S.APIVersion = strings.TrimSpace(cfg.K8S.APIVersion)
	cfg.K8S.IPBase = strings.TrimSpace(cfg.K8S.IPBase)
	for i := range cfg.K8S.Honeytokens {
		cfg.K8S.Honeytokens[i].Namespace = strings.TrimSpace(cfg.K8S.Honeytokens[i].Namespace)
		cfg.K8S.Honeytokens[i].Type = strings.TrimSpace(cfg.K8S.Honeytokens[i].Type)
		if cfg.K8S.Honeytokens[i].Type == "" {
			cfg.K8S.Honeytokens[i].Type = "Opaque"
		}
	}
	cfg.Kubelet.NodeName = strings.TrimSpace(cfg.Kubelet.NodeName)
	cfg.Logging.Format = strings.ToLower(strings.TrimSpace(cfg.Logging.Format))
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "json"
	}
	for i := range cfg.Logging.Sinks {
		cfg.Logging.Sinks[i].Type = strings.ToLower(strings.TrimSpace(cfg.Logging.Sinks[i].Type))
		cfg.Logging.Sinks[i].URL = strings.TrimSpace(cfg.Logging.Sinks[i].URL)
		cfg.Logging.Sinks[i].Index = strings.TrimSpace(cfg.Logging.Sinks[i].Index)
	}
}

// Validate checks the selected listener and the Kubernetes profile before
// startup. Bind addresses must be IP literals so listener startup never needs
// to resolve a hostname or issue a DNS query.
func Validate(cfg *model.Config) error {
	if cfg == nil {
		return fmt.Errorf("configuration is nil")
	}
	var host, port string
	switch cfg.RunMode.RunMode {
	case "k8s":
		host, port = cfg.K8S.Host, cfg.K8S.Port
	case "http":
		host, port = cfg.HTTP.Host, cfg.HTTP.Port
	case "tcp":
		host, port = cfg.TCP.Host, cfg.TCP.Port
	case "udp":
		host, port = cfg.UDP.Host, cfg.UDP.Port
	case "kubelet":
		host, port = cfg.Kubelet.Host, cfg.Kubelet.Port
	default:
		return fmt.Errorf("unknown run mode %q: choose k8s, http, tcp, udp, or kubelet", cfg.RunMode.RunMode)
	}
	if cfg.RunMode.RunMode == "kubelet" && !validTokenName(cfg.Kubelet.NodeName) {
		return fmt.Errorf("invalid kubelet node_name: expected a lowercase DNS subdomain")
	}
	if err := validateKubernetesProfile(cfg.K8S); err != nil {
		return err
	}
	if err := validateTokens(cfg.K8S); err != nil {
		return err
	}
	if err := validateNamespaces(cfg.K8S.Namespaces); err != nil {
		return err
	}
	if err := validateHoneytokens(cfg.K8S); err != nil {
		return err
	}
	if err := validateLogging(cfg.Logging); err != nil {
		return err
	}
	if err := validateSinks(cfg.Logging.Sinks); err != nil {
		return err
	}
	if err := validateHost(host); err != nil {
		return fmt.Errorf("invalid %s bind host: %w", cfg.RunMode.RunMode, err)
	}
	if err := validatePort(port); err != nil {
		return fmt.Errorf("invalid %s bind port: %w", cfg.RunMode.RunMode, err)
	}
	return nil
}

func validateTokens(cfg model.K8SConfig) error {
	if len(cfg.TokenValues) > maxTokenCount {
		return fmt.Errorf("Kubernetes token_values may contain at most %d entries", maxTokenCount)
	}
	if len(cfg.TokenNames) > maxTokenCount {
		return fmt.Errorf("Kubernetes token_names may contain at most %d entries", maxTokenCount)
	}
	totalBytes := 0
	for i, value := range cfg.TokenValues {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("Kubernetes token_values entry %d must not be empty", i+1)
		}
		if len(value) > maxTokenBytes {
			return fmt.Errorf("Kubernetes token_values entry %d exceeds the %d-byte limit", i+1, maxTokenBytes)
		}
		totalBytes += len(value)
	}
	for i, name := range cfg.TokenNames {
		if !validTokenName(name) {
			return fmt.Errorf("invalid Kubernetes token_names entry %d: expected a lowercase DNS subdomain name", i+1)
		}
		totalBytes += len(name)
	}
	if totalBytes > maxTokenTotal {
		return fmt.Errorf("Kubernetes token_names and token_values exceed the %d-byte aggregate limit", maxTokenTotal)
	}
	return nil
}

func validTokenName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || !isLowerAlphaNumeric(label[0]) || !isLowerAlphaNumeric(label[len(label)-1]) {
			return false
		}
		for i := 1; i < len(label)-1; i++ {
			if !isLowerAlphaNumeric(label[i]) && label[i] != '-' {
				return false
			}
		}
	}
	return true
}

func isLowerAlphaNumeric(char byte) bool {
	return char >= 'a' && char <= 'z' || char >= '0' && char <= '9'
}

func validateNamespaces(namespaces []string) error {
	if len(namespaces) > maxNamespaceCount {
		return fmt.Errorf("Kubernetes namespaces may contain at most %d entries", maxNamespaceCount)
	}
	seen := make(map[string]struct{}, len(namespaces))
	for i, namespace := range namespaces {
		if !validDNSLabel(namespace) {
			return fmt.Errorf("invalid Kubernetes namespaces entry %d: expected a lowercase DNS label", i+1)
		}
		if _, exists := seen[namespace]; exists {
			return fmt.Errorf("duplicate Kubernetes namespaces entry %d", i+1)
		}
		seen[namespace] = struct{}{}
	}
	return nil
}

func validateHoneytokens(cfg model.K8SConfig) error {
	if len(cfg.Honeytokens) > maxHoneytokenCount {
		return fmt.Errorf("Kubernetes honeytokens may contain at most %d entries", maxHoneytokenCount)
	}

	allowedNamespaces := map[string]struct{}{
		"default":         {},
		"kube-system":     {},
		"kube-public":     {},
		"kube-node-lease": {},
	}
	for _, namespace := range cfg.Namespaces {
		allowedNamespaces[namespace] = struct{}{}
	}

	totalDataEntries := 0
	totalSecretBytes := 0
	seenSecrets := make(map[string]struct{}, len(cfg.Honeytokens))
	for _, value := range cfg.TokenValues {
		totalSecretBytes += len(value)
	}
	for i, honeytoken := range cfg.Honeytokens {
		if !validTokenName(honeytoken.Name) {
			return fmt.Errorf("invalid Kubernetes honeytokens entry %d name: expected a lowercase DNS subdomain", i+1)
		}
		namespace := honeytoken.Namespace
		if namespace == "" {
			namespace = "default"
		}
		if !validDNSLabel(namespace) {
			return fmt.Errorf("invalid Kubernetes honeytokens entry %d namespace: expected a lowercase DNS label", i+1)
		}
		if _, exists := allowedNamespaces[namespace]; !exists {
			return fmt.Errorf("Kubernetes honeytokens entry %d uses a namespace that is neither built in nor configured in k8s.namespaces", i+1)
		}
		secretID := namespace + "\x00" + honeytoken.Name
		if _, exists := seenSecrets[secretID]; exists {
			return fmt.Errorf("duplicate Kubernetes honeytokens entry %d name and namespace", i+1)
		}
		seenSecrets[secretID] = struct{}{}
		if !validHoneytokenType(honeytoken.Type) {
			return fmt.Errorf("invalid Kubernetes honeytokens entry %d type", i+1)
		}
		if len(honeytoken.Data) == 0 {
			return fmt.Errorf("Kubernetes honeytokens entry %d must include at least one data entry", i+1)
		}
		if len(honeytoken.Data) > maxHoneytokenDataEntries {
			return fmt.Errorf("Kubernetes honeytokens entry %d may contain at most %d data entries", i+1, maxHoneytokenDataEntries)
		}
		totalDataEntries += len(honeytoken.Data)
		for key, value := range honeytoken.Data {
			if !validSecretDataKey(key) {
				return fmt.Errorf("Kubernetes honeytokens entry %d contains an invalid data key", i+1)
			}
			if len(value) > maxHoneytokenValueBytes {
				return fmt.Errorf("Kubernetes honeytokens entry %d data values may be at most %d bytes", i+1, maxHoneytokenValueBytes)
			}
			totalSecretBytes += len(value)
		}
	}
	if totalDataEntries > maxTotalHoneytokenDataEntries {
		return fmt.Errorf("Kubernetes honeytokens may contain at most %d data entries in total", maxTotalHoneytokenDataEntries)
	}
	if totalSecretBytes > maxSecretPayloadBytes {
		return fmt.Errorf("Kubernetes token and honeytoken data exceeds the %d-byte aggregate payload limit", maxSecretPayloadBytes)
	}
	return nil
}

func validDNSLabel(value string) bool {
	if len(value) == 0 || len(value) > maxNamespaceBytes || !isLowerAlphaNumeric(value[0]) || !isLowerAlphaNumeric(value[len(value)-1]) {
		return false
	}
	for i := 1; i < len(value)-1; i++ {
		if !isLowerAlphaNumeric(value[i]) && value[i] != '-' {
			return false
		}
	}
	return true
}

func validHoneytokenType(value string) bool {
	if len(value) == 0 || len(value) > 256 {
		return false
	}
	if value == "Opaque" {
		return true
	}
	if strings.Count(value, "/") != 1 {
		return false
	}
	parts := strings.SplitN(value, "/", 2)
	return validTokenName(parts[0]) && validDNSLabel(parts[1])
}

func validSecretDataKey(value string) bool {
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	for i := 0; i < len(value); i++ {
		char := value[i]
		if !isLowerAlphaNumeric(char) && !(char >= 'A' && char <= 'Z') && char != '-' && char != '_' && char != '.' {
			return false
		}
	}
	return true
}

func validateLogging(cfg model.LoggingConfig) error {
	if cfg.Format != "json" && cfg.Format != "text" {
		return fmt.Errorf("logging format must be json or text")
	}
	if len(cfg.TrustedProxyCIDRs) > maxTrustedProxyCIDRs {
		return fmt.Errorf("logging trusted_proxy_cidrs may contain at most %d entries", maxTrustedProxyCIDRs)
	}
	seen := make(map[string]struct{}, len(cfg.TrustedProxyCIDRs))
	for i, cidr := range cfg.TrustedProxyCIDRs {
		if len(cidr) > maxTrustedProxyCIDRBytes {
			return fmt.Errorf("logging trusted_proxy_cidrs entry %d exceeds the %d-byte limit", i+1, maxTrustedProxyCIDRBytes)
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid logging trusted_proxy_cidrs entry %d: expected a CIDR", i+1)
		}
		if _, exists := seen[cidr]; exists {
			return fmt.Errorf("duplicate logging trusted_proxy_cidrs entry %d", i+1)
		}
		seen[cidr] = struct{}{}
	}
	return nil
}

// validateSinks checks each configured log destination. URLs must be explicit
// http(s) endpoints with credentials supplied through dedicated fields so
// nothing sensitive is embedded in, or leaked through, a parsed URL.
func validateSinks(sinks []model.LogSinkConfig) error {
	if len(sinks) > maxSinkCount {
		return fmt.Errorf("logging sinks may contain at most %d entries", maxSinkCount)
	}
	for i, sink := range sinks {
		if len(sink.Token) > maxSinkCredentialBytes || len(sink.Password) > maxSinkCredentialBytes {
			return fmt.Errorf("invalid logging sinks entry %d: credentials exceed the %d-byte limit", i+1, maxSinkCredentialBytes)
		}
		if len(sink.Username) > maxSinkFieldBytes || len(sink.Source) > maxSinkFieldBytes || len(sink.Sourcetype) > maxSinkFieldBytes {
			return fmt.Errorf("invalid logging sinks entry %d: fields exceed the %d-byte limit", i+1, maxSinkFieldBytes)
		}
		if err := validateSinkHeaders(sink.Headers); err != nil {
			return fmt.Errorf("invalid logging sinks entry %d: %w", i+1, err)
		}
		switch sink.Type {
		case "file":
			if sink.Path == "" || len(sink.Path) > maxSinkPathBytes || strings.ContainsRune(sink.Path, 0) {
				return fmt.Errorf("invalid logging sinks entry %d: file sinks require a path of at most %d bytes", i+1, maxSinkPathBytes)
			}
		case "splunk", "elasticsearch", "elk", "http":
			if err := validateSinkURL(sink.URL); err != nil {
				return fmt.Errorf("invalid logging sinks entry %d: %w", i+1, err)
			}
		default:
			return fmt.Errorf("invalid logging sinks entry %d: unknown type %q: choose file, splunk, elasticsearch, or http", i+1, sink.Type)
		}
		if (sink.Type == "elasticsearch" || sink.Type == "elk") && !validSinkIndex(sink.Index) {
			return fmt.Errorf("invalid logging sinks entry %d: elasticsearch sinks require a valid index name", i+1)
		}
	}
	return nil
}

func validateSinkURL(raw string) error {
	if raw == "" || len(raw) > maxSinkURLBytes {
		return fmt.Errorf("sink url is required and may be at most %d bytes", maxSinkURLBytes)
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("sink url must be an absolute URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("sink url scheme must be http or https")
	}
	if parsed.User != nil {
		return fmt.Errorf("sink url must not embed credentials: use token, username, or password fields")
	}
	if parsed.Fragment != "" {
		return fmt.Errorf("sink url must not contain a fragment")
	}
	return nil
}

func validSinkIndex(value string) bool {
	if len(value) == 0 || len(value) > maxSinkIndexBytes || strings.ToLower(value) != value {
		return false
	}
	if strings.ContainsAny(value, `\/ *?"<>|,#:`) {
		return false
	}
	if value == "." || value == ".." || value[0] == '-' || value[0] == '_' || value[0] == '+' || value[0] == '.' {
		return false
	}
	return true
}

func validateSinkHeaders(headers map[string]string) error {
	if len(headers) > maxSinkHeaders {
		return fmt.Errorf("sink headers may contain at most %d entries", maxSinkHeaders)
	}
	for name, value := range headers {
		if !validSinkHeaderName(name) || len(name) > maxSinkHeaderNameBytes {
			return fmt.Errorf("sink headers contain an invalid name")
		}
		if len(value) > maxSinkHeaderValueBytes || strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("sink headers contain an invalid value for %q", name)
		}
	}
	return nil
}

func validSinkHeaderName(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		char := value[i]
		ok := isLowerAlphaNumeric(char) ||
			char >= 'A' && char <= 'Z' ||
			strings.ContainsRune("!#$%&'*+-.^_`|~", rune(char))
		if !ok {
			return false
		}
	}
	return true
}

func validateKubernetesProfile(cfg model.K8SConfig) error {
	const currentMinor = 37
	version := strings.TrimPrefix(cfg.APIVersion, "v1.")
	minor, err := strconv.Atoi(version)
	if !strings.HasPrefix(cfg.APIVersion, "v1.") || err != nil || minor < 19 || minor > currentMinor || strconv.Itoa(minor) != version {
		return fmt.Errorf("invalid Kubernetes profile %q: supported simulated profiles are v1.19 through v1.%d", cfg.APIVersion, currentMinor)
	}
	ip := net.ParseIP(cfg.IPBase)
	if ip == nil || ip.To4() == nil || !ip.IsPrivate() {
		return fmt.Errorf("invalid Kubernetes pod network base %q: use an RFC 1918 IPv4 address", cfg.IPBase)
	}
	return nil
}

func validateHost(host string) error {
	if net.ParseIP(host) == nil {
		return fmt.Errorf("must be an IPv4 or IPv6 literal (hostnames are not resolved)")
	}
	return nil
}

func validatePort(port string) error {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return fmt.Errorf("must be a decimal port from 1 through 65535")
	}
	return nil
}
