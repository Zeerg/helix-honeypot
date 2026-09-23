package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"helix-honeypot/model"
)

func TestNewConfigLoadsStructuredHoneytokensAndLogging(t *testing.T) {
	clearConfigEnvironment(t)
	filename := filepath.Join(t.TempDir(), "config.toml")
	content := `[run_mode]
mode = "k8s"

[k8s]
namespaces = ["payments"]

[[k8s.honeytokens]]
name = "cloud-access"
namespace = "payments"
data = { token = "synthetic-value" }

[logging]
format = "text"
include_user_agent = true
trusted_proxy_cidrs = ["192.0.2.0/24"]
`
	if err := os.WriteFile(filename, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := NewConfig(filename)
	if err != nil {
		t.Fatalf("NewConfig() error = %v", err)
	}
	if len(cfg.K8S.Namespaces) != 1 || cfg.K8S.Namespaces[0] != "payments" {
		t.Fatalf("namespaces = %#v, want [payments]", cfg.K8S.Namespaces)
	}
	if len(cfg.K8S.Honeytokens) != 1 {
		t.Fatalf("honeytokens count = %d, want 1", len(cfg.K8S.Honeytokens))
	}
	honeytoken := cfg.K8S.Honeytokens[0]
	if honeytoken.Name != "cloud-access" || honeytoken.Namespace != "payments" || honeytoken.Type != "Opaque" || honeytoken.Data["token"] != "synthetic-value" {
		t.Fatalf("honeytoken = %#v, unexpected parsed value", honeytoken)
	}
	if cfg.Logging.Format != "text" || !cfg.Logging.IncludeUserAgent || len(cfg.Logging.TrustedProxyCIDRs) != 1 {
		t.Fatalf("logging config = %#v, unexpected parsed value", cfg.Logging)
	}
}

func TestNewConfigDoesNotEchoMalformedSecretConfig(t *testing.T) {
	clearConfigEnvironment(t)
	filename := filepath.Join(t.TempDir(), "config.toml")
	secret := "synthetic-secret-must-not-appear"
	content := "[k8s]\ntoken_values = [\"" + secret + "\"\n"
	if err := os.WriteFile(filename, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := NewConfig(filename)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("NewConfig() error = %v, want sanitized parse error", err)
	}
}

func TestValidateRejectsUnconfiguredHoneytokenNamespace(t *testing.T) {
	cfg := Defaults()
	cfg.K8S.Namespaces = []string{"payments"}
	cfg.K8S.Honeytokens = []model.K8SHoneytoken{{
		Name:      "cloud-access",
		Namespace: "production",
		Data:      map[string]string{"token": "synthetic-value"},
	}}
	if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "namespace") {
		t.Fatalf("Validate() error = %v, want unconfigured namespace error", err)
	}
}

func TestNewConfigLoadsLogSinks(t *testing.T) {
	clearConfigEnvironment(t)
	filename := filepath.Join(t.TempDir(), "config.toml")
	content := `[logging]
[[logging.sinks]]
type = "splunk"
url = "https://splunk.example.internal:8088"
token = "synthetic-hec-token"
index = "honeypot"

[[logging.sinks]]
type = "elasticsearch"
url = "https://es.example.internal:9200"
index = "honeypot-events"
`
	if err := os.WriteFile(filename, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := NewConfig(filename)
	if err != nil {
		t.Fatalf("NewConfig() error = %v", err)
	}
	if len(cfg.Logging.Sinks) != 2 || cfg.Logging.Sinks[0].Type != "splunk" || cfg.Logging.Sinks[1].Index != "honeypot-events" {
		t.Fatalf("sinks = %#v, unexpected parsed value", cfg.Logging.Sinks)
	}
}

func TestNewConfigLoadsSinksFromEnvironment(t *testing.T) {
	clearConfigEnvironment(t)
	filename := filepath.Join(t.TempDir(), "missing.toml")
	t.Setenv("HELIX_SPLUNK_URL", "https://splunk.example.internal:8088")
	t.Setenv("HELIX_SPLUNK_TOKEN", "synthetic-hec-token")
	t.Setenv("HELIX_ELASTICSEARCH_URL", "https://es.example.internal:9200")
	t.Setenv("HELIX_ELASTICSEARCH_INDEX", "honeypot-events")
	t.Setenv("HELIX_HTTP_SINK_URL", "https://collector.example.internal/events")
	t.Setenv("HELIX_LOG_FILE", "/tmp/events.jsonl")

	cfg, err := NewConfig(filename)
	if err != nil {
		t.Fatalf("NewConfig() error = %v", err)
	}
	if len(cfg.Logging.Sinks) != 4 {
		t.Fatalf("sinks = %#v, want 4 env-defined sinks", cfg.Logging.Sinks)
	}
	types := map[string]model.LogSinkConfig{}
	for _, sink := range cfg.Logging.Sinks {
		types[sink.Type] = sink
	}
	if types["file"].Path != "/tmp/events.jsonl" ||
		types["splunk"].Token != "synthetic-hec-token" ||
		types["elasticsearch"].Index != "honeypot-events" ||
		types["http"].URL != "https://collector.example.internal/events" {
		t.Fatalf("sinks = %#v, unexpected env-derived values", cfg.Logging.Sinks)
	}
}

func TestNewConfigLoadsHoneytokensFromEnvironment(t *testing.T) {
	clearConfigEnvironment(t)
	filename := filepath.Join(t.TempDir(), "missing.toml")
	t.Setenv("HELIX_K8S_NAMESPACES", "payments,monitoring")
	t.Setenv("HELIX_K8S_HONEYTOKENS", "api-token@payments:token=synthetic-one,user=admin;db-creds:password=synthetic-two")

	cfg, err := NewConfig(filename)
	if err != nil {
		t.Fatalf("NewConfig() error = %v", err)
	}
	if len(cfg.K8S.Honeytokens) != 2 {
		t.Fatalf("honeytokens = %#v, want 2 env-defined entries", cfg.K8S.Honeytokens)
	}
	first, second := cfg.K8S.Honeytokens[0], cfg.K8S.Honeytokens[1]
	if first.Name != "api-token" || first.Namespace != "payments" || first.Data["token"] != "synthetic-one" || first.Data["user"] != "admin" {
		t.Fatalf("first honeytoken = %#v, unexpected parsed value", first)
	}
	if second.Name != "db-creds" || second.Namespace != "" || second.Data["password"] != "synthetic-two" {
		t.Fatalf("second honeytoken = %#v, want default namespace and parsed data", second)
	}
}

func TestNewConfigRejectsMalformedEnvHoneytokens(t *testing.T) {
	for name, value := range map[string]string{
		"missing data":       "api-token@payments",
		"missing key":        "api-token:=value",
		"empty entry only":   ";;;",
		"duplicate data key": "api-token:token=a,token=b",
	} {
		clearConfigEnvironment(t)
		t.Setenv("HELIX_K8S_HONEYTOKENS", value)
		filename := filepath.Join(t.TempDir(), "missing.toml")
		if _, err := NewConfig(filename); err == nil {
			t.Fatalf("NewConfig() accepted malformed HELIX_K8S_HONEYTOKENS %q", name)
		}
	}
}

func TestEnvHoneytokenErrorDoesNotEchoSecretValues(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("HELIX_K8S_HONEYTOKENS", "api-token:token=synthetic-must-not-appear")
	filename := filepath.Join(t.TempDir(), "missing.toml")
	// Force a parse failure after the secret value by using a malformed pair.
	t.Setenv("HELIX_K8S_HONEYTOKENS", "api-token:token=synthetic-must-not-appear,badpair")
	_, err := NewConfig(filename)
	if err == nil || strings.Contains(err.Error(), "synthetic-must-not-appear") {
		t.Fatalf("NewConfig() error = %v, want sanitized parse error", err)
	}
}

func TestNewConfigRejectsInvalidEnvSink(t *testing.T) {
	clearConfigEnvironment(t)
	filename := filepath.Join(t.TempDir(), "missing.toml")
	t.Setenv("HELIX_SPLUNK_URL", "ftp://splunk.example.internal")

	if _, err := NewConfig(filename); err == nil {
		t.Fatal("NewConfig() accepted an env-defined sink with a non-http scheme")
	}
}

func TestValidateRejectsInvalidLogSinks(t *testing.T) {
	cases := map[string]model.LogSinkConfig{
		"unknown type":      {Type: "carrier-pigeon"},
		"non-http scheme":   {Type: "splunk", URL: "ftp://splunk.example.internal"},
		"credential in url": {Type: "http", URL: "https://user:pass@collector.example.internal"},
		"missing index":     {Type: "elasticsearch", URL: "https://es.example.internal"},
		"uppercase index":   {Type: "elasticsearch", URL: "https://es.example.internal", Index: "Honeypot"},
		"missing file path": {Type: "file"},
		"oversized header":  {Type: "http", URL: "https://collector.example.internal", Headers: map[string]string{"X-Key": strings.Repeat("v", 2049)}},
	}
	for name, sink := range cases {
		cfg := Defaults()
		cfg.Logging.Sinks = []model.LogSinkConfig{sink}
		if err := Validate(&cfg); err == nil {
			t.Fatalf("Validate() accepted %s sink %#v", name, sink)
		}
	}
}

func TestValidateRejectsTooManyLogSinks(t *testing.T) {
	cfg := Defaults()
	for i := 0; i < 9; i++ {
		cfg.Logging.Sinks = append(cfg.Logging.Sinks, model.LogSinkConfig{Type: "file", Path: "/tmp/events.jsonl"})
	}
	if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "sinks") {
		t.Fatalf("Validate() error = %v, want sink count error", err)
	}
}

func TestSinkCredentialsJoinSensitiveValues(t *testing.T) {
	cfg := Defaults()
	cfg.Logging.Sinks = []model.LogSinkConfig{{
		Type:     "splunk",
		URL:      "https://splunk.example.internal",
		Token:    "synthetic-sink-token",
		Password: "synthetic-sink-password",
		Headers:  map[string]string{"Authorization": "synthetic-header-secret"},
	}}
	values := cfg.SensitiveValues()
	for _, want := range []string{"synthetic-sink-token", "synthetic-sink-password", "synthetic-header-secret"} {
		found := false
		for _, value := range values {
			if value == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("SensitiveValues() missing %q in %#v", want, values)
		}
	}
}

func clearConfigEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"RUN_MODE", "HELIX_RUN_MODE", "K8SAPI_VERSION", "HELIX_K8S_API_VERSION",
		"IP_BASE", "HELIX_K8S_IP_BASE", "K8S_HOST", "HELIX_K8S_HOST", "K8S_PORT", "HELIX_K8S_PORT",
		"GENERATE_KUBE_SYSTEM", "HELIX_K8S_GENERATE_KUBE_SYSTEM", "GENERATE_RANDOMNESS", "HELIX_K8S_GENERATE_RANDOMNESS",
		"HELIX_K8S_TOKEN_NAMES", "HELIX_K8S_TOKEN_VALUES", "HELIX_K8S_NAMESPACES", "HELIX_K8S_HONEYTOKENS",
		"HELIX_HTTP_HOST", "HELIX_HTTP_PORT", "HELIX_TCP_HOST", "HELIX_TCP_PORT", "HELIX_UDP_HOST", "HELIX_UDP_PORT",
		"HELIX_LOG_FORMAT", "HELIX_LOG_INCLUDE_USER_AGENT", "HELIX_LOG_TRUSTED_PROXY_CIDRS",
		"HELIX_LOG_FILE", "HELIX_SPLUNK_URL", "HELIX_SPLUNK_TOKEN", "HELIX_SPLUNK_INDEX",
		"HELIX_SPLUNK_SOURCE", "HELIX_SPLUNK_SOURCETYPE",
		"HELIX_ELASTICSEARCH_URL", "HELIX_ELK_URL", "HELIX_ELASTICSEARCH_INDEX",
		"HELIX_ELASTICSEARCH_TOKEN", "HELIX_ELASTICSEARCH_USERNAME", "HELIX_ELASTICSEARCH_PASSWORD",
		"HELIX_HTTP_SINK_URL", "HELIX_HTTP_SINK_TOKEN", "HELIX_HTTP_SINK_HEADERS",
	} {
		t.Setenv(key, "")
	}
}
