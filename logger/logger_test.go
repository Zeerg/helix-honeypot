package logger

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"net/netip"

	"helix-honeypot/model"
)

func TestClientAddrFromXFFRequiresTrustedPeerAndWalksFromRight(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}

	got := clientAddrFromXFF("10.0.0.4:8443", []string{"203.0.113.99, 198.51.100.25, 10.0.0.3"}, trusted)
	if got != "198.51.100.25" {
		t.Fatalf("trusted client address = %q, want 198.51.100.25", got)
	}

	got = clientAddrFromXFF("198.51.100.7:8443", []string{"203.0.113.99"}, trusted)
	if got != "" {
		t.Fatalf("untrusted peer client address = %q, want empty", got)
	}

	got = clientAddrFromXFF("10.0.0.4:8443", []string{"203.0.113.99, not-an-ip"}, trusted)
	if got != "" {
		t.Fatalf("malformed forwarded chain client address = %q, want empty", got)
	}
}

func TestWriteDefaultsToPrivacySafeJSON(t *testing.T) {
	var output bytes.Buffer
	NewEventLogger(&output).Write(model.Event{
		Sensor:     "http",
		RemoteAddr: "127.0.0.1:12345",
		ClientAddr: "203.0.113.8",
		Path:       "/api/v1/secrets/private-token-value",
		UserAgent:  "token=private-value",
	})

	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		t.Fatalf("event is not JSON: %v", err)
	}
	if _, exists := event["client_addr"]; exists {
		t.Fatalf("caller-supplied client_addr was trusted: %#v", event)
	}
	if _, exists := event["user_agent"]; exists {
		t.Fatalf("user_agent was included by default: %#v", event)
	}
	if path, _ := event["path"].(string); strings.Contains(path, "private-token-value") {
		t.Fatalf("secret-like path segment was not redacted: %q", path)
	}
}

func TestTextFormatIncludesConfiguredClientAddress(t *testing.T) {
	var output bytes.Buffer
	logger := NewEventLoggerWithConfig(&output, model.LoggingConfig{Format: "text"})
	logger.write(model.Event{Sensor: "http", RemoteAddr: "10.0.0.4:1234", Method: "GET", Path: "/readyz"}, "198.51.100.10")

	line := output.String()
	if !strings.Contains(line, `client_addr="198.51.100.10"`) || !strings.Contains(line, `sensor="http"`) {
		t.Fatalf("text event missing structured fields: %q", line)
	}
}

func TestConfiguredHoneytokenValuesAreRedactedFromLoggedFields(t *testing.T) {
	const secret = "synthetic-only-placeholder"
	var output bytes.Buffer
	logger := NewEventLoggerWithConfig(
		&output,
		model.LoggingConfig{IncludeUserAgent: true},
		secret,
	)
	for _, userAgent := range []string{
		"scanner/" + secret,
		"scanner/" + base64.StdEncoding.EncodeToString([]byte(secret)),
		"scanner/synthetic%2Donly%2Dplaceholder",
		"scanner/synthetic%252Donly%252Dplaceholder",
		"scanner/synthetic%2donly-placeholder",
	} {
		output.Reset()
		logger.Write(model.Event{
			Sensor:    "http",
			Method:    secret,
			Path:      "/capture/" + secret,
			UserAgent: userAgent,
		})

		var event model.Event
		if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
			t.Fatalf("event is not JSON: %v", err)
		}
		if strings.Contains(output.String(), secret) || event.Method != "[redacted]" || event.UserAgent != "[redacted]" {
			t.Fatalf("configured honeytoken leaked for user-agent %q: %s", userAgent, output.String())
		}
	}
}

func TestLongConfiguredHoneytokenIsRedactedBeforeUserAgentTruncation(t *testing.T) {
	secret := strings.Repeat("x", 600)
	var output bytes.Buffer
	logger := NewEventLoggerWithConfig(
		&output,
		model.LoggingConfig{IncludeUserAgent: true},
		secret,
	)
	logger.Write(model.Event{
		Sensor:    "http",
		Method:    "scanner/" + secret,
		UserAgent: "scanner/" + secret,
	})

	var event model.Event
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		t.Fatalf("event is not JSON: %v", err)
	}
	if strings.Contains(output.String(), secret[:32]) || event.Method != "[redacted]" || event.UserAgent != "[redacted]" {
		t.Fatalf("long configured honeytoken leaked as a prefix: %s", output.String())
	}
}

func TestConfiguredHoneytokenWithControlCharacterIsRedacted(t *testing.T) {
	const secret = "top\tsecret"
	var output bytes.Buffer
	logger := NewEventLoggerWithConfig(
		&output,
		model.LoggingConfig{IncludeUserAgent: true},
		secret,
	)
	logger.Write(model.Event{
		Sensor:    "http",
		UserAgent: "scanner/" + secret,
	})

	var event model.Event
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		t.Fatalf("event is not JSON: %v", err)
	}
	if strings.Contains(output.String(), "top secret") || event.UserAgent != "[redacted]" {
		t.Fatalf("control-character honeytoken leaked after normalization: %s", output.String())
	}
}
