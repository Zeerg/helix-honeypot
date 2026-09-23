package handler

import (
	"encoding/base64"
	"testing"

	"helix-honeypot/config"
	"helix-honeypot/model"
)

func TestNewAPISeedsConfiguredNamespacesAndHoneytokens(t *testing.T) {
	cfg := config.Defaults()
	cfg.K8S.Namespaces = []string{"payments"}
	cfg.K8S.Honeytokens = []model.K8SHoneytoken{{
		Name:      "cloud-access",
		Namespace: "payments",
		Data:      map[string]string{"token": "synthetic-value"},
	}}

	api, err := NewAPI(&cfg)
	if err != nil {
		t.Fatalf("NewAPI() error = %v", err)
	}
	if _, exists := api.store.get(objectKey{group: "", version: "v1", resource: "namespaces", name: "payments"}); !exists {
		t.Fatal("configured Namespace was not seeded")
	}
	secret, exists := api.store.get(objectKey{group: "", version: "v1", resource: "secrets", namespace: "payments", name: "cloud-access"})
	if !exists {
		t.Fatal("configured honeytoken Secret was not seeded")
	}
	if secret["type"] != "Opaque" {
		t.Fatalf("Secret type = %#v, want Opaque", secret["type"])
	}
	data, ok := secret["data"].(map[string]any)
	if !ok || data["token"] != base64.StdEncoding.EncodeToString([]byte("synthetic-value")) {
		t.Fatalf("Secret data = %#v, want base64-encoded synthetic value", secret["data"])
	}
}
