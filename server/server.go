package server

import (
	"log"

	"helix-honeypot/config"
	"helix-honeypot/honeypots/k8s"
	"helix-honeypot/honeypots/defense"
	"helix-honeypot/honeypots/udp"
	"helix-honeypot/honeypots/tcp"
	"helix-honeypot/honeypots/http"
)

// StartServer starts the honeypot server.
func StartHoneypot() error {
	// Initialize Config
	cfg, err := config.NewConfig("./config.toml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Generate Machine ID
	machineId, err := config.MakeMachineId()
	if err != nil {
		log.Fatal("Failed to generate machine ID: ", err)
	}
	cfg.MachineID = machineId

	// Run the configured honeypot
	if cfg.RunMode.RunMode == "k8s" {
		k8s.StartK8SHoneypot(cfg)
	} else if cfg.RunMode.RunMode == "def" {
		defense.StartDefenseHoneypot(cfg)
	} else if cfg.RunMode.RunMode == "udp" {
		udp.StartUDPHoneypot(cfg)
	} else if cfg.RunMode.RunMode == "tcp" {
		tcp.StartTCPHoneypot(cfg)
	} else if cfg.RunMode.RunMode == "http" {
		http.StartHTTPHoneypot(cfg)
	}
	return err
}
