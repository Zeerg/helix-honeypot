package server

import (
	"context"
	"fmt"

	"helix-honeypot/config"
	"helix-honeypot/honeypots/docker"
	httpMode "helix-honeypot/honeypots/http"
	"helix-honeypot/honeypots/k8s"
	"helix-honeypot/honeypots/kubelet"
	"helix-honeypot/honeypots/redis"
	"helix-honeypot/honeypots/tcp"
	"helix-honeypot/honeypots/udp"
)

// StartHoneypot loads and validates configuration, then runs exactly one
// supported honeypot mode until it returns or ctx is cancelled.
func StartHoneypot(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("start honeypot: context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	cfg, err := config.NewConfig("")
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	switch cfg.RunMode.RunMode {
	case "redis":
		err = redis.StartRedisHoneypot(ctx, cfg)
	case "docker":
		err = docker.StartDockerHoneypot(ctx, cfg)
	case "k8s":
		err = k8s.StartK8SHoneypot(ctx, cfg)
	case "http":
		err = httpMode.StartHTTPHoneypot(ctx, cfg)
	case "tcp":
		err = tcp.StartTCPHoneypot(ctx, cfg)
	case "udp":
		err = udp.StartUDPHoneypot(ctx, cfg)
	case "kubelet":
		err = kubelet.StartKubeletHoneypot(ctx, cfg)
	default:
		// Validate also protects callers constructing a configuration through a
		// different path, keeping the dispatcher closed over supported modes.
		return fmt.Errorf("unsupported run mode %q", cfg.RunMode.RunMode)
	}
	if err != nil {
		return fmt.Errorf("%s honeypot: %w", cfg.RunMode.RunMode, err)
	}
	return nil
}
