package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"helix-honeypot/server"
)

func main() {
	if err := run(); err != nil {
		slog.Error("honeypot stopped with an error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := server.StartHoneypot(ctx); err != nil {
		if ctx.Err() != nil && errors.Is(err, context.Canceled) {
			return nil
		}
		return fmt.Errorf("run honeypot: %w", err)
	}
	return nil
}
