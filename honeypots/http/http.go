package http

import (
	"context"
	"errors"
	"fmt"
	"net"
	stdhttp "net/http"
	"time"

	"github.com/labstack/echo/v5"

	"helix-honeypot/internal/netlimit"
	"helix-honeypot/logger"
	"helix-honeypot/model"
)

const shutdownTimeout = 5 * time.Second

const maxHTTPConnections = 128

// StartHTTPHoneypot serves a small HTTP surface until ctx is cancelled.
func StartHTTPHoneypot(ctx context.Context, cfg *model.Config) error {
	if cfg == nil {
		return errors.New("HTTP honeypot requires configuration")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	e := NewRouter()
	events, err := logger.NewEventLoggerFromConfig(nil, cfg)
	if err != nil {
		return fmt.Errorf("configure event sinks: %w", err)
	}
	defer events.Close()
	e.Use(events.HTTPMiddleware("http"))
	handler := func(c *echo.Context) error {
		return c.String(stdhttp.StatusOK, "OK")
	}
	e.Any("/", handler)
	e.Any("/*", handler)

	addr := net.JoinHostPort(cfg.HTTP.Host, cfg.HTTP.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen HTTP honeypot: %w", err)
	}
	cappedListener, err := netlimit.NewCappedListener(listener, maxHTTPConnections)
	if err != nil {
		_ = listener.Close()
		return fmt.Errorf("cap HTTP honeypot listener: %w", err)
	}
	defer cappedListener.Close()

	start := echo.StartConfig{
		Address:         addr,
		Listener:        cappedListener,
		HideBanner:      true,
		HidePort:        true,
		GracefulTimeout: shutdownTimeout,
		BeforeServeFunc: func(server *stdhttp.Server) error {
			server.ReadHeaderTimeout = 5 * time.Second
			server.ReadTimeout = 5 * time.Second
			server.WriteTimeout = 10 * time.Second
			server.IdleTimeout = 60 * time.Second
			server.MaxHeaderBytes = 16 * 1024
			return nil
		},
	}
	if err := start.Start(ctx, e); err != nil && !errors.Is(err, stdhttp.ErrServerClosed) {
		return fmt.Errorf("serve HTTP honeypot: %w", err)
	}
	return nil
}
