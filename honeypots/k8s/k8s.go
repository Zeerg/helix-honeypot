package k8s

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/labstack/echo/v5"

	"helix-honeypot/honeypots/k8s/handler"
	"helix-honeypot/honeypots/k8s/router"
	"helix-honeypot/internal/netlimit"
	"helix-honeypot/logger"
	"helix-honeypot/model"
)

const maxHTTPBodyBytes = 64 << 10

// StartK8SHoneypot runs an isolated, in-memory Kubernetes-shaped API server.
// It never connects to or mutates a real cluster.
func StartK8SHoneypot(ctx context.Context, cfg *model.Config) error {
	if cfg == nil {
		return fmt.Errorf("Kubernetes configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	api, err := handler.NewAPI(cfg)
	if err != nil {
		return err
	}
	address, err := listenAddress(cfg.K8S.Host, cfg.K8S.Port)
	if err != nil {
		return err
	}
	baseListener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen for Kubernetes honeypot API: %w", err)
	}
	cappedListener, err := netlimit.NewCappedListener(baseListener, 64)
	if err != nil {
		baseListener.Close()
		return fmt.Errorf("cap Kubernetes honeypot connections: %w", err)
	}
	defer cappedListener.Close()

	e := router.New()
	e.Use(recoverPanics)
	e.Use(limitRequestBody)
	events, err := logger.NewEventLoggerFromConfig(os.Stdout, cfg)
	if err != nil {
		return fmt.Errorf("configure event sinks: %w", err)
	}
	defer events.Close()
	e.Use(events.HTTPMiddleware("kubernetes"))
	e.Any("/", api.ServeHTTP)
	e.Any("/*", api.ServeHTTP)

	start := echo.StartConfig{
		Listener:        cappedListener,
		HideBanner:      true,
		HidePort:        true,
		GracefulTimeout: 5 * time.Second,
		BeforeServeFunc: func(server *http.Server) error {
			server.ReadHeaderTimeout = 5 * time.Second
			server.ReadTimeout = 10 * time.Second
			server.IdleTimeout = 60 * time.Second
			server.MaxHeaderBytes = 16 << 10
			return nil
		},
	}
	if err := start.Start(ctx, e); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("start Kubernetes honeypot API: %w", err)
	}
	return nil
}

func listenAddress(host, port string) (string, error) {
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	if port == "" {
		return "", fmt.Errorf("Kubernetes API port is required")
	}
	if strings.Contains(port, ":") || strings.Contains(port, "/") {
		return "", fmt.Errorf("invalid Kubernetes API port %q", port)
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), port), nil
}

func limitRequestBody(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		if c.Request().Body != nil {
			c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, maxHTTPBodyBytes)
		}
		return next(c)
	}
}

func recoverPanics(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) (err error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				err = c.JSON(http.StatusInternalServerError, map[string]any{
					"apiVersion": "v1", "kind": "Status", "status": "Failure",
					"message": "the simulated API server encountered an internal error",
					"reason":  "InternalError", "code": http.StatusInternalServerError,
				})
			}
		}()
		return next(c)
	}
}
