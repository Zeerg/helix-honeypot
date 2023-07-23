package http

import (
	"github.com/labstack/echo/v4"
	"helix-honeypot/model"
	"helix-honeypot/logger"
	"net/http"
)

func StartHTTPHoneypot(cfg *model.Config) {
	e := NewRouter()

	// Initialize logger
	customLogger, err := logger.NewCustomLogger(cfg)
	if err != nil {
		e.Logger.Fatal(err)
		return
	}

	// Set the logger middleware
	e.Use(customLogger.Middleware)

	e.GET("/*", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	e.Logger.Fatal(e.Start(cfg.HTTP.Host + ":" + cfg.HTTP.Port))
}
