package http

import (
	"io"
	"log/slog"
	"net/http"

	"github.com/labstack/echo/v5"
)

func NewRouter() *echo.Echo {
	echoRouter := echo.NewWithConfig(echo.Config{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		HTTPErrorHandler: func(c *echo.Context, err error) {
			response, unwrapErr := echo.UnwrapResponse(c.Response())
			if unwrapErr == nil && response.Committed {
				return
			}
			status := echo.StatusCode(err)
			if status < http.StatusBadRequest || status > 599 {
				status = http.StatusInternalServerError
			}
			_ = c.NoContent(status)
		},
	})
	return echoRouter
}
