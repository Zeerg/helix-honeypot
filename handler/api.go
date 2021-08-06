package handler

import (
	"github.com/labstack/echo/v4"
	"net/http"
)

// Basic API Handler
func ApiHandler(c echo.Context) error {
	return c.String(http.StatusOK, "Pod Route")
}