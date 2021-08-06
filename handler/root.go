package handler

import (
	"github.com/labstack/echo/v4"
	"net/http"
)

// Root Route Handler
func RootHandler(c echo.Context) error {
	return c.String(http.StatusOK, "Root Route")
}