package handler

import (
	"github.com/labstack/echo/v4"
	"net/http"
)
//Pods Handler
func PodsHandler(c echo.Context) error {
	return c.String(http.StatusOK, "Pod Route")
}
