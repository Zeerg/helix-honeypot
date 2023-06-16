package handler

import (
	"github.com/labstack/echo/v4"
	"os"
)

// Literally streams /dev/urandom to the response since Kubectl has no input validation or timeouts lol
func ActiveDefenseHandler(c echo.Context) error {
	devUrandom, _ := os.Open("/dev/urandom")
	return c.Stream(201, "application/json", devUrandom)
}
