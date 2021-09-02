package handler

import (
	"github.com/labstack/echo/v4"
	"os"
)
// Literally streams /dev/random to the response since Kubectl has no input validation or timeouts lol
func ActiveDefenseHandler(c echo.Context) error {
	devRandom, _ := os.Open("/dev/random")
	return c.Stream(201, "application/json", devRandom)
}