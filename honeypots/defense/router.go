package defense

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
)

func NewRouter() *echo.Echo {
	echoRouter := echo.New()
	echoRouter.Logger.SetLevel(log.DEBUG)
	echoRouter.HideBanner = true
	return echoRouter
}