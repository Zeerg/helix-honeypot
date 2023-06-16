package router

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
)

func New() *echo.Echo {
	echoRouter := echo.New()
	echoRouter.Logger.SetLevel(log.DEBUG)
	echoRouter.HideBanner = true
	return echoRouter
}
