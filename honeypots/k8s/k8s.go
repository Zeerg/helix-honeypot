package k8s

import (
	
	"github.com/labstack/echo/v4/middleware"

	"helix-honeypot/model"
	"helix-honeypot/logger"
	"helix-honeypot/honeypots/k8s/router"
	"helix-honeypot/honeypots/k8s/routes"
	"helix-honeypot/honeypots/k8s/handler"
)

func StartK8SHoneypot(cfg *model.Config) {

	// Initialize Echo instance with middleware
	e := router.New()
	
	// Initialize K8s Configs
	handler.Initialize(cfg)

	// Initialize logger
	customLogger, err := logger.NewCustomLogger(cfg)
	if err != nil {
		e.Logger.Fatal(err)
		return
	}

	
	// Set the logger middleware
	e.Use(customLogger.Middleware)

	e.Use(middleware.Recover())
	routes.DefineRoutes(e, cfg)
	// Define server information and start the server

	e.Logger.Fatal(e.Start(cfg.K8S.Host + ":" + cfg.K8S.Port))
}
