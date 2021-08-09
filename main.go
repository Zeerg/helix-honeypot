package main

import (
  "github.com/labstack/echo/v4/middleware"
  "github.com/zeerg/helix-honeypot/router"
  "github.com/zeerg/helix-honeypot/handler"
)

func main() {
  // Echo instance
  e := router.New()

  // Middleware
  e.Use(middleware.Logger())
  e.Use(middleware.Recover())

  // Routes
  e.GET("/", handler.RootHandler)

  e.GET("/api/v1", handler.ApiResourceList)
  e.GET("/api", handler.ApiHandler)
  e.GET("/apis", handler.ApiGroupList)
  e.GET("/apis/:service/:version", handler.ServiceHandler)
  e.GET("/openapi/v2", handler.OpenApiHandler)

  e.GET("/api/v1/namespaces/:namespace/:resource", handler.PodsHandler)

  e.POST("/api*", handler.PostHandler)

  // Start server
  e.Logger.Fatal(e.Start(":8000"))
}
