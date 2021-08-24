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

  // Routes for basic k8s operations
  e.GET("/", handler.RootHandler)
  e.GET("/openapi/v2", handler.OpenApiHandler)
  e.GET("/api/v1", handler.ApiResourceList)
  e.GET("/api", handler.ApiHandler)
  e.GET("/apis", handler.ApiGroupList)
  e.GET("/apis/apps/v1/namespaces/:namespace/:workload", handler.PodsHandler)
  e.GET("/apis/apps/v1/namespaces/:namespace/:workload/:app", handler.ResourceHandler)
  e.GET("/apis/:service/:version", handler.ServiceHandler)
  e.GET("/api/v1/namespaces/:namespace/:resource", handler.PodsHandler)
  e.GET("/apis/extensions/v1beta1/namespaces/:namespace/:resource", handler.PodsHandler)
  e.GET("/api/v1/:service", handler.PodsHandler)
  e.POST("/api*", handler.PostHandler)

 

  // Start server
  e.Logger.Fatal(e.Start(":8000"))
}
