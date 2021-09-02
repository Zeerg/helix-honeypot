package main

import (
  "github.com/labstack/echo/v4/middleware"
  "github.com/zeerg/helix-honeypot/router"
  "github.com/zeerg/helix-honeypot/handler"
  "flag"
  "fmt"
  "os"
)

func main() {
  // Get the run mode
  var runMode string
  flag.StringVar(&runMode, "mode", "api", "The run mode for the honeypot [api, ad]")
  flag.Parse()

  if len(runMode) == 0 {
    fmt.Println("Usage:")
    flag.PrintDefaults()
    os.Exit(1)
}


  // Echo instance
  e := router.New()

  // Middleware
  e.Use(middleware.Logger())
  e.Use(middleware.Recover())



  // Routes for basic k8s operations and api calls to info endpoints
  e.GET("/", handler.RootHandler)
  e.GET("/openapi/v2", handler.OpenApiHandler)
  e.GET("/api/v1", handler.ApiResourceList)
  e.GET("/api", handler.ApiHandler)
  e.GET("/apis", handler.ApiGroupList)
  e.GET("/apis/:service/:version", handler.ServiceHandler)
  e.GET("/apis/apps/v1/namespaces/:namespace/:workload/:app", handler.ResourceHandler)
  // Routes for Typical API Mode
  if runMode == "api" {
    e.GET("/apis/apps/v1/namespaces/:namespace/:workload", handler.PodsHandler)
    e.GET("/api/v1/namespaces/:namespace/:resource", handler.PodsHandler)
    e.GET("/apis/extensions/v1beta1/namespaces/:namespace/:resource", handler.PodsHandler)
    e.GET("/api/v1/:service", handler.PodsHandler)
    e.POST("/api*", handler.PostHandler)
    
  }
  // Routes for Active Defense Mode
  if runMode == "ad" {
    e.GET("/apis/apps/v1/namespaces/:namespace/:workload", handler.AdGetHandler)
    e.GET("/api/v1/namespaces/:namespace/:resource", handler.AdGetHandler)
    e.GET("/apis/extensions/v1beta1/namespaces/:namespace/:resource", handler.AdGetHandler)
    e.GET("/api/v1/:service", handler.AdGetHandler)
    e.POST("/api*", handler.AdPostHandler)
  }
 

 

  // Start server
  e.Logger.Fatal(e.Start(":8000"))
}
