package main

import (
  "net/http"
  "github.com/labstack/echo/v4"
  "github.com/labstack/echo/v4/middleware"
)

func main() {
  // Echo instance
  e := echo.New()

  // Middleware
  e.Use(middleware.Logger())
  e.Use(middleware.Recover())

  // Routes
  e.GET("/", rootHandler)
  e.get("/api/v1", apiHandler)
  e.GET("/openapi/v2", openApiHandler)
  e.GET("/api/v1/namespaces/:namespace/pods", podsHandler)

  // Start server
  e.Logger.Fatal(e.Start(":8000"))
}

// Handlers
func rootHandler(c echo.Context) error {
	return c.String(http.StatusOK, "Root Route")
}
func openApiHandler(c echo.Context) error {
	return c.String(http.StatusOK, "Api Route")
}
func podsHandler(c echo.Context) error {
	return c.String(http.StatusOK, "Pod Route")
}
func apiHandler(c echo.Context) error {
	return c.String(http.StatusOK, "Pod Route")
}