package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/labstack/echo/v4/middleware"
	"helix-honeypot/config"
	"helix-honeypot/generator"
	"helix-honeypot/handler"
	"helix-honeypot/router"
)

func writeKubeSystemConfigToFile(kubeSystemConfig map[string]interface{}) error {
	// Open a new file for writing only
	file, err := os.OpenFile(
		"kubeSystemConfig.json",            // path to the file
		os.O_WRONLY|os.O_TRUNC|os.O_CREATE, // open the file in write only mode, truncate it if it exists, or create it if it doesn't
		0755,
	)
	if err != nil {
		return err
	}
	defer file.Close()

	// Serialize the kubeSystemConfig map into JSON
	encoder := json.NewEncoder(file)
	return encoder.Encode(kubeSystemConfig)
}

func main() {
	// Define flags for run mode configuration
	var runMode string
	flag.StringVar(&runMode, "mode", "api", "The run mode for the honeypot [api, ad]")
	flag.Parse()

	// Validate run mode input
	if len(runMode) == 0 {
		fmt.Println("Usage:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Initialize Config
	cfg := config.NewConfig()
	handler.Initialize(cfg)

	// Initialize Echo instance with middleware
	e := router.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Configure routes based on run mode
	if runMode == "api" {

		kubesystemConfig := generator.GenerateKubeSystemConfig(cfg)

		if err := writeKubeSystemConfigToFile(kubesystemConfig); err != nil {
			fmt.Println("Error writing kube system config to file:", err)
			os.Exit(1)
		}
		// Routes for Typical API Mode for honeypot logging
		e.GET("/", handler.RootHandler)
		e.GET("/openapi/*", handler.OpenApiHandler)
		e.GET("/api/v1", handler.ApiResourceList)
		e.GET("/api", handler.ApiHandler)
		e.GET("/apis", handler.ApiGroupList)
		e.GET("/apis/:service/:version", handler.ServiceHandler)
		e.GET("/apis/apps/v1/namespaces/:namespace/:workload/:app", handler.ResourceHandler)
		e.GET("/apis/apps/v1/namespaces/kube-system/:workload", handler.KubeSystemList)
		e.GET("/apis/apps/v1/namespaces/:namespace/:workload", handler.EmptyListHandler)
		e.GET("/api/v1/namespaces/kube-system/:workload", handler.KubeSystemList)
		e.GET("/api/v1/namespaces/:namespace/:resource", handler.EmptyListHandler)
		e.GET("/apis/extensions/v1beta1/namespaces/:namespace/:resource", handler.EmptyListHandler)
		e.GET("/apis/extensions/v1beta1/:resource", handler.EmptyListHandler)
		e.GET("/api/v1/:service", handler.EmptyListHandler)
		e.POST("/api*", handler.EchoPostHandler)
		e.PATCH("/api*", handler.EchoPostHandler)
	} else if runMode == "ad" {
		// Routes for Active Defense Mode
		e.GET("/*", handler.ActiveDefenseHandler)
		e.POST("/*", handler.ActiveDefenseHandler)
	}

	// Define server information and start the server
	serverInfo := fmt.Sprintf("%s:%s", cfg.HTTP.Host, cfg.HTTP.Port)
	e.Logger.Fatal(e.Start(serverInfo))
}
