package routes

import (
	"github.com/labstack/echo/v4"
	"helix-honeypot/honeypots/k8s/generator"
	"helix-honeypot/honeypots/k8s/handler"
	"helix-honeypot/model"

	"os"
	"encoding/json"
	"net/http"
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

func writeDefaultConfigToFile(defaultConfig map[string]interface{}) error {
	// Open a new file for writing only
	file, err := os.OpenFile(
		"defaultConfig.json",            // path to the file
		os.O_WRONLY|os.O_TRUNC|os.O_CREATE, // open the file in write only mode, truncate it if it exists, or create it if it doesn't
		0755,
	)
	if err != nil {
		return err
	}
	defer file.Close()

	// Serialize the kubeSystemConfig map into JSON
	encoder := json.NewEncoder(file)
	return encoder.Encode(defaultConfig)
}

// DefineRoutes defines all the API routes for the application.
func DefineRoutes(e *echo.Echo, cfg *model.Config) error {
    // Routes for generating kube-system and default namespaces
    if cfg.K8S.GenerateKubeSys {
        // generate pods in the kube-system namespace
        kubesystemConfig := generator.GenerateKubeSystemConfig(cfg, "kube-system")

        if err := writeKubeSystemConfigToFile(kubesystemConfig); err != nil {
            return err
        }
        e.GET("/api/v1/namespaces/kube-system/pods", handler.KubeSystemList)
    }
    if cfg.K8S.GenerateRand {
        // generate pods with default namespace
        defaultConfig := generator.GenerateDefaultNamespaceConfig(cfg, "default")

        if err := writeDefaultConfigToFile(defaultConfig); err != nil {
            return err
        }
        e.GET("/api/v1/namespaces/default/pods", handler.DefaultList)
    }

    // Specific routes for k8s API resources
    e.GET("/apis/apps/v1/namespaces/:namespace/:workload/:app", handler.ResourceHandler)
    e.GET("/apis/apps/v1/namespaces/:namespace/:workload", handler.EmptyListHandler)
    e.GET("/apis/extensions/v1beta1/namespaces/:namespace/:resource", handler.EmptyListHandler)
    e.GET("/apis/extensions/v1beta1/:resource", handler.EmptyListHandler)
    e.GET("/api/v1/namespaces/:namespace/:resource", handler.EmptyListHandler)
    e.GET("/api/v1/namespaces/:namespace/secrets", func(c echo.Context) error {
        // Extract the namespace from the request path
        namespace := c.Param("namespace")

        // Generate the secret configuration
        secretConfig := generator.GenerateSecretConfig(cfg, namespace, cfg.K8S.TokenValues, cfg.K8S.TokenNames)

        // Return the secret configuration as the response
        return c.JSON(http.StatusOK, secretConfig)
    })

    // General routes for k8s API
    e.GET("/api/v1", handler.ApiResourceList)
    e.GET("/api/v1/:service", handler.EmptyListHandler)
    e.GET("/api", handler.ApiHandler)
    e.GET("/apis", handler.ApiGroupList)
    e.GET("/apis/:service/:version", handler.ServiceHandler)

    // Root and OpenAPI routes
    e.GET("/", handler.RootHandler)
    e.GET("/openapi/*", handler.OpenApiHandler)

    // Catch-all routes for POST and PATCH methods
    e.POST("/api*", handler.EchoPostHandler)
    e.PATCH("/api*", handler.EchoPostHandler)

    return nil
}