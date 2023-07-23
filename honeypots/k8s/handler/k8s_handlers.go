package handler

import (
	"encoding/json"
	"fmt"
	"github.com/labstack/echo/v4"
	"io/ioutil"
	"net/http"

	"helix-honeypot/honeypots/k8s/generator"
)


// ReadFile reads a file and returns its content as a byte array
func ReadFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

func getJsonResponse(c echo.Context, fileName string) error {
	var data map[string]interface{}
	err := json.Unmarshal(embedGet(fileName), &data)
	if err != nil {
		c.Logger().Print(err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to process the request",
		})
	}
	return c.JSON(http.StatusOK, data)
}

// ApiHandler returns the api.json embedded file
func ApiHandler(c echo.Context) error {
	return getJsonResponse(c, "api.json")
}

// ApiResourceList returns the api_resourcelist.json embedded file
func ApiResourceList(c echo.Context) error {
	return getJsonResponse(c, "api_resourcelist.json")
}

// ApiGroupList returns the api_grouplist.json embedded file
func ApiGroupList(c echo.Context) error {
	return getJsonResponse(c, "api_grouplist.json")
}

// KubeSystemList returns a fake kube system
func KubeSystemList(c echo.Context) error {
	data, err := ReadFile("kubeSystemConfig.json")
	if err != nil {
		return err
	}

	return c.JSONBlob(http.StatusOK, data)
}

// DefaultList returns a fake default namespace
func DefaultList(c echo.Context) error {
	data, err := ReadFile("defaultConfig.json")
	if err != nil {
		return err
	}

	return c.JSONBlob(http.StatusOK, data)
}

// Root Route Handler
func RootHandler(c echo.Context) error {
	return getJsonResponse(c, "root.json")
}

func EmptyListHandler(c echo.Context) error {
	// Generate the table
	table := generator.GenerateEmptyList()

	// Convert table to JSON
	jsonData, err := json.Marshal(table)
	if err != nil {
		// Handle error
		return err
	}

	return c.JSONBlob(http.StatusOK, jsonData)
}
// Handler for any k8s resource like deployments etc.
func ResourceHandler(c echo.Context) error {
	json_map := make(map[string]interface{})
	err := json.NewDecoder(c.Request().Body).Decode(&json_map)
	if err != nil {
		c.Logger().Print(err)
	}
	return c.JSON(404, json_map)
}

//Pods Handler just returns a 201 and echo's back the post request
func EchoPostHandler(c echo.Context) error {
	json_map := make(map[string]interface{})
	err := json.NewDecoder(c.Request().Body).Decode(&json_map)
	c.Logger().Print(json_map)
	if err != nil {
		c.Logger().Print(err)
	}
	return c.JSON(201, json_map)
}

//Pods Handler
func ServiceHandler(c echo.Context) error {
	servicePathBase := "resource_dump/"
	service := c.Param("service")
	version := c.Param("version")
	fileName := "serverresources.json"
	filePath := fmt.Sprintf("%s%s/%s/%s", servicePathBase, service, version, fileName)
	var data map[string]interface{}
	err := json.Unmarshal(embedGet(filePath), &data)
	if err != nil {
		c.Logger().Print(err)
	}
	return c.JSON(http.StatusOK, data)
}
