package handler

import (
	"github.com/labstack/echo/v4"
	"net/http"
	"encoding/json"
	"fmt"
)
// ApiHandler returns the api.json embedded file
func ApiHandler(c echo.Context) error {
	var data map[string]interface{}
	err := json.Unmarshal(embedGet("api.json"), &data)
	if err != nil {
		c.Logger().Print(err)
	}
	return c.JSON(http.StatusOK, data)
}
// ApiResourceList returns the api_resourcelist.json embedded file
func ApiResourceList(c echo.Context) error {
	var data map[string]interface{}
	err := json.Unmarshal(embedGet("api_resourcelist.json"), &data)
	if err != nil {
		c.Logger().Print(err)
	}
	return c.JSON(http.StatusOK, data)
}
// ApiGroupList returns the api_grouplist.json embedded file
func ApiGroupList(c echo.Context) error {
	var data map[string]interface{}
	err := json.Unmarshal(embedGet("api_grouplist.json"), &data)
	if err != nil {
		c.Logger().Print(err)
	}
	return c.JSON(http.StatusOK, data)
}
// Root Route Handler
func RootHandler(c echo.Context) error {
	var data map[string]interface{}
	err := json.Unmarshal(embedGet("root.json"), &data)
	if err != nil {
		c.Logger().Print(err)
	}
	return c.JSON(http.StatusOK, data)
}
// Pods Handler for default routes etc..Just returns blank
func PodsHandler(c echo.Context) error {
	var data map[string]interface{}
	err := json.Unmarshal(embedGet("empty_list.json"), &data)
	if err != nil {
		c.Logger().Print(err)
	}
	return c.JSON(http.StatusOK, data)
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
func PostHandler(c echo.Context) error {
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