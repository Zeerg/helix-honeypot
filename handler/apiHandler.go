package handler

import (
	"github.com/labstack/echo/v4"
	"net/http"
	"encoding/json"
)
func ApiHandler(c echo.Context) error {
	var data map[string]interface{}
	err := json.Unmarshal(embedGet("api.json"), &data)
	if err != nil {
		c.Logger().Print(err)
	}
	return c.JSON(http.StatusOK, data)
}
func ApiResourceList(c echo.Context) error {
	var data map[string]interface{}
	err := json.Unmarshal(embedGet("api_resourcelist.json"), &data)
	if err != nil {
		c.Logger().Print(err)
	}
	return c.JSON(http.StatusOK, data)
}
func ApiGroupList(c echo.Context) error {
	var data map[string]interface{}
	err := json.Unmarshal(embedGet("api_grouplist.json"), &data)
	if err != nil {
		c.Logger().Print(err)
	}
	return c.JSON(http.StatusOK, data)
}