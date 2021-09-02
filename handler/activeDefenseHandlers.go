package handler

import (
	"github.com/labstack/echo/v4"
	"net/http"
	"encoding/json"
)

// Pods Handler for default routes etc..Just returns blank
func AdGetHandler(c echo.Context) error {
	var data map[string]interface{}
	err := json.Unmarshal(embedGet("empty_list.json"), &data)
	if err != nil {
		c.Logger().Print(err)
	}
	return c.JSON(http.StatusOK, data)
}
func AdPostHandler(c echo.Context) error {
	json_map := make(map[string]interface{})
	err := json.NewDecoder(c.Request().Body).Decode(&json_map)
	c.Logger().Print(json_map)
	if err != nil {
		c.Logger().Print(err)
	}
	return c.JSON(201, json_map)
}