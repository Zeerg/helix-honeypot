package handler

import (
	"github.com/labstack/echo/v4"
	"encoding/json"
)

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
