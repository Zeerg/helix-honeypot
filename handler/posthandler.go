package handler

import (
	"github.com/labstack/echo/v4"
	"encoding/json"
)

type User struct {
	Name  string `json:"name"`
	Email string `json:"email"`
  }

//Pods Handler
func PostHandler(c echo.Context) error {
	json_map := make(map[string]interface{})
	err := json.NewDecoder(c.Request().Body).Decode(&json_map)
	if err != nil {
		return err
	}
	return c.JSON(201, json_map)
}
