package handler

import (
	"github.com/labstack/echo/v4"
	"net/http"
	"encoding/json"
)
// Root Route Handler
func RootHandler(c echo.Context) error {
	var data map[string]interface{}
	err := json.Unmarshal(embedGet("root.json"), &data)
	if err != nil {
		c.Logger().Print(err)
	}
	return c.JSON(http.StatusOK, data)
}