package handler

import (
	"github.com/labstack/echo/v4"
	"net/http"
    "fmt"
	"encoding/json"

)
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
