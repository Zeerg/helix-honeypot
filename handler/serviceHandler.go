package handler

import (
	"github.com/labstack/echo/v4"
	"net/http"
    "fmt"
    "io/ioutil"
	"encoding/json"

)
//Pods Handler
func ServiceHandler(c echo.Context) error {
	servicePathBase := "./kube_json/resource_dump/"
	service := c.Param("service")
	version := c.Param("version")
	fileName := "serverresources.json"
	filePath := fmt.Sprintf("%s%s/%s/%s", servicePathBase, service, version, fileName)
	jsonFile, err := ioutil.ReadFile(filePath)
    if err != nil {
		c.Logger().Print(err)
    }
	var result map[string]interface{}
	json.Unmarshal(jsonFile, &result)
	return c.JSON(http.StatusOK, result)
}
