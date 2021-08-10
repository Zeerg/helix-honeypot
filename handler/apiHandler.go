package handler

import (
	"github.com/labstack/echo/v4"
	"net/http"
	"encoding/json"
    "io/ioutil"
)
// Root Route Handler
func ApiHandler(c echo.Context) error {
	jsonFile, err := ioutil.ReadFile("./kube_json/api.json")
    if err != nil {
		c.Logger().Print(err)
    }
	var data map[string]interface{}
	err = json.Unmarshal(jsonFile, &data)

	return c.JSON(http.StatusOK, data)
}
// Basic API Handler
func ApiResourceList(c echo.Context) error {
	jsonFile, err := ioutil.ReadFile("./kube_json/api_resourcelist.json")
    if err != nil {
		c.Logger().Print(err)
    }
	var data map[string]interface{}
	err = json.Unmarshal(jsonFile, &data)

	return c.JSON(http.StatusOK, data)
}
func ApiGroupList(c echo.Context) error {
	jsonFile, err := ioutil.ReadFile("./kube_json/api_grouplist.json")
    if err != nil {
		c.Logger().Print(err)
    }
	var data map[string]interface{}
	err = json.Unmarshal(jsonFile, &data)
	return c.JSON(http.StatusOK, data)
}