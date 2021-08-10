package handler

import (
	"github.com/labstack/echo/v4"
	"net/http"
	"encoding/json"
    "io/ioutil"
)

// Pods Handler for default routes etc..Just returns blank
func PodsHandler(c echo.Context) error {
	jsonFile, err := ioutil.ReadFile("./kube_json/default_pods.json")
    if err != nil {
      c.Logger().Print(err)
    }
	var data map[string]interface{}
	err = json.Unmarshal(jsonFile, &data)

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