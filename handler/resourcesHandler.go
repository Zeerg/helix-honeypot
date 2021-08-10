package handler

import (
	"github.com/labstack/echo/v4"
	"net/http"
	"encoding/json"
    "fmt"
    "io/ioutil"
)
type podsStruct struct {
	APIVersion string        `json:"apiVersion"`
	Items      []interface{} `json:"items"`
	Kind       string        `json:"kind"`
	Metadata   struct {
		ResourceVersion string `json:"resourceVersion"`
		SelfLink        string `json:"selfLink"`
	} `json:"metadata"`
}
// Pods Handler for default routes etc..Just returns blank
func PodsHandler(c echo.Context) error {
	jsonFile, err := ioutil.ReadFile("./kube_json/default_pods.json")
    if err != nil {
      fmt.Print(err)
    }
	var data podsStruct
	err = json.Unmarshal(jsonFile, &data)

	return c.JSON(http.StatusOK, data)
}
// Handler for any k8s resource like deployments etc.
func ResourceHandler(c echo.Context) error {
	json_map := make(map[string]interface{})
	err := json.NewDecoder(c.Request().Body).Decode(&json_map)
	if err != nil {
		fmt.Print(err)
	}
	return c.JSON(404, json_map)
}