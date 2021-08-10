package handler

import (
	"github.com/labstack/echo/v4"
	"net/http"
	"encoding/json"
    "fmt"
    "io/ioutil"
)
// Root Route Handler
func RootHandler(c echo.Context) error {
	jsonFile, err := ioutil.ReadFile("./kube_json/root.json")
    if err != nil {
      fmt.Print(err)
    }
	var data map[string]interface{}
	err = json.Unmarshal(jsonFile, &data)

	return c.JSON(http.StatusOK, data)
}