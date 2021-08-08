package handler

import (
	"github.com/labstack/echo/v4"
	"net/http"
	"encoding/json"
    "fmt"
    "io/ioutil"
)
type rootApis struct {
	Versions                   []string `json:"versions"`
	ServerAddressByClientCIDRs []struct {
		ClientCIDR    string `json:"clientCIDR"`
		ServerAddress string `json:"serverAddress"`
	} `json:"serverAddressByClientCIDRs"`
}

// Root Route Handler
func ApiHandler(c echo.Context) error {
	jsonFile, err := ioutil.ReadFile("/Users/zeerg/starfleet/helix-honeypot/kube_json/api.json")
    if err != nil {
      fmt.Print(err)
    }
	var data rootApis
	err = json.Unmarshal(jsonFile, &data)

	return c.JSON(http.StatusOK, data)
}