package handler

import (
	"github.com/labstack/echo/v4"
	"net/http"
	"encoding/json"
    "fmt"
    "io/ioutil"
)
type apiV1Struct struct {
	Kind         string `json:"kind"`
	GroupVersion string `json:"groupVersion"`
	Resources    []struct {
		Name               string   `json:"name"`
		SingularName       string   `json:"singularName"`
		Namespaced         bool     `json:"namespaced"`
		Kind               string   `json:"kind"`
		Verbs              []string `json:"verbs"`
		ShortNames         []string `json:"shortNames,omitempty"`
		StorageVersionHash string   `json:"storageVersionHash,omitempty"`
		Categories         []string `json:"categories,omitempty"`
		Group              string   `json:"group,omitempty"`
		Version            string   `json:"version,omitempty"`
	} `json:"resources"`
}
// Basic API Handler
func ApiV1Handler(c echo.Context) error {
	jsonFile, err := ioutil.ReadFile("/Users/zeerg/starfleet/helix-honeypot/kube_json/v1_resourcelist.json")
    if err != nil {
      fmt.Print(err)
    }
	var data apiV1Struct
	err = json.Unmarshal(jsonFile, &data)

	return c.JSON(http.StatusOK, data)
}