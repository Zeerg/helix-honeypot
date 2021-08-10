package handler

import (
	"github.com/labstack/echo/v4"
	"net/http"
	"encoding/json"
    "io/ioutil"
)

type rootApis struct {
	Versions                   []string `json:"versions"`
	ServerAddressByClientCIDRs []struct {
		ClientCIDR    string `json:"clientCIDR"`
		ServerAddress string `json:"serverAddress"`
	} `json:"serverAddressByClientCIDRs"`
}

type apiResourceList struct {
	Kind         string `json:"kind"`
	APIVersion   string `json:"apiVersion"`
	GroupVersion string `json:"groupVersion"`
	Resources    []struct {
		Name               string   `json:"name"`
		SingularName       string   `json:"singularName"`
		Namespaced         bool     `json:"namespaced"`
		Kind               string   `json:"kind"`
		Verbs              []string `json:"verbs"`
		ShortNames         []string `json:"shortNames,omitempty"`
		StorageVersionHash string   `json:"storageVersionHash,omitempty"`
	} `json:"resources"`
}
type apiGroupList struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
	Groups     []struct {
		Name     string `json:"name"`
		Versions []struct {
			GroupVersion string `json:"groupVersion"`
			Version      string `json:"version"`
		} `json:"versions"`
		PreferredVersion struct {
			GroupVersion string `json:"groupVersion"`
			Version      string `json:"version"`
		} `json:"preferredVersion"`
	} `json:"groups"`
}
// Root Route Handler
func ApiHandler(c echo.Context) error {
	jsonFile, err := ioutil.ReadFile("./kube_json/api.json")
    if err != nil {
		c.Logger().Print(err)
    }
	var data rootApis
	err = json.Unmarshal(jsonFile, &data)

	return c.JSON(http.StatusOK, data)
}
// Basic API Handler
func ApiResourceList(c echo.Context) error {
	jsonFile, err := ioutil.ReadFile("./kube_json/api_resourcelist.json")
    if err != nil {
		c.Logger().Print(err)
    }
	var data apiResourceList
	err = json.Unmarshal(jsonFile, &data)

	return c.JSON(http.StatusOK, data)
}
func ApiGroupList(c echo.Context) error {
	jsonFile, err := ioutil.ReadFile("./kube_json/api_grouplist.json")
    if err != nil {
		c.Logger().Print(err)
    }
	var data apiGroupList
	err = json.Unmarshal(jsonFile, &data)
	return c.JSON(http.StatusOK, data)
}