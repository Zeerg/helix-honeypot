package handler

import (
	"net/http"
	//"path/filepath"
	"io/ioutil"
	"fmt"
	"bytes"
	"compress/gzip"
	"crypto/sha512"

	"github.com/labstack/echo/v4"
	"github.com/golang/protobuf/proto"
	openapi_v2 "github.com/googleapis/gnostic/openapiv2"
)
// Kubectl expects gzip usually
func gzipHelper(data []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(data)
	zw.Close()
	return buf.Bytes()
}
// Compute the ETAG 
func computeETag(data []byte) string {
	return fmt.Sprintf("\"%X\"", sha512.Sum512(data))
}
// OpenAPI Handler
func OpenApiHandler(c echo.Context) error {

	//openApiYamlPath, _ := filepath.Abs("/Users/zeerg/starfleet/helix-honeypot/openapi/k8s_v1.19.7_openapi.yaml")
	openApiData, err := ioutil.ReadFile("/Users/zeerg/starfleet/helix-honeypot/openapi/k8s_v1.19.7_openapi.yaml")
	if err != nil {
		return err
	}
	openApiDoc, err := openapi_v2.ParseDocument(openApiData)
	if err != nil {
		return err
	}
	binaryDoc, err := proto.Marshal(openApiDoc)
	if err != nil {
		return err
	}
	gzipDoc := gzipHelper(binaryDoc)
	gzipEtag := computeETag(gzipDoc)
	c.Response().Header().Set("ETAG", gzipEtag)
	c.Response().Header().Set("Vary", "Accept")
	c.Response().Header().Set("Content-Type", "application/octet-stream; charset=UTF-8")
	c.Response().Header().Set("Content-Encoding", "gzip")
	return c.HTMLBlob(http.StatusOK, gzipDoc)
}