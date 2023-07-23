package handler

import (
	"bytes"
	"compress/gzip"
	"crypto/sha512"
	"fmt"
	"net/http"

	openapi_v2 "github.com/google/gnostic/openapiv2"
	"github.com/labstack/echo/v4"
	"google.golang.org/protobuf/proto"

	"helix-honeypot/model"
)

// Declare a global variable for the configuration
var cfg *model.Config

// Function to initialize the handler package with configuration
func Initialize(c *model.Config) {
	cfg = c
}

// Kubectl expects gzip usually....I really don't know
func gzipHelper(data []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(data)
	zw.Close()
	return buf.Bytes()
}

// Compute the ETAG.....no idea if this is needed
func computeETag(data []byte) string {
	return fmt.Sprintf("\"%X\"", sha512.Sum512(data))
}

// OpenAPI Handler just sends the swagger doc via proto
func OpenApiHandler(c echo.Context) error {
	openApiDoc, err := openapi_v2.ParseDocument(embedGet(fmt.Sprintf("openapi/%s_openapi.json", cfg.K8S.APIVersion)))
	if err != nil {
		c.Logger().Print(err)
	}
	binaryDoc, err := proto.Marshal(openApiDoc)
	if err != nil {
		c.Logger().Print(err)
	}
	gzipDoc := gzipHelper(binaryDoc)
	gzipEtag := computeETag(gzipDoc)
	c.Response().Header().Set("ETAG", gzipEtag)
	c.Response().Header().Set("Vary", "Accept")
	c.Response().Header().Set("Content-Type", "application/octet-stream; charset=UTF-8")
	c.Response().Header().Set("Content-Encoding", "gzip")
	return c.HTMLBlob(http.StatusOK, gzipDoc)
}
