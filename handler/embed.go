package handler

import (
	"embed"
	"fmt"
)
// Embed the required files
//go:embed embedded/*
var embededFS embed.FS

// Embed FS function
func embedGet(fileName string) []byte {
	fileBytes, err := embededFS.ReadFile("embedded/" + fileName)
	if err != nil {
		fmt.Print(err)
	}
	return fileBytes
}