package handler

import "embed"

//go:embed embedded/openapi/*.json.gz
var embeddedFS embed.FS
