// Package web embeds the issuer UI's static assets and the OpenAPI spec
// so they ship inside the compiled binary.
package web

import "embed"

//go:embed static/*
var StaticFS embed.FS

//go:embed openapi.yaml
var OpenAPISpec []byte
