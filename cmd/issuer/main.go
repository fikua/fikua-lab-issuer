// Command issuer runs the Fikua Lab Issuer: an OID4VCI credential issuer
// serving both its JSON API and its issuance UI from a single Go binary.
package main

import (
	"io/fs"
	"log"
	"net/http"
	"os"

	"github.com/fikua/fikua-lab-issuer/internal/httpapi"
	"github.com/fikua/fikua-lab-issuer/internal/webui"
	"github.com/fikua/fikua-lab-issuer/web"
)

func main() {
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	// Set when this service is reached through a reverse-proxying Worker
	// under a path prefix, so its own asset links point back through that
	// prefix. Empty for local dev / direct access.
	basePath := os.Getenv("BASE_PATH")

	staticFS, err := fs.Sub(web.StaticFS, "static")
	if err != nil {
		log.Fatalf("static assets: %v", err)
	}

	mux := http.NewServeMux()
	httpapi.NewHandler().Routes(mux)
	webui.NewHandler(staticFS, basePath).Routes(mux)

	log.Printf("fikua-lab-issuer listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
