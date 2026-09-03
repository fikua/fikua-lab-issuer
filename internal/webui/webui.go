// Package webui serves the issuer's static UI (credential picker, issuance
// form, records browser): plain HTML/CSS/JS, no server-side templating.
package webui

import (
	"io/fs"
	"net/http"
	"strings"
)

// Handler serves the embedded static UI.
type Handler struct {
	staticFS fs.FS
	basePath string
}

// NewHandler builds a webui Handler. staticFS must contain index.html at its
// root plus its sibling assets (app.js, style.css, favicon.svg).
//
// basePath is prepended to the mount point (e.g. "" serves at "/", used for
// local dev / direct access; a future reverse-proxying Worker in front of
// this service would pass e.g. "/issuer").
func NewHandler(staticFS fs.FS, basePath string) *Handler {
	return &Handler{staticFS: staticFS, basePath: strings.TrimSuffix(basePath, "/")}
}

// Routes registers this handler's endpoints on mux.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.Handle("GET "+h.basePath+"/", http.StripPrefix(h.basePath+"/", http.FileServer(http.FS(h.staticFS))))
}
