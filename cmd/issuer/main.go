// Command issuer runs the Fikua Lab Issuer: an OID4VCI credential issuer
// serving both its JSON API and its issuance UI from a single Go binary.
package main

import (
	"context"
	"io/fs"
	"log"
	"net/http"

	"github.com/fikua/fikua-lab-issuer/internal/config"
	fikuacrypto "github.com/fikua/fikua-lab-issuer/internal/crypto"
	"github.com/fikua/fikua-lab-issuer/internal/httpapi"
	"github.com/fikua/fikua-lab-issuer/internal/issuance"
	"github.com/fikua/fikua-lab-issuer/internal/registryclient"
	"github.com/fikua/fikua-lab-issuer/internal/session"
	"github.com/fikua/fikua-lab-issuer/internal/webui"
	"github.com/fikua/fikua-lab-issuer/web"
)

func main() {
	cfg := config.Load()

	registry := registryclient.New(cfg.AttestationRegistryURL)
	cache := registryclient.NewCache(registry)
	// Blocking on boot is intentional: without a scheme catalogue this
	// issuer has nothing to serve, so a registry outage at startup should
	// fail loudly rather than come up empty. Once running, background
	// refreshes are best-effort (see Cache.Start).
	if err := cache.Start(context.Background(), cfg.RegistryRefreshInterval); err != nil {
		log.Fatalf("loading attestation catalogue from %s: %v", cfg.AttestationRegistryURL, err)
	}

	foundSchemes := 0
	for _, schemeID := range cfg.IssuableSchemes {
		if _, ok := cache.Get(schemeID); ok {
			foundSchemes++
		} else {
			log.Printf("warning: configured issuable scheme %q not found in attestation-registry catalogue", schemeID)
		}
	}

	issuerKey, err := fikuacrypto.LoadOrGenerate(cfg.CertsDir)
	if err != nil {
		log.Fatalf("loading signing key: %v", err)
	}
	log.Printf("issuer signing key loaded (kid=%s)", issuerKey.KID())

	sessions := session.NewStore()
	issuances := issuance.NewStore()
	issuanceService := issuance.NewService(cfg.BaseURL, issuerKey, sessions, issuances)

	staticFS, err := fs.Sub(web.StaticFS, "static")
	if err != nil {
		log.Fatalf("static assets: %v", err)
	}

	mux := http.NewServeMux()
	httpapi.NewHandler(cfg.BaseURL, cache, cfg.IssuableSchemes, issuerKey, issuanceService).Routes(mux)
	webui.NewHandler(staticFS, cfg.BasePath).Routes(mux)

	log.Printf("fikua-lab-issuer listening on %s (issuing %d/%d configured schemes; %d total in catalogue from %s)", cfg.Addr, foundSchemes, len(cfg.IssuableSchemes), len(cache.All()), cfg.AttestationRegistryURL)
	if err := http.ListenAndServe(cfg.Addr, mux); err != nil {
		log.Fatal(err)
	}
}
