// Command issuer runs the Fikua Lab Issuer: an OID4VCI credential issuer
// serving both its JSON API and its issuance UI from a single Go binary.
package main

import (
	"context"
	"database/sql"
	"io/fs"
	"log"
	"net/http"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/fikua/fikua-lab-issuer/db"
	"github.com/fikua/fikua-lab-issuer/internal/config"
	fikuacrypto "github.com/fikua/fikua-lab-issuer/internal/crypto"
	"github.com/fikua/fikua-lab-issuer/internal/cscclient"
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

	issuerKey, err := loadSigningKey(cfg)
	if err != nil {
		log.Fatalf("loading signing key: %v", err)
	}
	log.Printf("issuer signing key loaded (kid=%s)", issuerKey.KID())

	walletProviderAnchor, err := fikuacrypto.LoadWalletProviderAnchor(cfg.CertsDir)
	if err != nil {
		log.Fatalf("loading wallet provider trust anchor: %v", err)
	}
	if walletProviderAnchor == nil {
		log.Printf("warning: no root-ca.crt found in %s — accepting any self-consistent client attestation (no Wallet Provider trust pinning)", cfg.CertsDir)
	}

	issuances, err := loadIssuanceStore(cfg)
	if err != nil {
		log.Fatalf("setting up issuance store: %v", err)
	}

	sessions := session.NewStore()
	issuanceService := issuance.NewService(cfg.BaseURL, issuerKey, sessions, issuances, walletProviderAnchor)

	staticFS, err := fs.Sub(web.StaticFS, "static")
	if err != nil {
		log.Fatalf("static assets: %v", err)
	}

	mux := http.NewServeMux()
	httpapi.NewHandler(cfg.BaseURL, cache, cfg.IssuableSchemes, issuerKey, issuanceService, web.OpenAPISpec).Routes(mux)
	webui.NewHandler(staticFS, cfg.BasePath).Routes(mux)

	log.Printf("fikua-lab-issuer listening on %s (issuing %d/%d configured schemes; %d total in catalogue from %s)", cfg.Addr, foundSchemes, len(cfg.IssuableSchemes), len(cache.All()), cfg.AttestationRegistryURL)
	if err := http.ListenAndServe(cfg.Addr, mux); err != nil {
		log.Fatal(err)
	}
}

// loadSigningKey builds the issuer's signing key: remotely via the Fikua
// DSS's CSC API when cfg.DSSURL is set, or from cfg.CertsDir/an ephemeral
// key otherwise (see fikuacrypto.LoadOrGenerate).
func loadSigningKey(cfg config.Config) (*fikuacrypto.SigningKey, error) {
	if cfg.DSSURL == "" {
		return fikuacrypto.LoadOrGenerate(cfg.CertsDir)
	}

	log.Printf("signing via Fikua DSS at %s (credential=%s)", cfg.DSSURL, cfg.DSSCredentialID)
	client := cscclient.New(cscclient.Config{
		BaseURL:            cfg.DSSURL,
		ClientID:           cfg.DSSClientID,
		ClientSecret:       cfg.DSSClientSecret,
		CredentialID:       cfg.DSSCredentialID,
		CredentialPassword: cfg.DSSCredentialPassword,
	})
	signer, err := cscclient.NewSigner(context.Background(), client)
	if err != nil {
		return nil, err
	}
	leafDER, err := signer.LeafDER(context.Background())
	if err != nil {
		return nil, err
	}
	// Only the leaf goes into x5c — see LeafDER's doc comment.
	return fikuacrypto.NewRemote(signer, [][]byte{leafDER})
}

// loadIssuanceStore builds the issuance-record store: Postgres when
// cfg.DBURL is set (pinged and schema-applied before use, so a
// misconfigured or unreachable database fails loudly at boot rather than
// on the first request), or an in-memory fallback otherwise — fine for
// local development, but data is lost on every restart.
func loadIssuanceStore(cfg config.Config) (issuance.RecordStore, error) {
	if cfg.DBURL == "" {
		log.Printf("warning: no FIKUA_DB_URL configured — using in-memory issuance store (data lost on restart)")
		return issuance.NewStore(), nil
	}

	sqlDB, err := sql.Open("pgx", cfg.DBURL)
	if err != nil {
		return nil, err
	}
	if err := sqlDB.PingContext(context.Background()); err != nil {
		return nil, err
	}
	if _, err := sqlDB.ExecContext(context.Background(), db.Schema); err != nil {
		return nil, err
	}
	log.Printf("issuance records persisted to Postgres")
	return issuance.NewPostgresStore(sqlDB), nil
}
