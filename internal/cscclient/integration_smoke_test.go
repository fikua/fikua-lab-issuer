package cscclient_test

import (
	"context"
	"os"
	"testing"

	fikuacrypto "github.com/fikua/fikua-lab-issuer/internal/crypto"
	"github.com/fikua/fikua-lab-issuer/internal/cscclient"
	"github.com/fikua/fikua-lab-issuer/internal/sdjwt"
)

// TestSmokeAgainstRealDSS exercises the full remote-signing path against a
// real Fikua DSS instance. It's skipped unless FIKUA_DSS_SMOKE_TEST=1 is
// set, since it makes live network calls and needs real tenant
// credentials — not something to run in CI by default.
func TestSmokeAgainstRealDSS(t *testing.T) {
	if os.Getenv("FIKUA_DSS_SMOKE_TEST") != "1" {
		t.Skip("set FIKUA_DSS_SMOKE_TEST=1 (and FIKUA_DSS_URL/CLIENT_ID/CLIENT_SECRET/CREDENTIAL_ID/CREDENTIAL_PASSWORD) to run")
	}

	client := cscclient.New(cscclient.Config{
		BaseURL:            os.Getenv("FIKUA_DSS_URL"),
		ClientID:           os.Getenv("FIKUA_DSS_CLIENT_ID"),
		ClientSecret:       os.Getenv("FIKUA_DSS_CLIENT_SECRET"),
		CredentialID:       os.Getenv("FIKUA_DSS_CREDENTIAL_ID"),
		CredentialPassword: os.Getenv("FIKUA_DSS_CREDENTIAL_PASSWORD"),
	})

	ctx := context.Background()
	signer, err := cscclient.NewSigner(ctx, client)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	leafDER, err := signer.LeafDER(ctx)
	if err != nil {
		t.Fatalf("LeafDER: %v", err)
	}
	issuerKey, err := fikuacrypto.NewRemote(signer, [][]byte{leafDER})
	if err != nil {
		t.Fatalf("NewRemote: %v", err)
	}
	t.Logf("kid: %s", issuerKey.KID())

	token, err := sdjwt.NewBuilder(issuerKey).
		VCT("urn:eudi:pid:1").
		Issuer("https://issuer.fikua.com").
		Subject("urn:fikua:pid:smoketest").
		PlainClaim("issuing_authority", "Fikua Lab").
		X5CChain(issuerKey.X5CChain()).
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if token == "" {
		t.Fatal("expected a non-empty SD-JWT")
	}
	t.Logf("SD-JWT: %s", token)
}
