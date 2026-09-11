package credentialconfig

import (
	"testing"

	"github.com/fikua/fikua-lab-issuer/internal/registryclient"
)

func TestBuildClaims_PropagatesMandatoryFromPresence(t *testing.T) {
	claims := buildClaims([]registryclient.ClaimDefinition{
		{DataIdentifier: "given_name", Path: []string{"given_name"}, DataType: "string", Presence: registryclient.PresenceMandatory},
		{DataIdentifier: "email", Path: []string{"email"}, DataType: "string", Presence: registryclient.PresenceOptional},
		{DataIdentifier: "birth_place", Path: []string{"birth_place"}, DataType: "string", Presence: registryclient.PresenceConditional},
	})

	byPath := make(map[string]Claim, len(claims))
	for _, c := range claims {
		byPath[c.Path[0]] = c
	}

	if !byPath["given_name"].Mandatory {
		t.Error("given_name (PresenceMandatory) should be Mandatory=true")
	}
	if byPath["email"].Mandatory {
		t.Error("email (PresenceOptional) should be Mandatory=false")
	}
	if byPath["birth_place"].Mandatory {
		t.Error("birth_place (PresenceConditional) should be Mandatory=false — conditional is not the same as required")
	}
}

func TestBuildClaims_SkipsNonScalarAndNestedClaims(t *testing.T) {
	claims := buildClaims([]registryclient.ClaimDefinition{
		{DataIdentifier: "given_name", Path: []string{"given_name"}, DataType: "string", Presence: registryclient.PresenceMandatory},
		{DataIdentifier: "nationalities", Path: []string{"nationalities"}, DataType: "array", Presence: registryclient.PresenceMandatory},
		{DataIdentifier: "formatted", Path: []string{"address", "formatted"}, DataType: "string", Presence: registryclient.PresenceMandatory},
	})

	if len(claims) != 1 {
		t.Fatalf("expected only the single-segment scalar claim to survive, got %d: %+v", len(claims), claims)
	}
	if claims[0].Path[0] != "given_name" {
		t.Errorf("expected given_name, got %v", claims[0].Path)
	}
}
