package credentialconfig

import "testing"

func TestIsDateType(t *testing.T) {
	dateTypes := []string{
		"full-date",
		"tdate or full-date",
		"string (ISO 8601-1 YYYY-MM-DD)",
	}
	for _, dt := range dateTypes {
		if !isDateType(dt) {
			t.Errorf("isDateType(%q) = false, want true", dt)
		}
	}

	nonDateTypes := []string{
		"string",
		"number",
		"bstr",
		"tstr",
		"uint",
		"array of string (ISO 3166-1 alpha-2)",
		"string (ISO 3166-1 alpha-2)",
		"string (RFC 5322)",
		"string (URI)",
		"string (data URL, base64 JPEG)",
		"string (attestation type or vct)",
		"number (ISO/IEC 5218)",
		"object {country?, region?, locality?}",
		"place_of_birth (map: country?, region?, locality?)",
		"nationalities ([+ CountryCode])",
	}
	for _, dt := range nonDateTypes {
		if isDateType(dt) {
			t.Errorf("isDateType(%q) = true, want false", dt)
		}
	}
}
