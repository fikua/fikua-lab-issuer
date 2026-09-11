package credentialconfig

import "strings"

// isScalarType reports whether a registry ClaimDefinition.DataType
// describes a single scalar value (a string, number, or date) as opposed
// to a composite structure (an array or object) that a flat text/date
// input can't represent. DataType is free-form prose (e.g. "string (ISO
// 8601-1 YYYY-MM-DD)", "array of string (...)", "object {country?, ...}",
// "place_of_birth (map: ...)", "nationalities ([+ CountryCode])"), not an
// enum, so this matches on substrings rather than a fixed prefix list.
func isScalarType(dataType string) bool {
	composite := []string{"array", "object", "map", "nationalities", "place_of_birth"}
	lower := strings.ToLower(dataType)
	for _, marker := range composite {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	return true
}

// isDateType reports whether a registry ClaimDefinition.DataType
// describes a calendar date (e.g. "full-date", "tdate or full-date",
// "string (ISO 8601-1 YYYY-MM-DD)") — same free-form-prose substring
// matching as isScalarType, since DataType is not an enum here either.
// Lets the identification form (fikua-lab-idp's web/static/app.js)
// render the right input type for whatever credential is actually being
// issued, instead of a fixed list of PID field names.
func isDateType(dataType string) bool {
	lower := strings.ToLower(dataType)
	markers := []string{"full-date", "tdate", "yyyy-mm-dd"}
	for _, marker := range markers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
