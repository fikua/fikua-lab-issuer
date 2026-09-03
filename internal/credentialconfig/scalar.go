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
