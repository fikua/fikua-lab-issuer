package credentialconfig

import "strings"

// claimLabel derives a human-readable form label from a snake_case
// dataIdentifier (e.g. "given_name" -> "Given Name"). The registry's
// AttestationScheme carries no display label of its own for individual
// claims — Rulebook display metadata is document-level prose, not a form
// label — so this issuer derives one mechanically instead of hardcoding a
// lookup table per claim.
func claimLabel(dataIdentifier string) string {
	words := strings.Split(dataIdentifier, "_")
	for i, w := range words {
		if w == "" {
			continue
		}
		words[i] = strings.ToUpper(w[:1]) + w[1:]
	}
	return strings.Join(words, " ")
}
