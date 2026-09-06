package issuance

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/fikua/fikua-lab-issuer/internal/accesstoken"
	fikuacrypto "github.com/fikua/fikua-lab-issuer/internal/crypto"
	"github.com/fikua/fikua-lab-issuer/internal/mdoc"
	"github.com/fikua/fikua-lab-issuer/internal/oauth2"
	"github.com/fikua/fikua-lab-issuer/internal/oid4vci"
	"github.com/fikua/fikua-lab-issuer/internal/sdjwt"
	"github.com/fikua/fikua-lab-issuer/internal/session"
	"github.com/fikua/fikua-lab-issuer/internal/statuslist"
)

// statusListID is the only Status List Token this issuer serves — a
// single global list shared by every credential it issues (see
// db/schema.sql's status_list_entries doc comment for why one list is
// enough at this scale).
const statusListID = "pid"

// statusListCacheTTL bounds how often the status list token is rebuilt
// and re-signed (which, when signing via the Fikua DSS, is a network
// call) — independent of the token's own longer "ttl"/"exp" claims,
// which tell relying parties how long *they* may cache it. A revoke
// invalidates this cache immediately, so real staleness is bounded by
// min(statusListCacheTTL, time since last revoke).
const statusListCacheTTL = 60 * time.Second

// PIDConfigID and PIDMdocConfigID are the only credential_configuration_ids
// this issuer issues — Student ID is not carried over from the Java
// issuer (see the migration plan).
const (
	PIDConfigID     = "urn:eudi:pid:1"
	PIDMdocConfigID = "urn:eudi:pid:1.mdoc"
)

const (
	pidVCT           = "urn:eudi:pid:1"
	pidDocType       = "eu.europa.ec.eudi.pid.1"
	pidSubjectPrefix = "urn:fikua:pid:"
)

// Service implements this issuer's OID4VCI credential issuance: the
// nonce, credential and notification endpoints, plus issuance-record
// management and the status list.
//
// The OAuth2 authorization server this used to embed — PAR, /authorize,
// /token, and the end-user identification flow behind them — now lives in
// fikua-lab-idp. This service is a resource server: it verifies the
// access tokens that AS mints (see internal/accesstoken) rather than
// issuing them, and holds no authorization state of its own beyond the
// nonces its own Nonce Endpoint hands out.
type Service struct {
	baseURL    string
	issuerKey  *fikuacrypto.SigningKey
	sessions   *session.Store
	issuances  RecordStore
	statusList StatusListStore
	jtis       *oauth2.JTIStore
	tokens     *accesstoken.Verifier

	statusCacheMu    sync.Mutex
	statusCacheToken string
	statusCacheExp   time.Time
}

// NewService builds a Service. baseURL is this issuer's own Credential
// Issuer identifier (e.g. "https://issuer.fikua.com"), used as both the
// SD-JWT/mdoc `iss`/docType binding and the expected proof/DPoP JWT
// `aud`/`htu`. tokens verifies the access tokens presented at the
// protected endpoints, against the authorization server's published JWK
// Set. issuances is either the in-memory Store (dev/no-Postgres fallback)
// or a PostgresStore. statusList is the same underlying store, typed as
// StatusListStore — see cmd/issuer/main.go's wiring.
func NewService(baseURL string, issuerKey *fikuacrypto.SigningKey, sessions *session.Store, issuances RecordStore, statusList StatusListStore, tokens *accesstoken.Verifier) *Service {
	return &Service{
		baseURL:    baseURL,
		issuerKey:  issuerKey,
		sessions:   sessions,
		issuances:  issuances,
		statusList: statusList,
		jtis:       oauth2.NewJTIStore(),
		tokens:     tokens,
	}
}

// TriggerIssuanceRequest is the POST /oid4vci/v1/issuance request body.
type TriggerIssuanceRequest struct {
	CredentialType string         `json:"credential_type"`
	CredentialData map[string]any `json:"credential_data"`
	SourceType     string         `json:"source_type"`
	SourceRef      string         `json:"source_ref"`
}

// TriggerIssuanceResult is the POST /oid4vci/v1/issuance response body.
type TriggerIssuanceResult struct {
	IssuanceID         string `json:"issuance_id"`
	CredentialOfferURI string `json:"credential_offer_uri"`
}

// TriggerIssuance creates an issuance record and an authorization_code
// credential offer carrying an issuer_state that links the wallet's
// later /authorize (via PAR) back to this record. The offer is served
// by reference (credential_offer_uri, resolved via GET
// /oid4vci/v1/credential-offer/{id}) rather than inlined in this
// response — OID4VCI §4.1's two delivery styles are equivalent, but the
// deep link a wallet actually scans/opens embeds this URI, not the
// offer object itself.
func (s *Service) TriggerIssuance(req TriggerIssuanceRequest) (TriggerIssuanceResult, error) {
	credentialType := req.CredentialType
	if credentialType == "" {
		credentialType = PIDConfigID
	}
	credentialData := req.CredentialData
	if credentialData == nil {
		credentialData = map[string]any{}
	}
	credentialDataJSON, err := json.Marshal(credentialData)
	if err != nil {
		return TriggerIssuanceResult{}, oauth2.BadRequest(oauth2.InvalidRequest, "Failed to trigger issuance: "+err.Error())
	}

	rec := s.issuances.Create(credentialType, string(credentialDataJSON), req.SourceType, req.SourceRef)

	issuerState := session.RandomToken(16)
	s.issuances.UpdateIssuerState(rec.ID, issuerState)

	offer := oid4vci.AuthorizationCodeOffer(s.baseURL, credentialType, issuerState)
	offerJSON, err := json.Marshal(offer)
	if err != nil {
		return TriggerIssuanceResult{}, oauth2.BadRequest(oauth2.InvalidRequest, "Failed to trigger issuance: "+err.Error())
	}
	offerID := s.sessions.StoreCredentialOffer(string(offerJSON))
	s.issuances.UpdateStatus(rec.ID, "offer_created")

	offerURI := s.baseURL + "/oid4vci/v1/credential-offer/" + offerID
	return TriggerIssuanceResult{IssuanceID: rec.ID, CredentialOfferURI: offerURI}, nil
}

// GetCredentialOffer resolves a by-reference credential offer id
// (from a credential_offer_uri) to its stored Credential Offer JSON.
func (s *Service) GetCredentialOffer(id string) (string, bool) {
	return s.sessions.GetCredentialOffer(id)
}

// FindByIssuerState resolves a credential offer's issuer_state to the
// issuance record TriggerIssuance created it for. Exposed for the
// authorization server, which needs this link at /authorize but has no
// record store of its own.
func (s *Service) FindByIssuerState(issuerState string) (Record, bool) {
	return s.issuances.FindByIssuerState(issuerState)
}

// GenerateNonce implements the Nonce Endpoint (OID4VCI 1.0 §7). It stays
// on the Credential Issuer rather than moving to the authorization server
// with the rest of the OAuth2 endpoints: the spec defines it as a
// Credential Issuer endpoint, unauthenticated, and the nonces it hands
// out are bound to this issuer as the proof JWT's `aud`.
//
// A fresh nonce is always registered. If accessToken is present it is
// verified and its DPoP binding enforced, so a caller cannot use this
// endpoint to probe whether a token is valid without holding the matching
// key — but a token is not required, since a wallet legitimately calls
// this before it has one.
func (s *Service) GenerateNonce(ctx context.Context, accessToken, dpopHeader string) (string, error) {
	nonce := session.GenerateNonce()
	s.sessions.RegisterNonce(nonce)

	if accessToken != "" {
		claims, err := s.tokens.Verify(ctx, accessToken)
		if err != nil {
			return "", err
		}
		ath := oauth2.ComputeATH(accessToken)
		dpopKey, err := oauth2.ValidateDPoPProof(dpopHeader, "POST", s.baseURL+"/oid4vci/v1/nonce", ath, s.jtis)
		if err != nil {
			return "", err
		}
		if err := requireBoundThumbprint(claims.JKT, dpopKey, "DPoP key mismatch at nonce endpoint"); err != nil {
			return "", err
		}
	}
	return nonce, nil
}

// IssueCredential implements the credential endpoint. Everything it needs
// about the authorization comes from the verified access token's claims —
// there is no session to look up since the authorization server became a
// separate service.
func (s *Service) IssueCredential(ctx context.Context, accessToken, dpopHeader string, body []byte) (oid4vci.CredentialResponse, error) {
	claims, err := s.tokens.Verify(ctx, accessToken)
	if err != nil {
		return oid4vci.CredentialResponse{}, err
	}

	ath := oauth2.ComputeATH(accessToken)
	dpopKey, err := oauth2.ValidateDPoPProof(dpopHeader, "POST", s.baseURL+"/oid4vci/v1/credential", ath, s.jtis)
	if err != nil {
		return oid4vci.CredentialResponse{}, err
	}
	if err := requireBoundThumbprint(claims.JKT, dpopKey, "DPoP key mismatch"); err != nil {
		return oid4vci.CredentialResponse{}, err
	}

	var req oid4vci.CredentialRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return oid4vci.CredentialResponse{}, oauth2.BadRequest(oauth2.InvalidCredentialRequest, "Invalid request body: "+err.Error())
	}

	if req.CredentialConfigurationID == "" && req.CredentialIdentifier == "" {
		return oid4vci.CredentialResponse{}, oauth2.BadRequest(oauth2.InvalidCredentialRequest, "credential_configuration_id or credential_identifier is required")
	}
	if req.CredentialIdentifier != "" {
		return oid4vci.CredentialResponse{}, oauth2.BadRequest(oauth2.UnknownCredentialIdentifier, "Identifier-based credential requests are not supported")
	}
	if req.CredentialConfigurationID != PIDConfigID && req.CredentialConfigurationID != PIDMdocConfigID {
		return oid4vci.CredentialResponse{}, oauth2.BadRequest(oauth2.UnknownCredentialConfiguration, "Unknown credential_configuration_id: "+req.CredentialConfigurationID)
	}

	proofJWT := req.ExtractProofJWT()
	if proofJWT == "" {
		return oid4vci.CredentialResponse{}, oauth2.BadRequest(oauth2.InvalidProof, "proof_type must be jwt")
	}
	walletKey, err := oid4vci.ValidateProofJWT(proofJWT, s.baseURL)
	if err != nil {
		return oid4vci.CredentialResponse{}, err
	}

	if err := s.validateProofNonce(proofJWT, claims.CNonce); err != nil {
		return oid4vci.CredentialResponse{}, err
	}

	issuanceRecordID := claims.IssuanceRecordID
	if issuanceRecordID == "" {
		return oid4vci.CredentialResponse{}, oauth2.BadRequest(oauth2.InvalidRequest, "No issuance record linked to this access token. Use POST /oid4vci/v1/issuance to trigger credential issuance.")
	}
	rec, ok := s.issuances.FindByID(issuanceRecordID)
	if !ok || rec.CredentialData == "" || rec.CredentialData == "{}" {
		return oid4vci.CredentialResponse{}, oauth2.BadRequest(oauth2.InvalidRequest, "Issuance record has no credential data. Provide credential_data when triggering issuance.")
	}

	statusIdx, err := s.statusList.AllocateIdx(issuanceRecordID)
	if err != nil {
		return oid4vci.CredentialResponse{}, oauth2.BadRequest(oauth2.InvalidRequest, "Failed to allocate status list index: "+err.Error())
	}
	statusURI := s.baseURL + "/oid4vci/v1/status-list/" + statusListID

	var credential string
	if req.CredentialConfigurationID == PIDMdocConfigID {
		credential, err = s.buildMdocCredential(walletKey, rec, statusIdx, statusURI)
	} else {
		credential, err = s.buildSDJWTCredential(walletKey, rec, statusIdx, statusURI)
	}
	if err != nil {
		return oid4vci.CredentialResponse{}, oauth2.BadRequest(oauth2.InvalidRequest, "Invalid credential request: "+err.Error())
	}

	s.issuances.UpdateStatus(issuanceRecordID, "credential_issued")
	s.sessions.InvalidateNonce(claims.CNonce)

	return oid4vci.SuccessResponse(credential), nil
}

// requireBoundThumbprint enforces that the presented DPoP proof's key is
// the one the access token was sender-constrained to (RFC 9449 §6.1's
// cnf.jkt) — the pinning that stops a stolen access token being used with
// a different key. boundJKT comes from the verified token's own claims
// now, rather than from a session row shared with the token endpoint.
func requireBoundThumbprint(boundJKT string, presentedKey jwk.Key, mismatchMessage string) error {
	actual, err := oauth2.DPoPThumbprint(presentedKey)
	if err != nil {
		return oauth2.Unauthorized(oauth2.InvalidToken, "DPoP thumbprint verification failed")
	}
	if boundJKT != actual {
		return oauth2.Unauthorized(oauth2.InvalidToken, mismatchMessage)
	}
	return nil
}

// validateProofNonce checks the proof JWT's nonce against either this
// issuer's own single-use nonce store (a nonce handed out by the Nonce
// Endpoint) or the c_nonce the authorization server bound into the access
// token — the two-source check that lets a wallet present its first proof
// without a Nonce Endpoint round trip.
func (s *Service) validateProofNonce(proofJWT, tokenCNonce string) error {
	proofNonce, err := oid4vci.ProofNonce(proofJWT)
	if err != nil || proofNonce == "" {
		return oauth2.BadRequest(oauth2.InvalidNonce, "Proof nonce does not match c_nonce")
	}
	if s.sessions.ValidateNonce(proofNonce) {
		return nil
	}
	if tokenCNonce != "" && proofNonce == tokenCNonce {
		return nil
	}
	return oauth2.BadRequest(oauth2.InvalidNonce, "Proof nonce does not match c_nonce")
}

// GetStatusListToken returns the signed Status List Token JWT for listID
// (only statusListID exists today), rebuilding and re-signing it only
// when the in-process cache has expired or been invalidated by a revoke
// — see statusListCacheTTL.
func (s *Service) GetStatusListToken(listID string) (string, error) {
	if listID != statusListID {
		return "", oauth2.BadRequest(oauth2.InvalidRequest, "Unknown status list: "+listID)
	}

	s.statusCacheMu.Lock()
	defer s.statusCacheMu.Unlock()
	if s.statusCacheToken != "" && time.Now().Before(s.statusCacheExp) {
		return s.statusCacheToken, nil
	}

	entries, err := s.statusList.AllEntries()
	if err != nil {
		return "", oauth2.BadRequest(oauth2.InvalidRequest, "Failed to load status list entries: "+err.Error())
	}
	var size int64
	for idx := range entries {
		if idx+1 > size {
			size = idx + 1
		}
	}

	listURI := s.baseURL + "/oid4vci/v1/status-list/" + statusListID
	token, err := statuslist.Build(entries, size, listURI, s.issuerKey)
	if err != nil {
		return "", oauth2.BadRequest(oauth2.InvalidRequest, "Failed to build status list token: "+err.Error())
	}

	s.statusCacheToken = token
	s.statusCacheExp = time.Now().Add(statusListCacheTTL)
	return token, nil
}

// RevokeCredential marks issuanceRecordID's credential INVALID in the
// status list. Idempotent: revoking an already-revoked credential is a
// no-op success. Fails if the record doesn't exist, isn't actually
// issued yet (draft), or was issued before this feature shipped (no
// status-list entry — a known, accepted limitation, see
// db/schema.sql's status_list_entries doc comment).
func (s *Service) RevokeCredential(issuanceRecordID string) error {
	rec, ok := s.issuances.FindByID(issuanceRecordID)
	if !ok {
		return oauth2.BadRequest(oauth2.InvalidRequest, "Unknown issuance record: "+issuanceRecordID)
	}
	if rec.Status != "credential_issued" {
		return oauth2.BadRequest(oauth2.InvalidRequest, "Only an issued credential can be revoked (current status: "+rec.Status+")")
	}

	_, _, ok = s.statusList.FindByRecordID(issuanceRecordID)
	if !ok {
		return oauth2.BadRequest(oauth2.InvalidRequest, "This credential has no status list entry (issued before revocation support existed) and cannot be revoked")
	}

	if _, ok := s.statusList.SetStatus(issuanceRecordID, StatusInvalid); !ok {
		return oauth2.BadRequest(oauth2.InvalidRequest, "Failed to revoke credential")
	}

	s.statusCacheMu.Lock()
	s.statusCacheToken = ""
	s.statusCacheMu.Unlock()
	return nil
}

// statusClaim builds the IETF Token Status List "status" claim value
// (draft-ietf-oauth-status-list-21 §6.2's {status_list: {idx, uri}}
// shape), shared verbatim between the SD-JWT top-level claim and the
// mdoc namespace element.
func statusClaim(idx int64, uri string) map[string]any {
	return map[string]any{"status_list": map[string]any{"idx": idx, "uri": uri}}
}

func (s *Service) buildSDJWTCredential(walletKey jwk.Key, rec Record, statusIdx int64, statusURI string) (string, error) {
	var claims map[string]any
	if err := json.Unmarshal([]byte(rec.CredentialData), &claims); err != nil {
		return "", fmt.Errorf("parsing credential_data: %w", err)
	}

	builder := sdjwt.NewBuilder(s.issuerKey).
		VCT(pidVCT).
		Issuer(s.baseURL).
		Subject(pidSubjectPrefix + session.RandomToken(8)).
		HolderKey(walletKey).
		X5CChain(s.issuerKey.X5CChain())

	for name, value := range claims {
		builder.SelectiveClaim(name, fmt.Sprintf("%v", value))
	}
	builder.PlainClaim("issuing_authority", "Fikua Lab")
	builder.PlainClaim("issuing_country", "ES")
	builder.PlainClaim("status", statusClaim(statusIdx, statusURI))

	return builder.Build()
}

func (s *Service) buildMdocCredential(walletKey jwk.Key, rec Record, statusIdx int64, statusURI string) (string, error) {
	var claims map[string]any
	if err := json.Unmarshal([]byte(rec.CredentialData), &claims); err != nil {
		return "", fmt.Errorf("parsing credential_data: %w", err)
	}

	builder := mdoc.NewBuilder(s.issuerKey).
		DocType(pidDocType).
		Namespace(pidDocType).
		DeviceKey(walletKey).
		X5CChain(s.issuerKey.X5CChain())

	for name, value := range claims {
		builder.Element(name, fmt.Sprintf("%v", value))
	}
	builder.Element("issuing_authority", "Fikua Lab")
	builder.Element("issuing_country", "ES")
	builder.MapElement("status", statusClaim(statusIdx, statusURI))

	return builder.BuildBase64URL()
}
