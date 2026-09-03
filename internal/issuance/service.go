package issuance

import (
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"

	fikuacrypto "github.com/fikua/fikua-lab-issuer/internal/crypto"
	"github.com/fikua/fikua-lab-issuer/internal/mdoc"
	"github.com/fikua/fikua-lab-issuer/internal/oauth2"
	"github.com/fikua/fikua-lab-issuer/internal/oid4vci"
	"github.com/fikua/fikua-lab-issuer/internal/sdjwt"
	"github.com/fikua/fikua-lab-issuer/internal/session"
)

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

// requestURIPrefix is the PAR request_uri format prefix, per RFC 9126.
const requestURIPrefix = "urn:ietf:params:oauth:request_uri:"

// Service implements this issuer's OID4VCI flow: HAIP only —
// authorization_code grant via PAR, with DPoP sender-constraining and
// ATCA client attestation mandatory throughout, and PKCE (S256)
// mandatory at the token endpoint. There is no plain/pre-authorized_code
// profile — this issuer does not implement one.
type Service struct {
	baseURL      string
	issuerKey    *fikuacrypto.SigningKey
	sessions     *session.Store
	issuances    *Store
	jtis         *oauth2.JTIStore
	attestations *oauth2.ClientAttestationValidator
}

// NewService builds a Service. baseURL is this issuer's own Credential
// Issuer identifier (e.g. "https://issuer.fikua.com"), used as both the
// SD-JWT/mdoc `iss`/docType binding and the expected proof/DPoP JWT
// `aud`/`htu`. walletProviderAnchor optionally pins client-attestation
// (WIA) signature verification to a single trusted CA — pass nil to
// accept any self-consistent WIA (no chain-of-trust check), matching the
// Java issuer's "no root-ca.crt configured" fallback.
func NewService(baseURL string, issuerKey *fikuacrypto.SigningKey, sessions *session.Store, issuances *Store, walletProviderAnchor *x509.Certificate) *Service {
	return &Service{
		baseURL:      baseURL,
		issuerKey:    issuerKey,
		sessions:     sessions,
		issuances:    issuances,
		jtis:         oauth2.NewJTIStore(),
		attestations: oauth2.NewClientAttestationValidator(walletProviderAnchor),
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
	IssuanceID      string `json:"issuance_id"`
	CredentialOffer any    `json:"credential_offer"`
}

// TriggerIssuance creates an issuance record and an authorization_code
// credential offer carrying an issuer_state that links the wallet's
// later /authorize (via PAR) back to this record.
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
	s.issuances.UpdateStatus(rec.ID, "offer_created")

	return TriggerIssuanceResult{IssuanceID: rec.ID, CredentialOffer: offer}, nil
}

// HandlePar implements the Pushed Authorization Request endpoint (RFC
// 9126). Client attestation is mandatory; code_challenge_method, if
// given, must be S256. Returns the request_uri and its (advertised, not
// server-enforced — see the migration notes) 60s lifetime.
func (s *Service) HandlePar(params map[string]string, wiaHeader, popHeader string) (requestURI string, expiresIn int, err error) {
	clientID, attErr := s.attestations.Resolve(wiaHeader, popHeader, params["client_assertion_type"], params["client_assertion"])
	if attErr != nil {
		return "", 0, attErr
	}
	if clientID == "" {
		return "", 0, oauth2.BadRequest(oauth2.InvalidRequest, "Client attestation is required")
	}

	if method, ok := params["code_challenge_method"]; ok && method != "S256" {
		return "", 0, oauth2.BadRequest(oauth2.InvalidRequest, "Only S256 code_challenge_method is supported")
	}

	requestURI = requestURIPrefix + session.RandomToken(16)
	s.sessions.StoreParRequest(requestURI, params)
	return requestURI, 60, nil
}

// AuthorizeResult is the outcome of GET /oid4vci/v1/authorize.
type AuthorizeResult struct {
	Code        string
	RedirectURI string
	State       string
}

// HandleAuthorize resolves a PAR request_uri into an authorization code,
// bound to the issuance record referenced by the PAR params' issuer_state
// (set by TriggerIssuance's offer). Only the client_id-bearing,
// PAR-backed flow is implemented — this issuer has no client_id-less
// wallet-initiated sub-flow.
func (s *Service) HandleAuthorize(requestURI string) (AuthorizeResult, error) {
	if requestURI == "" {
		return AuthorizeResult{}, oauth2.BadRequest(oauth2.InvalidRequest, "Missing request_uri")
	}
	params, ok := s.sessions.ConsumeParRequest(requestURI)
	if !ok {
		return AuthorizeResult{}, oauth2.BadRequest(oauth2.InvalidRequest, "Invalid or expired request_uri")
	}

	metadata := map[string]any{}
	if codeChallenge := params["code_challenge"]; codeChallenge != "" {
		metadata["code_challenge"] = codeChallenge
	}
	if issuerState := params["issuer_state"]; issuerState != "" {
		if rec, ok := s.issuances.FindByIssuerState(issuerState); ok {
			metadata["issuanceRecordId"] = rec.ID
		}
	}

	sess := session.Data{SessionID: session.RandomToken(16), Metadata: metadata}
	code := s.sessions.CreateAuthCode(sess)

	return AuthorizeResult{Code: code, RedirectURI: params["redirect_uri"], State: params["state"]}, nil
}

// HandleAuthCodeToken implements the authorization_code grant at the
// token endpoint: client attestation and DPoP are validated, then the
// authorization code is consumed (irrecoverably — a subsequent PKCE
// failure does not un-consume it, matching upstream), then PKCE S256 is
// verified before minting a DPoP-bound access token.
func (s *Service) HandleAuthCodeToken(req oauth2.TokenRequest, dpopHeader, wiaHeader, popHeader string) (oauth2.TokenResponse, error) {
	clientID, attErr := s.attestations.Resolve(wiaHeader, popHeader, "", "")
	if attErr != nil {
		return oauth2.TokenResponse{}, attErr
	}
	if clientID == "" {
		return oauth2.TokenResponse{}, oauth2.BadRequest(oauth2.InvalidRequest, "Client attestation is required")
	}

	dpopKey, err := oauth2.ValidateDPoPProof(dpopHeader, "POST", s.baseURL+"/oid4vci/v1/token", "", s.jtis)
	if err != nil {
		return oauth2.TokenResponse{}, err
	}

	if req.Code == "" {
		return oauth2.TokenResponse{}, oauth2.BadRequest(oauth2.InvalidGrant, "Missing authorization code")
	}
	sess, ok := s.sessions.ConsumeAuthCode(req.Code)
	if !ok {
		return oauth2.TokenResponse{}, oauth2.BadRequest(oauth2.InvalidGrant, "Invalid authorization code")
	}

	if req.CodeVerifier == "" {
		return oauth2.TokenResponse{}, oauth2.BadRequest(oauth2.InvalidRequest, "Missing code_verifier")
	}
	storedChallenge, _ := sess.Metadata["code_challenge"].(string)
	if storedChallenge == "" || !oauth2.VerifyPKCES256(req.CodeVerifier, storedChallenge) {
		return oauth2.TokenResponse{}, oauth2.BadRequest(oauth2.InvalidGrant, "PKCE verification failed")
	}

	cNonce := session.GenerateNonce()
	s.sessions.RegisterNonce(cNonce)

	tokenSession := session.Data{SessionID: sess.SessionID, CNonce: cNonce, DPoPKey: dpopKey, Metadata: sess.Metadata}
	accessToken := s.sessions.CreateAccessToken(tokenSession)

	return oauth2.DPoPToken(accessToken), nil
}

// GenerateNonce implements the nonce endpoint. A fresh nonce is always
// registered globally; if accessToken identifies a session, DPoP is
// validated (mandatory whenever a session exists — this issuer does not
// silently skip DPoP when the header is missing, unlike the Java
// implementation it was ported from) and the session's cNonce is
// updated.
func (s *Service) GenerateNonce(accessToken, dpopHeader string) (string, error) {
	nonce := session.GenerateNonce()
	s.sessions.RegisterNonce(nonce)

	if accessToken != "" {
		sess, ok := s.sessions.GetAccessTokenSession(accessToken)
		if ok {
			ath := oauth2.ComputeATH(accessToken)
			dpopKey, err := oauth2.ValidateDPoPProof(dpopHeader, "POST", s.baseURL+"/oid4vci/v1/nonce", ath, s.jtis)
			if err != nil {
				return "", err
			}
			if err := requireMatchingThumbprint(sess.DPoPKey, dpopKey, "DPoP key mismatch at nonce endpoint"); err != nil {
				return "", err
			}
			sess.CNonce = nonce
			s.sessions.UpdateAccessTokenSession(accessToken, sess)
		}
	}
	return nonce, nil
}

// IssueCredential implements the credential endpoint.
func (s *Service) IssueCredential(accessToken, dpopHeader string, body []byte) (oid4vci.CredentialResponse, error) {
	sess, ok := s.sessions.GetAccessTokenSession(accessToken)
	if !ok {
		return oid4vci.CredentialResponse{}, oauth2.Unauthorized(oauth2.InvalidToken, "Invalid access token")
	}

	ath := oauth2.ComputeATH(accessToken)
	dpopKey, err := oauth2.ValidateDPoPProof(dpopHeader, "POST", s.baseURL+"/oid4vci/v1/credential", ath, s.jtis)
	if err != nil {
		return oid4vci.CredentialResponse{}, err
	}
	if err := requireMatchingThumbprint(sess.DPoPKey, dpopKey, "DPoP key mismatch"); err != nil {
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

	if err := s.validateProofNonce(proofJWT, sess); err != nil {
		return oid4vci.CredentialResponse{}, err
	}

	issuanceRecordID, _ := sess.Metadata["issuanceRecordId"].(string)
	if issuanceRecordID == "" {
		return oid4vci.CredentialResponse{}, oauth2.BadRequest(oauth2.InvalidRequest, "No issuance record linked to this session. Use POST /oid4vci/v1/issuance to trigger credential issuance.")
	}
	rec, ok := s.issuances.FindByID(issuanceRecordID)
	if !ok || rec.CredentialData == "" || rec.CredentialData == "{}" {
		return oid4vci.CredentialResponse{}, oauth2.BadRequest(oauth2.InvalidRequest, "Issuance record has no credential data. Provide credential_data when triggering issuance.")
	}

	var credential string
	if req.CredentialConfigurationID == PIDMdocConfigID {
		credential, err = s.buildMdocCredential(walletKey, rec)
	} else {
		credential, err = s.buildSDJWTCredential(walletKey, rec)
	}
	if err != nil {
		return oid4vci.CredentialResponse{}, oauth2.BadRequest(oauth2.InvalidRequest, "Invalid credential request: "+err.Error())
	}

	s.issuances.UpdateStatus(issuanceRecordID, "credential_issued")
	s.sessions.InvalidateNonce(sess.CNonce)

	return oid4vci.SuccessResponse(credential), nil
}

// requireMatchingThumbprint enforces that dpopKey's RFC 7638 thumbprint
// matches the one originally bound to the session at /token — the
// pinning this issuer relies on to stop a stolen access token being used
// with a different DPoP key. boundKey is nil if the session predates any
// DPoP binding (shouldn't happen in this HAIP-only issuer, but guarded
// defensively).
func requireMatchingThumbprint(boundKey, presentedKey jwk.Key, mismatchMessage string) error {
	if boundKey == nil {
		return nil
	}
	expected, err := oauth2.DPoPThumbprint(boundKey)
	if err != nil {
		return oauth2.Unauthorized(oauth2.InvalidToken, "DPoP thumbprint verification failed")
	}
	actual, err := oauth2.DPoPThumbprint(presentedKey)
	if err != nil {
		return oauth2.Unauthorized(oauth2.InvalidToken, "DPoP thumbprint verification failed")
	}
	if expected != actual {
		return oauth2.Unauthorized(oauth2.InvalidToken, mismatchMessage)
	}
	return nil
}

// validateProofNonce checks the proof JWT's nonce against either the
// global single-use nonce store or, as a fallback, the token-endpoint
// session's own cNonce — matching the Java issuer's two-source check.
func (s *Service) validateProofNonce(proofJWT string, sess session.Data) error {
	proofNonce, err := oid4vci.ProofNonce(proofJWT)
	if err != nil || proofNonce == "" {
		return oauth2.BadRequest(oauth2.InvalidNonce, "Proof nonce does not match c_nonce")
	}
	if s.sessions.ValidateNonce(proofNonce) {
		return nil
	}
	if proofNonce == sess.CNonce {
		return nil
	}
	return oauth2.BadRequest(oauth2.InvalidNonce, "Proof nonce does not match c_nonce")
}

func (s *Service) buildSDJWTCredential(walletKey jwk.Key, rec Record) (string, error) {
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

	return builder.Build()
}

func (s *Service) buildMdocCredential(walletKey jwk.Key, rec Record) (string, error) {
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

	return builder.BuildBase64URL()
}
