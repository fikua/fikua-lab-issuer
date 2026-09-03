package issuance

import (
	"crypto/rand"
	"encoding/binary"
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
// this slice issues — Student ID is not carried over from the Java issuer
// (see the migration plan), and authorization_code/HAIP/PAR/DPoP land in
// later slices. PIDMdocConfigID matches credentialconfig's
// configurationID naming (scheme id + ".mdoc" suffix for the mdoc format).
const (
	PIDConfigID     = "urn:eudi:pid:1"
	PIDMdocConfigID = "urn:eudi:pid:1.mdoc"
)

const (
	pidVCT           = "urn:eudi:pid:1"
	pidDocType       = "eu.europa.ec.eudi.pid.1"
	pidSubjectPrefix = "urn:fikua:pid:"
)

// Service implements the pre-authorized_code OID4VCI flow and SD-JWT PID
// issuance — a direct port of the Java issuer's IssuanceService, scoped to
// this slice (no DPoP, no PAR, no client attestation, no mdoc).
type Service struct {
	baseURL   string
	issuerKey *fikuacrypto.SigningKey
	sessions  *session.Store
	issuances *Store
}

// NewService builds a Service. baseURL is this issuer's own Credential
// Issuer identifier (e.g. "https://issuer.fikua.com"), used as both the
// SD-JWT `iss` claim and the expected proof JWT `aud`.
func NewService(baseURL string, issuerKey *fikuacrypto.SigningKey, sessions *session.Store, issuances *Store) *Service {
	return &Service{baseURL: baseURL, issuerKey: issuerKey, sessions: sessions, issuances: issuances}
}

// TriggerIssuanceRequest is the POST /oid4vci/v1/issuance request body,
// scoped to this slice's pre-authorized_code-only path.
type TriggerIssuanceRequest struct {
	CredentialType string         `json:"credential_type"`
	CredentialData map[string]any `json:"credential_data"`
	SourceType     string         `json:"source_type"`
	SourceRef      string         `json:"source_ref"`
	TxCodeRequired bool           `json:"tx_code_required"`
}

// TriggerIssuanceResult is the POST /oid4vci/v1/issuance response body.
type TriggerIssuanceResult struct {
	IssuanceID      string `json:"issuance_id"`
	TxCode          string `json:"tx_code,omitempty"`
	CredentialOffer any    `json:"credential_offer,omitempty"`
}

// TriggerIssuance creates an issuance record and a pre-authorized_code
// credential offer for it — the pre-authorized_code branch of the Java
// issuer's triggerIssuance (authorization_code/HAIP is a later slice, so
// this slice always takes this branch).
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

	metadata := map[string]any{"issuanceRecordId": rec.ID}
	var txCode string
	if req.TxCodeRequired {
		txCode = generateTxCode()
		metadata["tx_code"] = txCode
	}

	sess := session.Data{SessionID: session.RandomToken(16), Metadata: metadata}
	preAuthCode := s.sessions.CreatePreAuthCode(sess)
	s.issuances.UpdatePreAuthCode(rec.ID, preAuthCode)

	offer := oid4vci.PreAuthorizedOffer(s.baseURL, credentialType, preAuthCode, req.TxCodeRequired)
	s.issuances.UpdateStatus(rec.ID, "offer_created")

	result := TriggerIssuanceResult{IssuanceID: rec.ID, CredentialOffer: offer}
	if txCode != "" {
		result.TxCode = txCode
		s.issuances.UpdateTxCode(rec.ID, txCode)
	}
	return result, nil
}

// HandlePreAuthToken implements the pre-authorized_code grant at the token
// endpoint.
func (s *Service) HandlePreAuthToken(req oauth2.TokenRequest) (oauth2.TokenResponse, error) {
	if req.PreAuthorizedCode == "" {
		return oauth2.TokenResponse{}, oauth2.BadRequest(oauth2.InvalidGrant, "Missing pre-authorized_code")
	}
	sess, ok := s.sessions.ConsumePreAuthCode(req.PreAuthorizedCode)
	if !ok {
		return oauth2.TokenResponse{}, oauth2.BadRequest(oauth2.InvalidGrant, "Invalid or expired pre-authorized_code")
	}

	if expected, hasTxCode := sess.Metadata["tx_code"].(string); hasTxCode {
		if req.TxCode == "" || req.TxCode != expected {
			return oauth2.TokenResponse{}, oauth2.BadRequest(oauth2.InvalidGrant, "Invalid or missing tx_code")
		}
	}

	cNonce := session.GenerateNonce()
	s.sessions.RegisterNonce(cNonce)

	tokenSession := session.Data{SessionID: sess.SessionID, CNonce: cNonce, Metadata: sess.Metadata}
	accessToken := s.sessions.CreateAccessToken(tokenSession)

	return oauth2.BearerToken(accessToken), nil
}

// GenerateNonce implements the nonce endpoint: it always registers a fresh
// nonce in the global store, and additionally binds it to accessToken's
// session as that session's cNonce when a valid access token is given.
func (s *Service) GenerateNonce(accessToken string) string {
	nonce := session.GenerateNonce()
	s.sessions.RegisterNonce(nonce)
	if accessToken != "" {
		if sess, ok := s.sessions.GetAccessTokenSession(accessToken); ok {
			sess.CNonce = nonce
			s.sessions.UpdateAccessTokenSession(accessToken, sess)
		}
	}
	return nonce
}

// IssueCredential implements the credential endpoint for the
// pre-authorized_code + PID sd-jwt path.
func (s *Service) IssueCredential(accessToken string, body []byte) (oid4vci.CredentialResponse, error) {
	sess, ok := s.sessions.GetAccessTokenSession(accessToken)
	if !ok {
		return oid4vci.CredentialResponse{}, oauth2.Unauthorized(oauth2.InvalidToken, "Invalid access token")
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

// generateTxCode returns a uniformly random 6-digit numeric string
// ("100000"–"999999"), matching the Java issuer's generateTxCode.
func generateTxCode() string {
	var buf [4]byte
	_, _ = rand.Read(buf[:])
	n := binary.BigEndian.Uint32(buf[:]) % 900000
	return fmt.Sprintf("%06d", 100000+n)
}
