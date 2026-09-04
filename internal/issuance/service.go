package issuance

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"

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

// boundClientIDKey is the internal (non-spec) key used to carry the
// attested client_id that made a PAR request through to the resulting
// authorization code's session metadata — see HandlePar's doc comment.
const boundClientIDKey = "_bound_client_id"

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
	baseURL         string
	identifyBaseURL string
	issuerKey       *fikuacrypto.SigningKey
	sessions        *session.Store
	issuances       RecordStore
	statusList      StatusListStore
	jtis            *oauth2.JTIStore
	attestations    *oauth2.ClientAttestationValidator

	statusCacheMu    sync.Mutex
	statusCacheToken string
	statusCacheExp   time.Time
}

// NewService builds a Service. baseURL is this issuer's own Credential
// Issuer identifier (e.g. "https://issuer.fikua.com"), used as both the
// SD-JWT/mdoc `iss`/docType binding and the expected proof/DPoP JWT
// `aud`/`htu`. walletProviderAnchor optionally pins client-attestation
// (WIA) signature verification to a single trusted CA — pass nil to
// accept any self-consistent WIA (no chain-of-trust check), matching the
// Java issuer's "no root-ca.crt configured" fallback. issuances is either
// the in-memory Store (dev/no-Postgres fallback) or a PostgresStore.
// statusList is the same underlying store, typed as StatusListStore — see
// cmd/issuer/main.go's wiring. identifyBaseURL, if non-empty, is where
// HandleAuthorize redirects for real end-user identification instead of
// synthesizing PID data — see IdentifyBaseURL's doc comment in
// internal/config.
func NewService(baseURL string, identifyBaseURL string, issuerKey *fikuacrypto.SigningKey, sessions *session.Store, issuances RecordStore, statusList StatusListStore, walletProviderAnchor *x509.Certificate) *Service {
	return &Service{
		baseURL:         baseURL,
		identifyBaseURL: identifyBaseURL,
		issuerKey:       issuerKey,
		sessions:        sessions,
		issuances:       issuances,
		statusList:      statusList,
		jtis:            oauth2.NewJTIStore(),
		attestations:    oauth2.NewClientAttestationValidator(walletProviderAnchor, baseURL),
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

// BuildAuthorizationRedirect adds the authorization response params
// (code, state, iss) to result.RedirectURI. Registered redirect_uris can
// already carry their own query string (RFC 6749 §3.1.2 explicitly
// allows this — the OIDF conformance suite's "matching callback
// parameters" test registers one with ?dummy1=lorem&dummy2=ipsum and
// requires it survive intact), so this must merge into any existing
// query rather than always starting a fresh "?". Shared by the httpapi
// layer's /authorize 302 and CompleteIdentification's JSON redirect
// field — both produce the exact same URL shape.
func BuildAuthorizationRedirect(result AuthorizeResult, issuer string) (string, error) {
	u, err := url.Parse(result.RedirectURI)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("code", result.Code)
	if result.State != "" {
		q.Set("state", result.State)
	}
	q.Set("iss", issuer)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// HandlePar implements the Pushed Authorization Request endpoint (RFC
// 9126). Client attestation is mandatory; code_challenge_method, if
// given, must be S256. Returns the request_uri and its (advertised, not
// server-enforced — see the migration notes) 60s lifetime.
//
// DPoP-PAR binding (RFC 9449 §10.1): a client may bind the eventual
// authorization code to a DPoP key either by sending a dpop_jkt form
// parameter, or by attaching a DPoP proof to the PAR request itself
// (in which case the proof's key thumbprint is treated as if it were
// dpop_jkt). Both mechanisms must be supported, and if both are used at
// once, the thumbprints must match — the resolved thumbprint, whichever
// path it came from, is stored on the PAR params under "dpop_jkt" so
// HandleAuthCodeToken can enforce it against the token endpoint's own
// DPoP proof later.
func (s *Service) HandlePar(params map[string]string, wiaHeader, popHeader, dpopHeader string) (requestURI string, expiresIn int, err error) {
	// RFC 9126 §2.1: request_uri is the one authorization-endpoint
	// parameter a pushed authorization request MUST NOT carry — it's
	// what this endpoint produces, not something a client can push in.
	if params["request_uri"] != "" {
		return "", 0, oauth2.BadRequest(oauth2.InvalidRequest, "request_uri must not be provided in a pushed authorization request")
	}

	clientID, attErr := s.attestations.Resolve(wiaHeader, popHeader, params["client_assertion_type"], params["client_assertion"])
	if attErr != nil {
		return "", 0, attErr
	}
	if clientID == "" {
		return "", 0, oauth2.BadRequest(oauth2.InvalidRequest, "Client attestation is required")
	}
	// Bound to the authorization code at /authorize time and re-checked
	// against the /token endpoint's own client attestation in
	// HandleAuthCodeToken (RFC 6749 §4.1.3: the token endpoint must
	// reject a code presented by a client other than the one it was
	// issued to). boundClientID isn't a real OAuth2 param — it's an
	// internal key on the same params map that rides along through
	// StoreParRequest/StorePendingAuth to CreateAuthCode's session
	// metadata.
	params[boundClientIDKey] = clientID

	// FAPI 2.0 Security Profile §5.3.2.2-1: only the authorization_code
	// flow (response_type=code) is permitted — code id_token and other
	// hybrid/implicit response types would return an id_token via the
	// browser, where it can leak.
	if responseType, ok := params["response_type"]; ok && responseType != "code" {
		return "", 0, oauth2.BadRequest(oauth2.UnsupportedResponseType, "Only response_type=code is supported")
	}

	// FAPI 2.0 Security Profile §5.3.2.2-5 / RFC 7636: PKCE is mandatory,
	// not merely validated when present.
	if params["code_challenge"] == "" {
		return "", 0, oauth2.BadRequest(oauth2.InvalidRequest, "code_challenge is required")
	}
	if method := params["code_challenge_method"]; method != "S256" {
		return "", 0, oauth2.BadRequest(oauth2.InvalidRequest, "Only S256 code_challenge_method is supported")
	}

	if dpopHeader != "" {
		dpopKey, err := oauth2.ValidateDPoPProof(dpopHeader, "POST", s.baseURL+"/oid4vci/v1/par", "", s.jtis)
		if err != nil {
			return "", 0, err
		}
		thumbprint, err := oauth2.DPoPThumbprint(dpopKey)
		if err != nil {
			return "", 0, oauth2.BadRequest(oauth2.InvalidRequest, "Failed to compute DPoP thumbprint: "+err.Error())
		}
		if declared := params["dpop_jkt"]; declared != "" && declared != thumbprint {
			return "", 0, oauth2.BadRequest(oauth2.InvalidRequest, "dpop_jkt does not match the DPoP proof's key")
		}
		params["dpop_jkt"] = thumbprint
	}

	requestURI = requestURIPrefix + session.RandomToken(16)
	s.sessions.StoreParRequest(requestURI, params)
	return requestURI, 60, nil
}

// AuthorizeResult is the outcome of GET /oid4vci/v1/authorize. Exactly
// one of two shapes applies: IdentifyRedirect non-empty means "302 the
// browser here instead, ignore the rest" (deferring to the end-user
// identification flow); otherwise Code/RedirectURI/State carry the
// completed OAuth2 authorization response.
type AuthorizeResult struct {
	Code             string
	RedirectURI      string
	State            string
	IdentifyRedirect string
}

// defaultPIDCredentialData is the synthetic PID data used when
// /authorize has no issuance record to bind to — see HandleAuthorize's
// doc comment for why that happens and why this is the right fallback
// for a lab/conformance-testing issuer. Matches the UI's own "Fill test
// data" defaults (web/static/app.js's DEFAULT_DATA).
var defaultPIDCredentialData = map[string]any{
	"given_name":  "Max",
	"family_name": "Mustermann",
	"birth_date":  "1990-06-15",
}

// HandleAuthorize resolves a PAR request_uri into an authorization code,
// bound to the issuance record referenced by the PAR params' issuer_state
// (set by TriggerIssuance's offer). Only the client_id-bearing,
// PAR-backed flow is implemented — this issuer has no client_id-less
// wallet-initiated sub-flow.
//
// A real issuer would authenticate the end-user interactively at this
// endpoint (per OID4VCI's authorization_code flow) and derive the
// credential data from that identity check. When no issuer_state
// resolves an existing issuance record, this now has two possible
// behaviors:
//
//   - identifyBaseURL configured: defer to the real end-user
//     identification flow (see ResolveIdentifyScope/CompleteIdentification)
//     by minting a pending-authorization token and returning
//     AuthorizeResult.IdentifyRedirect — the httpapi layer 302s the
//     browser there instead of completing the OAuth2 response here.
//   - identifyBaseURL unset (the default): fall back to synthesizing PID
//     data, exactly as before. Kept specifically because the OIDF
//     conformance suite's automated client cannot complete an
//     interactive identification form — see defaultPIDCredentialData.
//
// A spec-conformant wallet/test client has no reason to know about
// issuer_state as an out-of-band mechanism at all: it may reuse a
// credential_offer's issuer_state for a second authorization (e.g. a
// conformance test exercising two OAuth2 clients against the same
// offer), or send a completely fresh authorization request with no
// issuer_state. Either case hits the same two-way branch above.
//
// queryClientID, if non-empty, is the client_id query parameter this
// GET request itself carried (distinct from the PAR-time client_id that
// minted requestURI). PAR §2.2 requires a request_uri be bound to the
// client that pushed it — RFC 9126's PAR-3-3 conformance check catches
// exactly this: presenting client A's request_uri while claiming to be
// client B.
func (s *Service) HandleAuthorize(requestURI, queryClientID string) (AuthorizeResult, error) {
	if requestURI == "" {
		return AuthorizeResult{}, oauth2.BadRequest(oauth2.InvalidRequest, "Missing request_uri")
	}
	params, ok := s.sessions.ConsumeParRequest(requestURI)
	if !ok {
		return AuthorizeResult{}, oauth2.BadRequest(oauth2.InvalidRequest, "Invalid or expired request_uri")
	}
	if queryClientID != "" && params["client_id"] != "" && queryClientID != params["client_id"] {
		return AuthorizeResult{}, oauth2.BadRequest(oauth2.InvalidRequest, "request_uri is bound to a different client")
	}

	var rec Record
	var foundRecord bool
	if issuerState := params["issuer_state"]; issuerState != "" {
		rec, foundRecord = s.issuances.FindByIssuerState(issuerState)
	}
	if !foundRecord && s.identifyBaseURL != "" {
		token := s.sessions.StorePendingAuth(params)
		return AuthorizeResult{IdentifyRedirect: s.identifyBaseURL + "?session=" + token}, nil
	}
	if !foundRecord {
		credentialDataJSON, err := json.Marshal(defaultPIDCredentialData)
		if err != nil {
			return AuthorizeResult{}, oauth2.BadRequest(oauth2.InvalidRequest, "Failed to build default credential data: "+err.Error())
		}
		rec = s.issuances.Create(PIDConfigID, string(credentialDataJSON), "conformance_test", "auto-created at /authorize (no issuer_state)")
		s.issuances.UpdateStatus(rec.ID, "offer_created")
	}

	metadata := map[string]any{"issuanceRecordId": rec.ID, boundClientIDKey: params[boundClientIDKey]}
	if codeChallenge := params["code_challenge"]; codeChallenge != "" {
		metadata["code_challenge"] = codeChallenge
	}
	if dpopJKT := params["dpop_jkt"]; dpopJKT != "" {
		metadata["dpop_jkt"] = dpopJKT
	}

	sess := session.Data{SessionID: session.RandomToken(16), Metadata: metadata}
	code := s.sessions.CreateAuthCode(sess)

	return AuthorizeResult{Code: code, RedirectURI: params["redirect_uri"], State: params["state"]}, nil
}

// ResolveIdentifyScope is a non-destructive lookup for GET
// /identify/claims: given a pending-authorization session token (minted
// by HandleAuthorize's identify-redirect branch), returns the
// credential_configuration_id the identification form should collect
// claims for. This issuer only ever issues PID, so it's always
// PIDConfigID today — kept as a method (not a constant) so a future
// scope-to-config mapping has one place to live if this issuer ever
// grows a second credential type reachable via wallet-initiated auth.
func (s *Service) ResolveIdentifyScope(sessionToken string) (credentialConfigID string, err error) {
	if _, ok := s.sessions.GetPendingAuth(sessionToken); !ok {
		return "", oauth2.BadRequest(oauth2.InvalidRequest, "Invalid or expired identification session")
	}
	return PIDConfigID, nil
}

// CompleteIdentification implements POST /identify/complete: it turns a
// completed identification form into the same OAuth2 authorization
// response HandleAuthorize's normal path produces, resuming the flow
// that was deferred to the identify redirect.
//
// Replay-safe for identifyReplayTTL: a retried POST for the same
// session (double form submit, flaky network) gets back the exact same
// redirect instead of "invalid or expired session", since the
// pending-authorization token itself is consumed destructively
// (single-use) on the first successful call.
func (s *Service) CompleteIdentification(sessionToken string, credentialData map[string]any, sourceType, sourceRef string) (redirect string, err error) {
	if cached, ok := s.sessions.GetIdentifyReplay(sessionToken); ok {
		return cached, nil
	}

	params, ok := s.sessions.ConsumePendingAuth(sessionToken)
	if !ok {
		return "", oauth2.BadRequest(oauth2.InvalidRequest, "Invalid or expired identification session")
	}

	credentialDataJSON, err := json.Marshal(credentialData)
	if err != nil {
		return "", oauth2.BadRequest(oauth2.InvalidRequest, "Invalid credential_data: "+err.Error())
	}
	rec := s.issuances.Create(PIDConfigID, string(credentialDataJSON), sourceType, sourceRef)
	s.issuances.UpdateStatus(rec.ID, "offer_created")

	metadata := map[string]any{"issuanceRecordId": rec.ID, boundClientIDKey: params[boundClientIDKey]}
	if codeChallenge := params["code_challenge"]; codeChallenge != "" {
		metadata["code_challenge"] = codeChallenge
	}
	if dpopJKT := params["dpop_jkt"]; dpopJKT != "" {
		metadata["dpop_jkt"] = dpopJKT
	}
	sess := session.Data{SessionID: session.RandomToken(16), Metadata: metadata}
	code := s.sessions.CreateAuthCode(sess)

	result := AuthorizeResult{Code: code, RedirectURI: params["redirect_uri"], State: params["state"]}
	redirect, err = BuildAuthorizationRedirect(result, s.baseURL)
	if err != nil {
		return "", oauth2.BadRequest(oauth2.InvalidRequest, "Invalid redirect_uri: "+err.Error())
	}

	s.sessions.StoreIdentifyReplay(sessionToken, redirect)
	return redirect, nil
}

// RejectIdentification implements the user-cancels-authentication path:
// per RFC 6749 §4.1.2.1, when the resource owner denies the request, the
// authorization server redirects back to redirect_uri with
// error=access_denied (never a JSON error body — the client is waiting
// on a redirect, exactly like the success path). No issuance record is
// created. Replay-safe the same way CompleteIdentification is, and
// shares its replay cache — a session can be completed or rejected, but
// not both, and either outcome replays identically on a retried POST.
func (s *Service) RejectIdentification(sessionToken string) (redirect string, err error) {
	if cached, ok := s.sessions.GetIdentifyReplay(sessionToken); ok {
		return cached, nil
	}

	params, ok := s.sessions.ConsumePendingAuth(sessionToken)
	if !ok {
		return "", oauth2.BadRequest(oauth2.InvalidRequest, "Invalid or expired identification session")
	}

	u, err := url.Parse(params["redirect_uri"])
	if err != nil {
		return "", oauth2.BadRequest(oauth2.InvalidRequest, "Invalid redirect_uri: "+err.Error())
	}
	q := u.Query()
	q.Set("error", "access_denied")
	q.Set("error_description", "The end-user denied the authorization request")
	if params["state"] != "" {
		q.Set("state", params["state"])
	}
	u.RawQuery = q.Encode()
	redirect = u.String()

	s.sessions.StoreIdentifyReplay(sessionToken, redirect)
	return redirect, nil
}

// HandleAuthCodeToken implements the authorization_code grant at the
// token endpoint: client attestation and DPoP are validated, then the
// authorization code is consumed (irrecoverably — a subsequent PKCE
// failure does not un-consume it, matching upstream), then PKCE S256 is
// verified before minting a DPoP-bound access token.
func (s *Service) HandleAuthCodeToken(req oauth2.TokenRequest, dpopHeader, wiaHeader, popHeader string) (oauth2.TokenResponse, error) {
	// Resolve tries the header transport first (wiaHeader/popHeader), then
	// falls back to the request's own form-based assertion — mirroring
	// HandlePar's same precedence, so a client authenticating via
	// client_assertion/client_assertion_type at /token (instead of the
	// OAuth-Client-Attestation headers) is no longer silently ignored.
	clientID, attErr := s.attestations.Resolve(wiaHeader, popHeader, req.ClientAssertionType, req.ClientAssertion)
	if attErr != nil {
		return oauth2.TokenResponse{}, attErr
	}
	if clientID == "" {
		return oauth2.TokenResponse{}, oauth2.BadRequest(oauth2.InvalidRequest, "Client attestation is required")
	}
	// RFC 6749 §5.2: an explicit client_id form parameter naming a
	// different client than the one this request's attestation
	// authenticates must be rejected — this issuer doesn't use client_id
	// for authentication, but a mismatch here means the caller is trying
	// to claim an identity its attestation doesn't back.
	if req.ClientID != "" && req.ClientID != clientID {
		return oauth2.TokenResponse{}, oauth2.Unauthorized(oauth2.InvalidClient, "client_id does not match the attested client")
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

	// Authorization code binding to client (RFC 6749 §4.1.3): the client
	// presenting the code at /token must be the same one the PAR/authorize
	// request came from — not merely any client with valid attestation.
	if boundClientID, _ := sess.Metadata[boundClientIDKey].(string); boundClientID != "" && boundClientID != clientID {
		return oauth2.TokenResponse{}, oauth2.BadRequest(oauth2.InvalidGrant, "Authorization code was not issued to this client")
	}

	// DPoP-PAR binding (RFC 9449 §10.1): if a dpop_jkt was bound to this
	// authorization at PAR time, the token endpoint's own DPoP proof must
	// be for that exact key.
	if boundJKT, _ := sess.Metadata["dpop_jkt"].(string); boundJKT != "" {
		thumbprint, err := oauth2.DPoPThumbprint(dpopKey)
		if err != nil || thumbprint != boundJKT {
			return oauth2.TokenResponse{}, oauth2.BadRequest(oauth2.InvalidGrant, "DPoP proof key does not match the one bound at the PAR endpoint")
		}
	}

	// RFC 7636 §4.6: a missing code_verifier is a PKCE verification
	// failure like any other, and must be reported the same way
	// (invalid_grant) — not invalid_request, which the OIDF conformance
	// suite (RFC6749-5.2/RFC7636-4.6) treats as a distinct, wrong error.
	if req.CodeVerifier == "" {
		return oauth2.TokenResponse{}, oauth2.BadRequest(oauth2.InvalidGrant, "Missing code_verifier")
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
