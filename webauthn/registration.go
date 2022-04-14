package webauthn

import (
	"bytes"
	"encoding/base64"

	"github.com/Gaukas/webauthn/protocol"
	"github.com/Gaukas/webauthn/protocol/webauthncose"
)

type RegistrationRequest struct {
	session                   *SessionData                        // A server implementation should save this for verification
	credentialCreationOptions *protocol.CredentialCreationOptions // A server implementation should send this to the client
}

func (rr *RegistrationRequest) Session() *SessionData {
	return rr.session
}

func (rr *RegistrationRequest) CredentialCreationOptions() *protocol.CredentialCreationOptions {
	return rr.credentialCreationOptions
}

type RegistrationOption func(*protocol.PublicKeyCredentialCreationOptions)

// Generate a new set of registration data to be sent to the client and authenticator.
func (webauthn *WebAuthn) Register(user User, opts ...RegistrationOption) (*RegistrationRequest, error) {
	challenge, err := protocol.CreateChallenge()
	if err != nil {
		return nil, err
	}

	webAuthnUser := protocol.UserEntity{
		ID:          user.WebAuthnID(),
		DisplayName: user.WebAuthnDisplayName(),
		CredentialEntity: protocol.CredentialEntity{
			Name: user.WebAuthnName(),
			Icon: user.WebAuthnIcon(),
		},
	}

	relyingParty := protocol.RelyingPartyEntity{
		ID: webauthn.Config.RPID,
		CredentialEntity: protocol.CredentialEntity{
			Name: webauthn.Config.RPDisplayName,
			Icon: webauthn.Config.RPIcon,
		},
	}

	credentialParams := defaultRegistrationCredentialParameters()

	creationOptions := protocol.PublicKeyCredentialCreationOptions{
		Challenge:              challenge,
		RelyingParty:           relyingParty,
		User:                   webAuthnUser,
		Parameters:             credentialParams,
		AuthenticatorSelection: webauthn.Config.AuthenticatorSelection,
		Timeout:                webauthn.Config.Timeout,
		Attestation:            webauthn.Config.AttestationPreference,
	}

	for _, setter := range opts {
		setter(&creationOptions)
	}

	response := protocol.CredentialCreationOptions{Response: creationOptions}
	newSessionData := SessionData{
		Challenge:        base64.RawURLEncoding.EncodeToString(challenge),
		UserID:           user.WebAuthnID(),
		UserVerification: creationOptions.AuthenticatorSelection.UserVerification,
	}

	if err != nil {
		return nil, protocol.ErrParsingData.WithDetails("Error packing session data")
	}

	return &RegistrationRequest{
		session:                   &newSessionData,
		credentialCreationOptions: &response,
	}, nil
}

// Provide non-default parameters regarding the authenticator to select.
func WithAuthenticatorSelection(authenticatorSelection protocol.AuthenticatorSelection) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) {
		cco.AuthenticatorSelection = authenticatorSelection
	}
}

// Provide non-default parameters regarding credentials to exclude from retrieval.
func WithExclusions(excludeList []protocol.CredentialDescriptor) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) {
		cco.CredentialExcludeList = excludeList
	}
}

// Provide non-default parameters regarding whether the authenticator should attest to the credential.
func WithConveyancePreference(preference protocol.ConveyancePreference) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) {
		cco.Attestation = preference
	}
}

// Provide extension parameter to registration options
func WithExtensions(extension protocol.AuthenticationExtensions) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) {
		cco.Extensions = extension
	}
}

// WithResidentKeyRequirement sets both the resident key and require resident key protocol options. This could conflict
// with webauthn.WithAuthenticatorSelection if it doesn't come after it.
func WithResidentKeyRequirement(requirement protocol.ResidentKeyRequirement) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) {
		cco.AuthenticatorSelection.ResidentKey = requirement
		switch requirement {
		case protocol.ResidentKeyRequirementRequired:
			cco.AuthenticatorSelection.RequireResidentKey = protocol.ResidentKeyRequired()
		default:
			cco.AuthenticatorSelection.RequireResidentKey = protocol.ResidentKeyUnrequired()
		}
	}
}

type RegistrationResponse struct {
	user           User // The user submitting the
	session        *SessionData
	response       interface{}
	parsedResponse *protocol.ParsedCredentialCreationData
}

func ParseRegistrationResponse(user User, session *SessionData, response interface{}) (*RegistrationResponse, error) {
	parsedResponse, err := protocol.ParseCredentialCreationResponse(response)
	if err != nil {
		return nil, err
	}

	return &RegistrationResponse{
		user:           user,
		session:        session,
		response:       response,
		parsedResponse: parsedResponse,
	}, nil
}

// CreateCredential verifies a parsed response against the user's credentials and session data.
func (webauthn *WebAuthn) CreateCredential(rr *RegistrationResponse) (*Credential, error) {
	if rr.parsedResponse == nil {
		return nil, protocol.ErrVerification.WithDetails("No parsed response")
	}

	if !bytes.Equal(rr.user.WebAuthnID(), rr.session.UserID) {
		return nil, protocol.ErrBadRequest.WithDetails("ID mismatch for User and Session")
	}

	shouldVerifyUser := rr.session.UserVerification == protocol.VerificationRequired

	invalidErr := rr.parsedResponse.Verify(rr.session.Challenge, shouldVerifyUser, webauthn.Config.RPID, webauthn.Config.RPOrigin)
	if invalidErr != nil {
		return nil, invalidErr
	}

	return MakeNewCredential(rr.parsedResponse)
}

func defaultRegistrationCredentialParameters() []protocol.CredentialParameter {
	return []protocol.CredentialParameter{
		{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgES256,
		},
		{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgES384,
		},
		{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgES512,
		},
		{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgRS256,
		},
		{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgRS384,
		},
		{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgRS512,
		},
		{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgPS256,
		},
		{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgPS384,
		},
		{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgPS512,
		},
		{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgEdDSA,
		},
	}
}
