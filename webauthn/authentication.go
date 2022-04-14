package webauthn

import (
	"bytes"
	"encoding/base64"

	"github.com/Gaukas/webauthn/protocol"
)

type AuthenticationRequest struct {
	session                  *SessionData                       // A server implementation should save this for verification
	credentialRequestOptions *protocol.CredentialRequestOptions // A server implementation should send this to the client
}

func (ar *AuthenticationRequest) Session() *SessionData {
	return ar.session
}

func (ar *AuthenticationRequest) CredentialRequestOptions() *protocol.CredentialRequestOptions {
	return ar.credentialRequestOptions
}

// Creates the CredentialAssertion data payload that should be sent to the user agent for beginning the
// login/assertion process. The format of this data can be seen in §5.5 of the WebAuthn specification
// (https://www.w3.org/TR/webauthn/#assertion-options). These default values can be amended by providing
// additional LoginOption parameters. This function also returns sessionData, that must be stored by the
// RP in a secure manner and then provided to the FinishLogin function. This data helps us verify the
// ownership of the credential being retreived.
// [TO-DO] - Add support for usernameless
func (webauthn *WebAuthn) Authenticate(user User, opts ...AuthenticationOption) (*AuthenticationRequest, error) {
	challenge, err := protocol.CreateChallenge()
	if err != nil {
		return nil, err
	}

	credentials := user.WebAuthnCredentials()

	if len(credentials) == 0 { // If the user does not have any credentials, we cannot do login
		return nil, protocol.ErrBadRequest.WithDetails("Found no credentials for user")
	}

	var allowedCredentials = make([]protocol.CredentialDescriptor, len(credentials))

	for i, credential := range credentials {
		var credentialDescriptor protocol.CredentialDescriptor
		credentialDescriptor.CredentialID = credential.ID
		credentialDescriptor.Type = protocol.PublicKeyCredentialType
		allowedCredentials[i] = credentialDescriptor
	}

	requestOptions := protocol.PublicKeyCredentialRequestOptions{
		Challenge:          challenge,
		Timeout:            webauthn.Config.Timeout,
		RelyingPartyID:     webauthn.Config.RPID,
		UserVerification:   webauthn.Config.AuthenticatorSelection.UserVerification,
		AllowedCredentials: allowedCredentials,
	}

	for _, setter := range opts {
		setter(&requestOptions)
	}

	newSessionData := SessionData{
		Challenge:            base64.RawURLEncoding.EncodeToString(challenge),
		UserID:               user.WebAuthnID(),
		AllowedCredentialIDs: requestOptions.GetAllowedCredentialIDs(),
		UserVerification:     requestOptions.UserVerification,
		Extensions:           requestOptions.Extensions,
	}

	response := protocol.CredentialRequestOptions{Response: requestOptions}

	return &AuthenticationRequest{
		session:                  &newSessionData,
		credentialRequestOptions: &response,
	}, nil
}

// AuthenticationOption is used to provide parameters that modify the default Credential Assertion Payload that is sent to the user.
type AuthenticationOption func(*protocol.PublicKeyCredentialRequestOptions)

// Updates the allowed credential list with Credential Descripiptors, discussed in §5.10.3
// (https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor) with user-supplied values
func WithAllowedCredentials(allowList []protocol.CredentialDescriptor) AuthenticationOption {
	return func(cco *protocol.PublicKeyCredentialRequestOptions) {
		cco.AllowedCredentials = allowList
	}
}

// Request a user verification preference
func WithUserVerification(userVerification protocol.UserVerificationRequirement) AuthenticationOption {
	return func(cco *protocol.PublicKeyCredentialRequestOptions) {
		cco.UserVerification = userVerification
	}
}

// Request additional extensions for assertion
func WithAssertionExtensions(extensions protocol.AuthenticationExtensions) AuthenticationOption {
	return func(cco *protocol.PublicKeyCredentialRequestOptions) {
		cco.Extensions = extensions
	}
}

// Request the challenge to be set as a specific value
func WithChallenge(challenge []byte) AuthenticationOption {
	return func(cco *protocol.PublicKeyCredentialRequestOptions) {
		cco.Challenge = challenge
	}
}

type AuthenticationResponse struct {
	user           User // The user submitting the
	session        *SessionData
	response       interface{}
	parsedResponse *protocol.ParsedCredentialAssertionData
}

func ParseAuthenticationResponse(user User, session *SessionData, response interface{}) (*AuthenticationResponse, error) {
	parsedResponse, err := protocol.ParseCredentialRequestResponse(response)
	if err != nil {
		return nil, err
	}

	return &AuthenticationResponse{
		user:           user,
		session:        session,
		response:       response,
		parsedResponse: parsedResponse,
	}, nil
}

// ValidateLogin takes a parsed response and validates it against the user credentials and session data
func (webauthn *WebAuthn) VerifyAuthentication(ar *AuthenticationResponse) (*Credential, error) {
	if ar.parsedResponse == nil {
		return nil, protocol.ErrVerification.WithDetails("No parsed response")
	}

	if !bytes.Equal(ar.user.WebAuthnID(), ar.session.UserID) {
		return nil, protocol.ErrBadRequest.WithDetails("ID mismatch for User and Session")
	}

	// Step 1. If the allowCredentials option was given when this authentication ceremony was initiated,
	// verify that credential.id identifies one of the public key credentials that were listed in
	// allowCredentials.

	// NON-NORMATIVE Prior Step: Verify that the allowCredentials for the session are owned by the user provided
	userCredentials := ar.user.WebAuthnCredentials()
	var credentialFound bool
	if len(ar.session.AllowedCredentialIDs) > 0 {
		var credentialsOwned bool
		for _, allowedCredentialID := range ar.session.AllowedCredentialIDs {
			for _, userCredential := range userCredentials {
				if bytes.Equal(userCredential.ID, allowedCredentialID) {
					credentialsOwned = true
					break
				}
				credentialsOwned = false
			}
		}
		if !credentialsOwned {
			return nil, protocol.ErrBadRequest.WithDetails("User does not own all credentials from the allowedCredentialList")
		}
		for _, allowedCredentialID := range ar.session.AllowedCredentialIDs {
			if bytes.Equal(ar.parsedResponse.RawID, allowedCredentialID) {
				credentialFound = true
				break
			}
		}
		if !credentialFound {
			return nil, protocol.ErrBadRequest.WithDetails("User does not own the credential returned")
		}
	}

	// Step 2. If credential.response.userHandle is present, verify that the user identified by this value is
	// the owner of the public key credential identified by credential.id.

	// This is in part handled by our Step 1

	userHandle := ar.parsedResponse.Response.UserHandle
	if len(userHandle) > 0 {
		if !bytes.Equal(userHandle, ar.user.WebAuthnID()) {
			return nil, protocol.ErrBadRequest.WithDetails("userHandle and User ID do not match")
		}
	}

	// Step 3. Using credential’s id attribute (or the corresponding rawId, if base64url encoding is inappropriate
	// for your use case), look up the corresponding credential public key.
	var credential Credential
	var credentialIndex int
	for idx, cred := range userCredentials {
		if bytes.Equal(cred.ID, ar.parsedResponse.RawID) {
			credential = cred
			credentialFound = true
			credentialIndex = idx
			break
		}
		credentialFound = false
	}

	if !credentialFound {
		return nil, protocol.ErrBadRequest.WithDetails("Unable to find the credential for the returned credential ID")
	}

	shouldVerifyUser := ar.session.UserVerification == protocol.VerificationRequired

	rpID := webauthn.Config.RPID
	rpOrigin := webauthn.Config.RPOrigin

	appID, err := ar.parsedResponse.GetAppID(ar.session.Extensions, credential.AttestationType)
	if err != nil {
		return nil, err
	}

	// Handle steps 4 through 16
	validError := ar.parsedResponse.Verify(ar.session.Challenge, rpID, rpOrigin, appID, shouldVerifyUser, credential.PublicKey)
	if validError != nil {
		return nil, validError
	}

	// Handle step 17
	credential.Authenticator.UpdateCounter(ar.parsedResponse.Response.AuthenticatorData.Counter)
	if !credential.Authenticator.CloneWarning { // If not cloned then update the counter value
		err = ar.user.WebAuthnUpdateCredential(credentialIndex, credential)
	}

	return &credential, err
}
