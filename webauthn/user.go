package webauthn

import "errors"

var (
	ErrCredentialNotFound = errors.New("credential not found for the given index")
)

// User is built to interface with the Relying Party's User entry and
// elaborate the fields and methods needed for WebAuthn
type User interface {
	// Rdlock() guarantees no current write could be happening on the user
	WebAuthnRdlock()
	// Wrlock() guarantees no current read/write could be happening on the user
	WebAuthnWrlock()
	// User ID according to the Relying Party, read-only
	WebAuthnID() []byte
	// User Name according to the Relying Party, read-only
	WebAuthnName() string
	// Display Name of the user, read-only
	WebAuthnDisplayName() string
	// User's icon url, read-only
	WebAuthnIcon() string
	// Credentials owned by the user
	WebAuthnCredentials() []Credential
	// WebAuthnUpdateCredential updates the user credential at the given index
	WebAuthnUpdateCredential(idx int, cred Credential) error
}
