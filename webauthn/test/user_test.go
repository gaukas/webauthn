package webauthn_test

import "github.com/Gaukas/webauthn/webauthn"

// testUser is an unfunctional implementation only for testing
type testUser struct {
	id []byte
}

func (*testUser) WebAuthnRdlock() {}

func (*testUser) WebAuthnWrlock() {}

func (user *testUser) WebAuthnID() []byte {
	return user.id
}

func (*testUser) WebAuthnName() string {
	return "newUser"
}

func (*testUser) WebAuthnDisplayName() string {
	return "New User"
}

func (*testUser) WebAuthnIcon() string {
	return "https://pics.com/avatar.png"
}

func (*testUser) WebAuthnCredentials() []webauthn.Credential {
	return []webauthn.Credential{}
}

func (*testUser) WebAuthnNewCredential(_ webauthn.Credential) {}

func (*testUser) WebAuthnUpdateCredential(_ int, _ webauthn.Credential) error {
	return nil
}
