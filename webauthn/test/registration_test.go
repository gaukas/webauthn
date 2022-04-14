package webauthn_test

import (
	"testing"

	"github.com/Gaukas/webauthn/protocol"
	"github.com/Gaukas/webauthn/webauthn"
)

func TestLogin_ParseRegistrationResponseFailure(t *testing.T) {
	user := &testUser{
		id: []byte("123"),
	}
	session := &webauthn.SessionData{
		UserID: []byte("ABC"),
	}

	rr, err := webauthn.ParseRegistrationResponse(user, session, nil)
	if err == nil {
		t.Errorf("ParseRegistrationResponse() error = nil, want %v", protocol.ErrBadRequest.Type)
	}
	if rr != nil {
		t.Errorf("ParseRegistrationResponse() RegistrationResponse != nil")
	}
}

func TestLogin_CreateCredentialFailure(t *testing.T) {
	rr := &webauthn.RegistrationResponse{}

	wa := &webauthn.WebAuthn{}
	credential, err := wa.CreateCredential(rr)
	if err == nil {
		t.Errorf("CreateCredential() error = nil, want %v", protocol.ErrBadRequest.Type)
	}
	if credential != nil {
		t.Errorf("CreateCredential() credential = %v, want nil", credential)
	}
}
