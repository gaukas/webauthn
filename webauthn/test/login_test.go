package webauthn_test

import (
	"testing"

	"github.com/Gaukas/webauthn/protocol"
	"github.com/Gaukas/webauthn/webauthn"
)

func TestLogin_ParseAuthenticationResponseFailure(t *testing.T) {
	user := &testUser{
		id: []byte("123"),
	}
	session := &webauthn.SessionData{
		UserID: []byte("ABC"),
	}

	ar, err := webauthn.ParseAuthenticationResponse(user, session, nil)
	if err == nil {
		t.Errorf("ParseAuthenticationResponse() error = nil, want %v", protocol.ErrBadRequest.Type)
	}
	if ar != nil {
		t.Errorf("ParseAuthenticationResponse() AuthenticationResponse != nil")
	}
}

func TestLogin_VerifyAuthenticationFailure(t *testing.T) {
	ar := &webauthn.AuthenticationResponse{}

	wa := &webauthn.WebAuthn{}
	credential, err := wa.VerifyAuthentication(ar)
	if err == nil {
		t.Errorf("VerifyAuthentication() error = nil, want %v", protocol.ErrBadRequest.Type)
	}
	if credential != nil {
		t.Errorf("VerifyAuthentication() credential = %v, want nil", credential)
	}
}
