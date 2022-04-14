package protocol_test

import (
	"reflect"
	"testing"

	"github.com/Gaukas/webauthn/protocol"
)

func TestPublicKeyCredentialRequestOptions_GetAllowedCredentialIDs(t *testing.T) {
	type fields struct {
		Challenge          protocol.Challenge
		Timeout            int
		RelyingPartyID     string
		AllowedCredentials []protocol.CredentialDescriptor
		UserVerification   protocol.UserVerificationRequirement
		Extensions         protocol.AuthenticationExtensions
	}
	tests := []struct {
		name   string
		fields fields
		want   [][]byte
	}{
		{
			"Correct Credential IDs",
			fields{
				Challenge: protocol.Challenge([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
				Timeout:   60,
				AllowedCredentials: []protocol.CredentialDescriptor{
					{
						Type: "public-key", CredentialID: []byte("1234"), Transport: []protocol.AuthenticatorTransport{"usb"},
					},
				},
				RelyingPartyID:   "test.org",
				UserVerification: protocol.VerificationPreferred,
				Extensions:       protocol.AuthenticationExtensions{},
			},
			[][]byte{
				[]byte("1234"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &protocol.PublicKeyCredentialRequestOptions{
				Challenge:          tt.fields.Challenge,
				Timeout:            tt.fields.Timeout,
				RelyingPartyID:     tt.fields.RelyingPartyID,
				AllowedCredentials: tt.fields.AllowedCredentials,
				UserVerification:   tt.fields.UserVerification,
				Extensions:         tt.fields.Extensions,
			}
			if got := a.GetAllowedCredentialIDs(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PublicKeyCredentialRequestOptions.GetAllowedCredentialIDs() = %v, want %v", got, tt.want)
			}
		})
	}
}
