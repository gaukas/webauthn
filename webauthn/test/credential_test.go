package webauthn_test

import (
	"reflect"
	"testing"

	"github.com/Gaukas/webauthn/protocol"
	"github.com/Gaukas/webauthn/webauthn"
)

func TestMakeNewCredential(t *testing.T) {
	type args struct {
		c *protocol.ParsedCredentialCreationData
	}
	tests := []struct {
		name    string
		args    args
		want    *webauthn.Credential
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := webauthn.MakeNewCredential(tt.args.c)
			if (err != nil) != tt.wantErr {
				t.Errorf("MakeNewCredential() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MakeNewCredential() = %v, want %v", got, tt.want)
			}
		})
	}
}
