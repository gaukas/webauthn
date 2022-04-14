package protocol_test

import (
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/Gaukas/webauthn/protocol"
)

func setupCollectedClientData(challenge []byte) *protocol.CollectedClientData {
	ccd := &protocol.CollectedClientData{
		Type:   protocol.CreateCeremony,
		Origin: "example.com",
	}

	ccd.Challenge = base64.RawURLEncoding.EncodeToString(challenge)
	return ccd
}

func TestVerifyCollectedClientData(t *testing.T) {
	newChallenge, err := protocol.CreateChallenge()
	if err != nil {
		t.Fatalf("error creating challenge: %s", err)
	}

	ccd := setupCollectedClientData(newChallenge)
	var storedChallenge = newChallenge

	originURL, _ := url.Parse(ccd.Origin)
	err = ccd.Verify(storedChallenge.String(), ccd.Type, protocol.FullyQualifiedOrigin(originURL))
	if err != nil {
		t.Fatalf("error verifying challenge: expected %#v got %#v", protocol.Challenge(ccd.Challenge), storedChallenge)
	}
}

func TestVerifyCollectedClientDataIncorrectChallenge(t *testing.T) {
	newChallenge, err := protocol.CreateChallenge()
	if err != nil {
		t.Fatalf("error creating challenge: %s", err)
	}
	ccd := setupCollectedClientData(newChallenge)
	bogusChallenge, err := protocol.CreateChallenge()
	if err != nil {
		t.Fatalf("error creating challenge: %s", err)
	}
	storedChallenge := protocol.Challenge(bogusChallenge)
	err = ccd.Verify(storedChallenge.String(), ccd.Type, ccd.Origin)
	if err == nil {
		t.Fatalf("error expected but not received. expected %#v got %#v", protocol.Challenge(ccd.Challenge), storedChallenge)
	}
}
