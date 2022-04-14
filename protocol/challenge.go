package protocol

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// ChallengeLength - Length of bytes to generate for a challenge
const ChallengeLength = 32
const MinimalChallengeLength = 16

var ErrChallengeTooShort = errors.New("Challenge is too short")

// Challenge that should be signed and returned by the authenticator
type Challenge URLEncodedBase64

// Create a new challenge to be sent to the authenticator. The spec recommends using
// at least 16 bytes with 100 bits of entropy. We use 32 bytes.
func CreateChallenge() (Challenge, error) {
	challenge := make([]byte, ChallengeLength)
	_, err := rand.Read(challenge)
	if err != nil {
		return nil, err
	}
	return challenge, nil
}

func ChallengeFromBytes(challenge []byte) (Challenge, error) {
	if len(challenge) < MinimalChallengeLength {
		return nil, ErrChallengeTooShort
	}

	return Challenge(challenge), nil
}

func (c Challenge) String() string {
	return base64.RawURLEncoding.EncodeToString(c)
}
