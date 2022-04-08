package session

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
	"time"
)

type TokenStore interface {
	Create(token DatabaseToken) error
	Revoke(identifier string) error
	Update(token DatabaseToken) error
	List(userId string) ([]DatabaseToken, error)
	FindByIdentifier(identifier string) (DatabaseToken, error)
}

type DatabaseToken struct {
	Identifier         string
	VerifierHash       string
	ExpirationDateTime time.Time
	UserId             string
	Details            string
}

type ExpirationPolicy struct {
	Amount int64
	Unit   time.Duration // hours, seconds, etc.
}

type manager struct {
	store            TokenStore
	expirationPolicy *ExpirationPolicy
}

func NewManager(store TokenStore, expirationPolicy *ExpirationPolicy) *manager {
	if expirationPolicy == nil {
		return &manager{
			store: store,
			expirationPolicy: &ExpirationPolicy{ // 30 days until session will be expired by default
				Amount: 30,
				Unit:   time.Duration(time.Hour * 24),
			},
		}
	} else {
		return &manager{
			store:            store,
			expirationPolicy: expirationPolicy,
		}
	}

}

func (m manager) Generate(userId string, details string) (string, error) {
	identifier, err := secureRandomBytes(16)
	if err != nil {
		return "", err
	}

	verifier, err := secureRandomBytes(16)
	if err != nil {
		return "", err
	}

	identifierHex := hex.EncodeToString(identifier)
	sessionToken := identifierHex + "." + hex.EncodeToString(verifier)

	dbToken := DatabaseToken{
		Identifier:         identifierHex,
		VerifierHash:       hex.EncodeToString(sha256Bytes(verifier)),
		ExpirationDateTime: time.Now().UTC().Add(expirationDelta(m.expirationPolicy.Amount, m.expirationPolicy.Unit)),
		UserId:             userId,
		Details:            details,
	}

	err = m.store.Create(dbToken)
	if err != nil {
		return "", err
	}

	return sessionToken, nil
}

func secureRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (m manager) Verify(sessionToken string) (bool, error) {
	splitToken := strings.Split(sessionToken, ".")
	savedToken, err := m.store.FindByIdentifier(splitToken[0])
	if err != nil {
		return false, err
	}

	var needUpdateToken = false

	expirationDateTime := savedToken.ExpirationDateTime
	now := time.Now().UTC()

	if expirationDateTime.Before(now) {
		return false, nil
	}

	// check dates only
	// update token only when dates are different
	d := expirationDelta(m.expirationPolicy.Amount, m.expirationPolicy.Unit)
	if !(expirationDateTime.Add(-(d)).Truncate(24 * time.Hour).Equal(now.Truncate(24 * time.Hour))) {
		needUpdateToken = true
	}

	// check equality of the verifiers
	decodedVerifier, err := hex.DecodeString(splitToken[1])
	if err != nil {
		return false, err
	}

	decodedVerifierHash, err := hex.DecodeString(savedToken.VerifierHash)
	if err != nil {
		return false, err
	}

	verifiersEquals := subtle.ConstantTimeCompare(decodedVerifierHash, sha256Bytes(decodedVerifier)) == 1
	if verifiersEquals {
		if needUpdateToken {
			err := m.store.Update(
				DatabaseToken{
					Identifier:         savedToken.Identifier,
					VerifierHash:       savedToken.VerifierHash,
					ExpirationDateTime: time.Now().UTC().Add(expirationDelta(m.expirationPolicy.Amount, m.expirationPolicy.Unit)), // renew expiration date
					UserId:             savedToken.UserId,
					Details:            savedToken.Details,
				})
			if err != nil {
				return false, err
			}
		}
		return true, nil
	} else {
		return false, nil
	}
}

func expirationDelta(amount int64, unit time.Duration) time.Duration {
	return time.Duration(amount) * unit
}

func sha256Bytes(v []byte) []byte {
	h := sha256.New()
	h.Write(v)

	return h.Sum(nil)
}

func (m manager) List(userId string) ([]DatabaseToken, error) {
	sessions, err := m.store.List(userId)
	if err != nil {
		return nil, err
	}

	return sessions, nil
}

func (m manager) Revoke(identifier string) error {
	err := m.store.Revoke(identifier)
	if err != nil {
		return err
	}

	return nil
}
