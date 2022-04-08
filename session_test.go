package session

import (
	"strings"
	"testing"
	"time"
)

type fakeStore struct {
	db map[string]*DatabaseToken
}

func new() *fakeStore {
	return &fakeStore{
		db: make(map[string]*DatabaseToken),
	}
}

func (m *fakeStore) Create(token DatabaseToken) error {
	m.db[token.Identifier] = &token

	return nil
}

func (m *fakeStore) Revoke(identifier string) error {
	delete(m.db, identifier)

	return nil
}

func (m *fakeStore) Update(token DatabaseToken) error {
	oldVal := m.db[token.Identifier]
	oldVal.Identifier = token.Identifier
	oldVal.VerifierHash = token.VerifierHash
	oldVal.ExpirationDateTime = token.ExpirationDateTime
	oldVal.UserId = token.UserId
	oldVal.Details = token.Details

	m.db[token.Identifier] = oldVal

	return nil
}

func (m *fakeStore) List(userId string) ([]DatabaseToken, error) {
	var res = make([]DatabaseToken, 0)
	for _, v := range m.db {
		if v.UserId == userId {
			res = append(res, *v)
		}
	}

	return res, nil
}

func (m *fakeStore) FindByIdentifier(identifier string) (DatabaseToken, error) {
	return *m.db[identifier], nil
}

func TestManager_VerifySuccessWithoutUpdate(t *testing.T) {
	store := new()

	sessionManager := NewManager(store, &ExpirationPolicy{30, time.Duration(time.Hour * 24)})

	userId := "id1234567890"

	token, err := sessionManager.Generate(userId, "")
	if err != nil {
		t.Errorf("sessionManager.Generate(userId, \"\") = %q", err.Error())
	}

	valid, err := sessionManager.Verify(token)
	if err != nil {
		t.Errorf("sessionManager.Verify(%q) = %q; want %v", token, err.Error(), true)
	}

	if valid != true {
		t.Errorf("sessionManager.Verify(%q) = %v; want %v", token, false, true)
	}
}

func TestManager_VerifySuccessWithUpdate(t *testing.T) {
	store := new()

	sessionManager := NewManager(store, &ExpirationPolicy{30, time.Duration(time.Hour * 24)})

	userId := "id1234567890"

	token, err := sessionManager.Generate(userId, "")
	if err != nil {
		t.Errorf("sessionManager.Generate(userId, \"\") = %q", err.Error())
	}

	// change expiration date for test
	oldToken, _ := store.FindByIdentifier(strings.Split(token, ".")[0])
	oldToken.ExpirationDateTime = oldToken.ExpirationDateTime.Add(-(time.Hour * 48))
	store.Update(oldToken)

	valid, err := sessionManager.Verify(token)
	if err != nil {
		t.Errorf("sessionManager.Verify(%q) = %q; want %v", token, err.Error(), true)
	}

	if valid != true {
		t.Errorf("sessionManager.Verify(%q) = %v; want %v", token, false, true)
	}
}

func TestManager_VerifyFailedTokenExpired(t *testing.T) {
	store := new()

	sessionManager := NewManager(store, &ExpirationPolicy{-30, time.Duration(time.Hour * 24)})

	userId := "id1234567890"

	token, err := sessionManager.Generate(userId, "")
	if err != nil {
		t.Errorf("sessionManager.Generate(userId, \"\") = %q", err.Error())
	}

	valid, err := sessionManager.Verify(token)
	if err != nil {
		t.Errorf("sessionManager.Verify(%q) = %q; want %v", token, err.Error(), true)
	}

	if valid != false {
		t.Errorf("sessionManager.Verify(%q) = %v; want %v", token, true, false)
	}
}

func TestManager_VerifyFailedVerifiersDoNotEquals(t *testing.T) {
	store := new()

	sessionManager := NewManager(store, &ExpirationPolicy{30, time.Duration(time.Hour * 24)})

	userId := "id1234567890"

	token, err := sessionManager.Generate(userId, "")
	if err != nil {
		t.Errorf("sessionManager.Generate(userId, \"\") = %q", err.Error())
	}

	valid, err := sessionManager.Verify(strings.Split(token, ".")[0] + "." + "12345678")
	if err != nil {
		t.Errorf("sessionManager.Verify(%q) = %q; want %v", token, err.Error(), true)
	}

	if valid != false {
		t.Errorf("sessionManager.Verify(%q) = %v; want %v", token, true, false)
	}
}

func TestManager_RevokeSuccess(t *testing.T) {
	store := new()

	sessionManager := NewManager(store, &ExpirationPolicy{30, time.Duration(time.Hour * 24)})

	userId := "id1234567890"

	token, err := sessionManager.Generate(userId, "")
	if err != nil {
		t.Errorf("sessionManager.Generate(userId, \"\") = %q", err.Error())
	}

	if len(store.db) != 1 {
		t.Errorf("got %d; wanted %d", len(store.db), 1)
	}

	sessionManager.Revoke(strings.Split(token, ".")[0])

	if len(store.db) != 0 {
		t.Errorf("sessionManager.Revoke(%q) got %d; wanted %d", strings.Split(token, ".")[0], len(store.db), 0)
	}
}

func TestManager_ListSuccess(t *testing.T) {
	store := new()

	sessionManager := NewManager(store, &ExpirationPolicy{30, time.Duration(time.Hour * 24)})

	userId := "id1234567890"

	_, err := sessionManager.Generate(userId, "")
	if err != nil {
		t.Errorf("sessionManager.Generate(userId, \"\") = %q", err.Error())
	}
	_, err = sessionManager.Generate(userId, "")
	if err != nil {
		t.Errorf("sessionManager.Generate(userId, \"\") = %q", err.Error())
	}
	_, err = sessionManager.Generate(userId, "")
	if err != nil {
		t.Errorf("sessionManager.Generate(userId, \"\") = %q", err.Error())
	}

	if len(store.db) != 3 {
		t.Errorf("got %d; wanted %d", len(store.db), 3)
	}

	list, err := sessionManager.List(userId)
	if err != nil {
		t.Errorf("sessionManager.List(%q) = %q", userId, err.Error())
	}

	if len(list) != 3 {
		t.Errorf("sessionManager.List(%q) got %d; wanted %d", userId, len(list), 3)
	}
}
