The library helps managing sessions. It supports generating and verifying session's tokens. It also supports revoking and listing user sessions.

You need to implement `TokenStore` interface for storing session's tokens. You can store tokens in any SQL database, document database, or key-value store.

The token consists of two parts (secure random 16 bytes both): identifier and verifier divided by dot:
```
e331f62186318b18cdfa8be66b87ef5e.f2a4e2278609e1b59e529267d59187cb
```
Server sends this token to the client to store and use for subsequent requests.

Client sends this token back for verifying.

Example:
```go
expirationPolicy := &session.ExpirationPolicy {
    Amount: 30,
    Unit: time.Duration(time.Hour * 24)
}
manager := session.NewManager(store, expirationPolicy)

token, err := manager.Generate("userId", "some-details")
if err != nil {
	fmt.Errorf("Unable to generate token %q", token)
}
valid, err := manager.Verify(token) // true
if err != nil {
	fmt.Errorf("Unable to verify token %q", token)
}
list, err := manager.List("userId") // list.size == 1
if err != nil {
	fmt.Errorf("User %q has no sessions", token)
}
err := manager.Revoke("identifier") // list.size == 0
if err != nil {
	fmt.ErrorF("Can't revoke session")
}
```

The library has no external dependencies.