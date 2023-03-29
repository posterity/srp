[![GoDoc reference](https://img.shields.io/badge/godoc-reference-blue.svg)](https://pkg.go.dev/code.posterity.life/srp/v2)

```golang
go get code.posterity.life/srp/v2@latest
```

# Secure Remote Password

Package srp is a Go implementation of
[Secure Remote Password](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol)
protocol as defined by [RFC 2945](https://tools.ietf.org/html/rfc2945) and
[RFC 5054](https://tools.ietf.org/html/rfc5054).

> SRP is an authentication method that allows the use
> of user names and passwords over unencrypted channels without
> revealing the password to an eavesdropper. SRP also supplies a
> shared secret at the end of the authentication sequence that can be
> used to generate encryption keys.

SRP is used by leading privacy-conscious companies such as
[Apple](https://support.apple.com/guide/security/escrow-security-for-icloud-keychain-sec3e341e75d/web),
[1Password](https://blog.1password.com/developers-how-we-use-srp-and-you-can-too/),
[ProtonMail](https://protonmail.com/blog/cryptographic-architecture-response/),
and yours truly.

## Protocol

Conceptually, SRP is not different from how most of us think about
authentication; the client signs up by storing a _secret_ on the server, and to
login, it must prove to that server that it knows it.

With SRP, the client first registers by storing a cryptographic value (`verifier`)
derived from its password on the server. To login, they both exchange a
series of opaque values but never the user's password or the `verifier`. Trust
can be established at the end of the process because for the server,
only the client who knows the `verifier` could have sent those values,
and vice versa.

SRP comes with four major benefits:

1. For the end-user, the familiar experience of using a username and a password
   remains fundamentally the same;
2. Server cannot leak a password it never saw;
3. After registration, both client and server can formally verify each
   other's identities without needing a third-party (e.g. CA);
4. Sessions can be secured with an extra layer of encryption on top of TLS.

### Params selection

SRP requires the client and the server to agree on a given set of parameters,
namely a Diffie-Hellman (DH) group, a hash function, and a key derivation
function.

All the DH groups defined in [RFC 5054](https://tools.ietf.org/html/rfc5054)
are available. You can use any hash function you would like
(e.g. `SHA256`, [Blake2b](https://pkg.go.dev/golang.org/x/crypto/blake2b)), and
the same goes for key derivation
(e.g. [Argon2](https://pkg.go.dev/golang.org/x/crypto/argon2),
[Scrypt](https://pkg.go.dev/golang.org/x/crypto/scrypt) or
[PBKDF2](https://pkg.go.dev/golang.org/x/crypto/pbkdf2)).

The example below shows the DH group 16 used in conjunction with `SHA256` and
[Argon2](https://pkg.go.dev/golang.org/x/crypto/argon2):

```golang
import (
  "runtime"
  "github.com/posterity/srp"
  "golang.org/x/crypto/argon2"

  _ "crypto/sha256"
)

// KDFArgon2 uses Argon2.
func KDFArgon2(username, password string, salt []byte) ([]byte, error) {
  p := []byte(username + ":" + password)
  key := argon2.IDKey(p, salt, 3, 256 * 1048576, runtime.NumCPU(), 32)
  return key, nil
}

// Params instance using DH group 16, SHA256 for hashing and Argon2 as a KDF.
var params = &srp.Params{
  Name: "DH16–SHA256–Argon2",
  Group: srp.RFC5054Group4096,
  Hash: crypto.SHA256,
  KDF: KDFArgon2,
}
```

### User Registration

During user registration, the client must send the server a `verifier`; a
value safely derived from the user's password with a unique random salt.

```go
tp, err := srp.ComputeVerifier(params, username, password, srp.NewSalt())
if err != nil {
  log.Fatalf("error computing verifier: %v", err)
}

// The verifier can be accessed as tp.Verifier().

// On the server, it's recommended to store the verifier along with
// the username and the salt used to compute it, so sending the whole
// triplet tp ([]byte) is more appropriate.
Send(tp)
```

The `Triplet` returned by `ComputeVerifier` encapsulates three variables into a
single byte array that the server can store:

- Username
- Verifier
- Salt

It's important for the server to treat the triplet with care, as it contains
a secret value (`verifier`) which should never be shared with anyone.

The `salt` value it contains however should be made available publicly to
_anyone who asks_ via a public URL.

### Login

When it's time to authenticate a user, client and server follow a three-step
process:

1. `client` and `server` exchange ephemeral public keys `A` and `B`,
   respectively;
2. `client` computes a proof and sends it to the server;
3. `server` checks the client's proof and sends the client a proof of their own.

#### Client-side

On the client side, the first step is to initialize a `Client`.

```go
var (
  username  = "alice@example.com"
  password  = "p@$$w0rd"
  salt      []byte // Retrieved from the server
)
client, err := srp.NewClient(params, username, password, salt)
if err != nil {
  log.Fatal(err)
}
```

All the values must match those used to create the verifier that was stored
on the server. The `salt` should be retrievable from the server without
requiring prior authentication.

The next step is to send the ephemeral public key `A` to the server:

```go
A := client.A()

// Send A to the server
```

The server will do the same, sending their ephemeral public key `B` instead.
Configure it on the client as following:

```go
var B []byte // Received from the server

client.SetB(B)
```

Next, compute the client proof and send it to the server.

```go
M1, err := client.ComputeM1()
if err != nil {
  log.Fatalf("error computing proof: %v", err)
}

// send M1 to the server
```

If the server accepts the client's proof, they will send their own server proof.

```go
var M2 []byte // Received from the server

ok, err := client.CheckM2(M2)
if err != nil {
  log.Fatalf("error checking M2: %v", err)
}
if !ok {
  log.Fatalf("server is not authentic")
}
```

At this stage, the client and the server can trust each other, and can
(optionally) use a shared encryption key to secure their session from this
point on.

```go
sharedKey, err := client.SessionKey()
if err != nil {
  log.Fatalf("error computing key: %v", err)
}

// sharedKey is a 256 bit key which was computed
// locally.
```

#### Server-side

The process on the server-side is very similar to the above, with one key
difference: the server must first receive and verify the client's proof (`M1`)
before it computes and shares its own (`M2`).

```go
var (
  triplet srp.Triplet                             // Retrieved from the server
)
server, err := srp.NewServer(params, username, password, salt)
if err != nil {
  log.Fatal(err)
}
```

The next step is to wait for the user to send their ephemeral public key `A`
to configure it on the server.

```go
var A []byte // received from the client

if err := server.setA(A); err != nil {
  log.Fatal("error configuring A: %v", err)
}
```

If no error is caught, the next step is to send to server's ephemeral public
key `B` to the client.

```go
B := server.B()

// send B to the client
```

Now the server must wait for the client to submit their proof `M1`.

```go
var M1 []byte   // Received from the client

ok, err := server.CheckM1(M1)
if err != nil {
  log.Fatalf("error verifying M1: %v", err)
}

if !ok {
  log.Fatalf("client is not authentic")
}
```

If this verification fails, the process must stop at this point, and no further
information should be shared with the client over this session. A new `Server`
instance will need to be created and the negotiation restarted.

If successful, the server can consider the client as _authentic_, but it
still needs to send its own proof `M2`.

```go
M2, err := server.ComputeM2()
if err != nil {
  log.Fatalf("error computing M2: %v", err)
}

// send M2 to the client
```

If the client accepts the proof, they can both consider each other as
_authentic_ and compute their shared session key to encrypt their exchanges
and protect themselves from eavesdropping.

```go
sharedKey, err := server.SessionKey()
if err != nil {
  log.Fatalf("error computing key: %v", err)
}

// sharedKey is a 256 bit key which was computed
// locally.
```

## Implementation

SRP is protocol-agnostic and can be implemented on top of any existing
client/server architecture.

At Posterity, we use a custom websocket protocol, but a simple HTTP API would
be equally suitable. In any case, the process can usually be completed in
two round-trips, excluding the request needed to retrieve the `salt` value
of the user:

```plain
(Client) 👧🏼  ---------→ A
                        B   ←--------- 👨🏽 (Server)

(Client) 👧🏼  ---------→ M1
                        M2  ←--------- 👨🏽 (Server)

```

If you're using a stateless architecture (e.g. REST), the state of a `Server`
can be saved and restored using `Server.Save` and `RestoreServer` respectively.
Bear in mind that a `Server`'s internal state contains the user's `verifier`,
and should therefore be handled appropriately.

A secure connection between the client and the server is a necessity,
especially when the client first needs to send their `verifier` to the server.

## Session Encryption

SRP defines a way for the client and the server to independently compute a
strong but ephemeral encryption key which they can use to secure their
communications during a session.

At Posterity, we use
[Encrypted-Content-Encoding for HTTP](https://github.com/posterity/ece) to set
that in motion, using the shared key to encrypt all client-server exchanges
with AES-256-GCM after login.

## Contributions

Contributions are welcome via Pull Requests.

## About us

What if you're hit by a bus tomorrow? [Posterity](https://posterity.life) helps
you make a plan in the event something happens to you.
