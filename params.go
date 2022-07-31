package srp

import (
	"crypto"
	"fmt"

	"errors"
	"math/big"
	"strings"

	_ "crypto/sha1" //#nosec
	_ "embed"       // Embedding RFC5054 DH groups
)

var (
	//go:embed groups/1024.txt
	hex1024 string

	//go:embed groups/1536.txt
	hex1536 string

	//go:embed groups/2048.txt
	hex2048 string

	//go:embed groups/3072.txt
	hex3072 string

	//go:embed groups/4096.txt
	hex4096 string

	//go:embed groups/6144.txt
	hex6144 string

	//go:embed groups/8192.txt
	hex8192 string
)

// KDF is the signature of a key derivation function.
type KDF func(username, password string, salt []byte) ([]byte, error)

// MustParseHex returns a *big.Int instance
// from the given hex string, or panics.
func mustParseHex(parts ...string) *big.Int {
	builder := new(strings.Builder)
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.ReplaceAll(p, " ", "")
		p = strings.ReplaceAll(p, "\r", "")
		p = strings.ReplaceAll(p, "\n", "")
		builder.WriteString(p)
	}

	n, ok := new(big.Int).SetString(builder.String(), 16)
	if !ok {
		panic(errors.New("failed to load params N"))
	}

	return n
}

// RFC5054KDF is the [KDF] defined in [RFC5054].
//
// 	x = SHA(s | SHA(U | ":" | p))
//
// Deprecated: This KDF function is only provided for compatibility
// with [RFC5054] and for testing purposes. It is not recommended
// for production use. Instead, use a key derivation function
// [KDF] designed for password hashing such as [Argon2],
// [Scrypt] or [PBKDF2].
//
// [RFC5054]: https://datatracker.ietf.org/doc/html/rfc5054
// [Argon2]: https://pkg.go.dev/golang.org/x/crypto/argon2
// [Scrypt]: https://pkg.go.dev/golang.org/x/crypto/scrypt
// [PBKDF2]: https://pkg.go.dev/golang.org/x/crypto/pbkdf2
func RFC5054KDF(username, password string, salt []byte) ([]byte, error) {
	h := crypto.SHA1.New()
	h.Write([]byte(fmt.Sprintf("%s:%s", username, password)))
	digest := h.Sum(nil)[:h.Size()]

	h.Reset()
	h.Write(salt)
	h.Write(digest)
	digest = h.Sum(nil)[:h.Size()]
	return digest, nil
}

// Params represents the DH group, the hash and
// key derivation function that a client and server
// jointly agreed to use.
//
//   import (
//     "runtime"
//     "github.com/posterity/srp"
//   	 "golang.org/x/crypto/argon2"
//
//   	 _ "crypto/sha256"
// 	 )
//
// 	 func KDFArgon2(username, password string, salt []byte) ([]byte, error) {
//   	 p := []byte(username + ":" + password)
//   	 key := argon2.IDKey(p, salt, 3, 256 * 1048576, runtime.NumCPU(), 32)
//   	 return key, nil
// 	 }
//
// 	 var params = &srp.Params{
//   	 Name: "DH16–SHA256–Argon2",
//   	 Group: srp.RFC5054Group4096,
//   	 Hash: crypto.SHA256,
//   	 KDF: KDFArgon2,
// 	 }
type Params struct {
	Name  string
	Group *Group
	Hash  crypto.Hash
	KDF   KDF
}

// hashBytes returns the hash of a.
func (p *Params) hashBytes(a []byte) []byte {
	h := p.Hash.New()
	h.Write(a)
	return h.Sum(nil)[:h.Size()]
}

// String returns the name of p.
func (p *Params) String() string {
	return p.Name
}

// Group represents a Diffie-Hellman group.
type Group struct {
	ID           string
	Generator    *big.Int
	N            *big.Int
	ExponentSize int
}

// Diffie-Hellman group 2.
//
// Deprecated: This group is not recommended
// for production-use.
var RFC5054Group1024 = &Group{
	ID:           "2",
	Generator:    big.NewInt(2),
	N:            mustParseHex(hex1024),
	ExponentSize: 32,
}

// Diffie-Hellman group 5.
//
// Deprecated: This group is not recommended
// for production-use.
var RFC5054Group1536 = &Group{
	ID:           "5",
	Generator:    big.NewInt(2),
	N:            mustParseHex(hex1536),
	ExponentSize: 23,
}

// Diffie-Hellman group 14, 15, 16, 17 and 18
// defined in [RFC5054].
//
// [RFC5054]: https://datatracker.ietf.org/doc/html/rfc5054
var (
	RFC5054Group2048 = &Group{
		ID:           "14",
		Generator:    big.NewInt(2),
		N:            mustParseHex(hex2048),
		ExponentSize: 27,
	}

	RFC5054Group3072 = &Group{
		ID:           "15",
		Generator:    big.NewInt(5),
		N:            mustParseHex(hex3072),
		ExponentSize: 32,
	}

	RFC5054Group4096 = &Group{
		ID:           "16",
		Generator:    big.NewInt(5),
		N:            mustParseHex(hex4096),
		ExponentSize: 38,
	}

	RFC5054Group6144 = &Group{
		ID:           "17",
		Generator:    big.NewInt(5),
		N:            mustParseHex(hex6144),
		ExponentSize: 43,
	}

	RFC5054Group8192 = &Group{
		ID:           "18",
		Generator:    big.NewInt(19),
		N:            mustParseHex(hex8192),
		ExponentSize: 48,
	}
)
