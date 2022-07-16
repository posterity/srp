package srp

import (
	"crypto"

	"errors"
	"io"
	"math/big"
	"strings"

	_ "crypto/sha1" //#nosec
	_ "embed"       // Embedding RFC5054 groups
)

// ErrUnknownGroup is the error returned when a referenced
// group cannot be found in [Groups].
var ErrUnknownGroup = errors.New("unregistered group")

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

// mustParseHex returns a *big.Int instance
// from the given hex string, or panics.
func mustParseHex(str string) *big.Int {
	str = strings.TrimSpace(str)
	str = strings.ReplaceAll(str, " ", "")
	str = strings.ReplaceAll(str, "\r", "")
	str = strings.ReplaceAll(str, "\n", "")
	n, ok := new(big.Int).SetString(str, 16)
	if !ok {
		panic(errors.New("invalid hex string for group"))
	}

	return n
}

// RFC5054KDF is the [KDF] defined in [RFC5054].
//
// 	x = SHA(s | SHA(U | ":" | p))
//
// Deprecated: This method is only provided for compatibility with
// the standard and for testing purposes. It is not recommended
// for production use.
//
// Instead, use a key derivation function [KDF] designed
// for password hashing such as [Argon2], [Scrypt] or [PBKDF2].
//
// [RFC5054]: https://datatracker.ietf.org/doc/html/rfc5054
// [Argon2]: https://pkg.go.dev/golang.org/x/crypto/argon2
// [Scrypt]: https://pkg.go.dev/golang.org/x/crypto/scrypt
// [PBKDF2]: https://pkg.go.dev/golang.org/x/crypto/pbkdf2
func RFC5054KDF(username, password string, salt []byte) ([]byte, error) {
	h := crypto.SHA1.New()
	if _, err := io.WriteString(h, username); err != nil {
		return nil, errors.New("failed to write username")
	}
	if _, err := io.WriteString(h, ":"); err != nil {
		return nil, errors.New("failed to write separator")
	}
	if _, err := io.WriteString(h, password); err != nil {
		return nil, errors.New("failed to write password")
	}
	digest := h.Sum(nil)[:h.Size()]

	h.Reset()
	if _, err := h.Write(salt); err != nil {
		return nil, errors.New("failed to write salt")
	}
	if _, err := h.Write(digest); err != nil {
		return nil, errors.New("failed to write H(I:P)")
	}
	digest = h.Sum(nil)[:h.Size()]

	return digest, nil
}

// Group represents a Diffie-Hellman group.
type Group struct {
	ID           string
	Name         string
	Generator    *big.Int
	N            *big.Int
	ExponentSize int // RFC 3526 §8
	Hash         crypto.Hash
	KDF          KDF
}

// Clone returns an altered copy of g.
//  import (
// 		golang.org/x/crypto/argon2
// 		github.com/posterity/srp
// 	)
//
//  KDFAragon2 := func(username, password string, salt []byte) ([]byte, error) {
// 		p := []byte(username + ":" + password)
// 		key := argon2.Key(p, salt, 3, 32*1024, 4, 32)
// 		return key, nil
// 	}
// 	g := srp.RFC5054Group2048.Clone("custom-group", crypto.SHA256, KDFAragon2)
// 	srp.Groups[group.Name()] = g
func (g *Group) Clone(name string, h crypto.Hash, kdf KDF) *Group {
	return &Group{
		Name:         name,
		Generator:    g.Generator,
		N:            g.N,
		ExponentSize: g.ExponentSize,
		Hash:         h,
		KDF:          kdf,
	}
}

// hashBytes returns the hash of a.
func (g *Group) hashBytes(a []byte) []byte {
	h := g.Hash.New()
	h.Write(a)
	return h.Sum(nil)[:h.Size()]
}

// String returns the name of this group.
func (g *Group) String() string {
	return g.Name
}

// Diffie-Hellman groups defined in [RFC5054].
//
// Deprecated: These groups are provided for compatibility
// and testing purposes, and should not be used as-is.
//
// Use [Group.Clone] to customize one of these groups
// with your a hash and KDF of your choosing.
//
// [RFC5054]: https://datatracker.ietf.org/doc/html/rfc5054
var (
	RFC5054Group1024 = &Group{
		ID:           "1",
		Name:         "1024",
		Generator:    big.NewInt(2),
		N:            mustParseHex(hex1024),
		ExponentSize: 32,
		Hash:         crypto.SHA1,
		KDF:          RFC5054KDF,
	}

	RFC5054Group1536 = &Group{
		ID:           "5",
		Name:         "1536",
		Generator:    big.NewInt(2),
		N:            mustParseHex(hex1536),
		ExponentSize: 23,
		Hash:         crypto.SHA1,
		KDF:          RFC5054KDF,
	}

	RFC5054Group2048 = &Group{
		ID:           "14",
		Name:         "2048",
		Generator:    big.NewInt(2),
		N:            mustParseHex(hex2048),
		ExponentSize: 27,
		Hash:         crypto.SHA1,
		KDF:          RFC5054KDF,
	}

	RFC5054Group3072 = &Group{
		ID:           "15",
		Name:         "3072",
		Generator:    big.NewInt(5),
		N:            mustParseHex(hex3072),
		ExponentSize: 32,
		Hash:         crypto.SHA1,
		KDF:          RFC5054KDF,
	}

	RFC5054Group4096 = &Group{
		ID:           "16",
		Name:         "4096",
		Generator:    big.NewInt(5),
		N:            mustParseHex(hex4096),
		ExponentSize: 38,
		Hash:         crypto.SHA1,
		KDF:          RFC5054KDF,
	}

	RFC5054Group6144 = &Group{
		ID:           "17",
		Name:         "6144",
		Generator:    big.NewInt(5),
		N:            mustParseHex(hex6144),
		ExponentSize: 43,
		Hash:         crypto.SHA1,
		KDF:          RFC5054KDF,
	}

	RFC5054Group8192 = &Group{
		ID:           "18",
		Name:         "8192",
		Generator:    big.NewInt(19),
		N:            mustParseHex(hex8192),
		ExponentSize: 48,
		Hash:         crypto.SHA1,
		KDF:          RFC5054KDF,
	}
)

// Groups holds index all the know groups
// by their name.
var Groups = map[string]*Group{
	RFC5054Group2048.Name: RFC5054Group1024,
	RFC5054Group2048.Name: RFC5054Group1536,
	RFC5054Group2048.Name: RFC5054Group2048,
	RFC5054Group3072.Name: RFC5054Group3072,
	RFC5054Group4096.Name: RFC5054Group4096,
	RFC5054Group6144.Name: RFC5054Group6144,
	RFC5054Group8192.Name: RFC5054Group8192,
}
