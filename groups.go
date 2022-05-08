package srp

import (
	"crypto"
	"hash"
	"io"

	_ "crypto/sha256"
	"crypto/sha512"

	_ "embed"
	"errors"
	"math/big"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// errUnregisteredGroup is the error returned when a custom group
// is used before it's registered with the Register function.
var errUnregisteredGroup = errors.New("custom groups must be registered first (Register)")

var (
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

// PBKDF2 is a KDF function that uses the PBKDF2 algorithm.
func PBKDF2(username, password string, salt []byte) ([]byte, error) {
	k := pbkdf2.Key([]byte(username+password), salt, 100000, 32, sha512.New512_256)
	return k, nil
}

// mustParseHex returns a *big.Int instance
// from the given hex string, or panics.
func mustParseHex(str string) *big.Int {
	str = strings.TrimSpace(str)
	str = strings.ReplaceAll(str, " ", "")
	str = strings.ReplaceAll(str, "\r", "")
	str = strings.ReplaceAll(str, "\n", "")
	n, ok := new(big.Int).SetString(str, 16)
	if !ok {
		panic(errors.New("failed to load group N"))
	}

	return n
}

// RFC5054KDF is the key derivation function defined in RFC 5054.
//
// Deprecated: This method is only provided for compatibility with some
// early implementations, and is not recommended for production use.
// Instead, use a key derivation function (KDF) that involves a hashing
// scheme designed for password hashing.
//
// See the PBKDF2 method provided in this package.
func RFC5054KDF(h hash.Hash, username, password string, salt []byte) ([]byte, error) {
	h.Reset()
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

// RFC5054KDFWithSHA256 is a variation of the KDF defined in RFC 5054,
// using SHA256 instead of the compromised SHA1.
func RFC5054KDFWithSHA256(username, password string, salt []byte) ([]byte, error) {
	return RFC5054KDF(crypto.SHA256.New(), username, password, salt)
}

// Group represents an SRP group.
type Group struct {
	Name         string
	Generator    *big.Int
	N            *big.Int
	ExponentSize int // RFC 3526 §8

	// Hashing algorithm used.
	Hash crypto.Hash

	// Key Derivation Function used to compute
	// the x value.
	Derive KDF
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

// RFC5054-defined groups, with updated
// hashing and key-derivation functions.
var (
	RFC5054Group2048 = &Group{
		Name:         "2048",
		Generator:    big.NewInt(2),
		N:            mustParseHex(hex2048),
		ExponentSize: 27,
		Hash:         crypto.SHA256,
		Derive:       RFC5054KDFWithSHA256,
	}

	RFC5054Group3072 = &Group{
		Name:         "3072",
		Generator:    big.NewInt(5),
		N:            mustParseHex(hex3072),
		ExponentSize: 32,
		Hash:         crypto.SHA256,
		Derive:       RFC5054KDFWithSHA256,
	}

	RFC5054Group4096 = &Group{
		Name:         "4096",
		Generator:    big.NewInt(5),
		N:            mustParseHex(hex4096),
		ExponentSize: 38,
		Hash:         crypto.SHA256,
		Derive:       PBKDF2,
	}

	RFC5054Group6144 = &Group{
		Name:         "6144",
		Generator:    big.NewInt(5),
		N:            mustParseHex(hex6144),
		ExponentSize: 43,
		Hash:         crypto.SHA256,
		Derive:       PBKDF2,
	}

	RFC5054Group8192 = &Group{
		Name:         "8192",
		Generator:    big.NewInt(19),
		N:            mustParseHex(hex8192),
		ExponentSize: 48,
		Hash:         crypto.SHA256,
		Derive:       PBKDF2,
	}
)

// registeredGroups holds a reference to all the
// known groups.
var registeredGroups = map[string]*Group{
	RFC5054Group2048.Name: RFC5054Group2048,
	RFC5054Group3072.Name: RFC5054Group3072,
	RFC5054Group4096.Name: RFC5054Group4096,
	RFC5054Group6144.Name: RFC5054Group6144,
	RFC5054Group8192.Name: RFC5054Group8192,
}

// Registers a custom defined group to be used in either a Client
// or a Server instance.
func Register(g *Group) error {
	_, ok := registeredGroups[g.Name]
	if ok {
		return errors.New("group named \"s\" already exists")
	}
	registeredGroups[g.Name] = g
	return nil
}
