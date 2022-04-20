// Package srp is an implementation of the Secure Remote Password
// protocol as defined in RFC 5054 and RFC 2945.
//
// It's based on the work of 1Password (https://github.com/1Password/srp),
// with a few key changes to restore compatibility with the RFC, and to make
// the codebase more idiomatic.
//
// Custom Groups
//
// All but two of the groups defined in the RFCs are available, but you can also
// define your own in order to use a different key-derivation function for example.
//
// For that, create a new Group instance and register it before
// you initialize a Client or a Server instance.
//
// 	g := &Group{
// 		Name:         "Custom Group",
// 		Generator:    big.NewInt(2),
// 		N:            big.NewInt(...),
// 		ExponentSize: 27,
// 		Hash:         crypto.SHA256,
// 		Derive:       PBKDF2,
// 	}
// 	if err := srp.Register(g); err != nil {
//		log.Fatalf("error registering group: %v", err)
// 	}
package srp

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
)

var (
	bigZero = big.NewInt(0)
	bigOne  = big.NewInt(1)
)

// Smallest ephemeral key size allowed.
const minEphemeralKeySize = 32

// SaltLength represents the default length
// for a salt created with NewRandomSalt.
const SaltLength = 12

// NewRandomSalt returns a new random salt with the given length.
//
// If length < 1, SaltLength is used instead.
func NewRandomSalt(length int) []byte {
	if length < 1 {
		length = SaltLength
	}
	return randomKey(length)
}

// computeM1 computes the value of the client proof M1.
//
// Formula:
// 	H(H(N) XOR H(g) | H(U) | s | A | B | K)
func computeM1(group *Group, username, salt []byte, A, B *big.Int, K []byte) (*big.Int, error) {
	var (
		hN = group.hashBytes(group.N.Bytes())
		hg = group.hashBytes(group.Generator.Bytes())
		hU = group.hashBytes(username)
	)

	groupXOR, err := xorBytes(hN, hg)
	if err != nil {
		return nil, err
	}

	h := group.Hash.New()
	if _, err := h.Write(groupXOR); err != nil {
		return nil, fmt.Errorf("failed to write group hash to hasher: %w", err)
	}
	if _, err := h.Write(hU); err != nil {
		return nil, fmt.Errorf("failed to write u hash to hasher: %w", err)
	}
	if _, err := h.Write(salt); err != nil {
		return nil, fmt.Errorf("failed to write salt to hasher: %w", err)
	}
	if _, err := h.Write(A.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to write A to hasher: %w", err)
	}
	if _, err := h.Write(B.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to write B to hasher: %w", err)
	}
	if _, err := h.Write(K); err != nil {
		return nil, fmt.Errorf("failed to write key to hasher: %w", err)
	}
	digest := h.Sum(nil)[:h.Size()]

	return new(big.Int).SetBytes(digest), nil
}

// computeM2 computes the value of the server proof M2.
//
// Formula:
// 	H(A | M | K)
func computeM2(group *Group, A, M1 *big.Int, K []byte) (*big.Int, error) {
	h := group.Hash.New()
	if _, err := h.Write(A.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to write A to hasher: %w", err)
	}
	if _, err := h.Write(M1.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to write M to hasher: %w", err)
	}
	if _, err := h.Write(K); err != nil {
		return nil, fmt.Errorf("failed to write key to hasher: %w", err)
	}

	digest := h.Sum(nil)[:h.Size()]
	return new(big.Int).SetBytes(digest), nil
}

// checkProof returns true if Mx (M1 or M2) is
// equal to proof.
func checkProof(Mx, proof []byte) bool {
	result := subtle.ConstantTimeCompare(Mx, proof)
	return (result == 1)
}

// computeK returns the encryption key
// derived by a server from this session.
//
// Formula:
// 	(A * v^u) ^ b % N
func computeServerS(group *Group, v, u, A, b *big.Int) (*big.Int, error) {
	base := new(big.Int)
	base.Exp(v, u, group.N)
	base.Mul(base, A)

	S := new(big.Int).Exp(base, b, group.N)
	return S, nil
}

// computeClientK returns the encryption key
// derived by a client from a session.
//
// Formula:
// 	(B - (k * g ^ x)) ^ (a + (u * x)) % N
func computeClientS(group *Group, k, x, u, B, a *big.Int) (*big.Int, error) {
	// (k * g ^ x)
	product := new(big.Int).Mul(k, new(big.Int).Exp(group.Generator, x, group.N))

	// (B - (k * g ^ x))
	base := new(big.Int).Sub(B, product)

	// (a + (u * x))
	exp := new(big.Int).Add(a, new(big.Int).Mul(u, x))

	// (B - (k * g ^ x)) ^ (a + (u * x)) % N
	S := new(big.Int).Exp(base, exp, group.N)
	return S, nil
}

// computeLittleK computes the value of k.
//
// Formula:
// 	H(N | PAD(g))
func computeLittleK(group *Group) (*big.Int, error) {
	g, err := pad(group.Generator.Bytes(), group.N.BitLen())
	if err != nil {
		return nil, fmt.Errorf("failed to pad g")
	}

	h := group.Hash.New()
	if _, err := h.Write(group.N.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to write N to hasher: %w", err)
	}
	if _, err = h.Write(g); err != nil {
		return nil, fmt.Errorf("failed to write g to hasher: %w", err)
	}

	digest := h.Sum(nil)[:h.Size()]
	return new(big.Int).SetBytes(digest), nil
}

// computeLittleU computes the value of u.
func computeLittleU(group *Group, A, B *big.Int) (*big.Int, error) {
	if A == nil {
		return nil, errors.New("client public ephemeral A must be set first")
	}

	bA, err := pad(A.Bytes(), group.N.BitLen())
	if err != nil {
		return nil, fmt.Errorf("failed to pad A: %w", err)
	}

	bB, err := pad(B.Bytes(), group.N.BitLen())
	if err != nil {
		return nil, fmt.Errorf("failed to pad B: %w", err)
	}

	h := group.Hash.New()
	if _, err = h.Write(bA); err != nil {
		return nil, fmt.Errorf("failed to write to hasher: %w", err)
	}
	if _, err := h.Write(bB); err != nil {
		return nil, fmt.Errorf("failed to write to hasher: %w", err)
	}

	digest := h.Sum(nil)[:h.Size()]
	u := new(big.Int).SetBytes(digest)
	return u, nil
}

// makeServerKeyPair creates a server's ephemeral key pair
// (b, B).
func makeServerKeyPair(group *Group, k, v *big.Int) (b *big.Int, B *big.Int) {
	size := group.ExponentSize
	if group.ExponentSize < minEphemeralKeySize {
		size = minEphemeralKeySize
	}

	randKey := randomKey(size)
	b = new(big.Int).SetBytes(randKey)

	B = new(big.Int)
	var (
		term1 = new(big.Int)
		term2 = new(big.Int)
	)
	term1.Mul(k, v)
	term1.Mod(term1, group.N)
	term2.Exp(group.Generator, b, group.N)
	B.Add(term1, term2)
	B.Mod(B, group.N)

	return
}

// makeClientKeyPair creates a client's ephemeral key pair
// (a, A).
func makeClientKeyPair(group *Group) (a *big.Int, A *big.Int) {
	size := group.ExponentSize
	if group.ExponentSize < minEphemeralKeySize {
		size = minEphemeralKeySize
	}

	randKey := make([]byte, size)
	if _, err := rand.Read(randKey); err != nil {
		panic(fmt.Errorf("failed to get random bytes: %v", err))
	}

	a = new(big.Int).SetBytes(randKey)
	A = new(big.Int).Exp(group.Generator, a, group.N)
	return
}

// isValidEphemeral returns true if i is valid
// public ephemeral key for the given group.
func isValidEphemeralKey(group *Group, i *big.Int) bool {
	r := new(big.Int)
	if r.Mod(i, group.N); r.Sign() == 0 {
		return false
	}

	if r.GCD(nil, nil, i, group.N).Cmp(bigOne) != 0 {
		return false
	}

	return true
}

// randomKey returns a new random key
// with the given length.
func randomKey(length int) []byte {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Errorf("failed to get random bytes: %v", err))
	}
	return b
}

// pad left-pads b with zeros until it reaches the
// desired length in bits.
func pad(b []byte, bits int) ([]byte, error) {
	length := bits / 8
	padding := length - len(b)
	if padding < 0 {
		return nil, errors.New("padding cannot be negative")
	}

	padded := make([]byte, padding, length)
	padded = append(padded, b...)
	if len(padded) != length {
		return nil, errors.New("resulting array is not the right size")
	}
	return padded, nil
}

// xorBytes returns an array containing
// the result of of a[i] XOR b[i].
func xorBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("slices must be of equal length")
	}
	output := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		output[i] = a[i] ^ b[i]
	}
	return output, nil
}
