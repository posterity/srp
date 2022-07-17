// Package srp is an implementation of the Secure Remote Password
// protocol as defined in [RFC5054] and [RFC2945].
//
// It's based on the work of [1Password], with a few key changes to
// restore compatibility with the original RFCs, and to make the codebase
// more idiomatic.
//
// [RFC5054]: https://datatracker.ietf.org/doc/html/rfc5054
// [RFC2945]: https://datatracker.ietf.org/doc/html/rfc2945
// [1Password]: https://github.com/1Password/srp
package srp

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math/big"
)

var (
	bigZero = big.NewInt(0)
	bigOne  = big.NewInt(1)
)

// Smallest ephemeral key size allowed.
const minEphemeralKeySize = 32

// SaltLength represents the default length
// for a salt created with NewSalt.
const SaltLength = 12

// NewSalt returns a new random salt
// using rand.Reader.
func NewSalt() []byte {
	return randomKey(SaltLength)
}

// computeM1 computes the value of the client proof M1.
//
// Formula:
// 	M1 = H(H(N) XOR H(g) | H(U) | s | A | B | K)
func computeM1(params *Params, username, salt []byte, A, B *big.Int, K []byte) (*big.Int, error) {
	var (
		hN = params.hashBytes(params.Group.N.Bytes())
		hg = params.hashBytes(params.Group.Generator.Bytes())
		hU = params.hashBytes(username)
	)

	groupXOR, err := xorBytes(hN, hg)
	if err != nil {
		return nil, err
	}

	h := params.Hash.New()
	if _, err := h.Write(groupXOR); err != nil {
		return nil, fmt.Errorf("failed to write params hash to hasher: %w", err)
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
// 	M2 = H(A | M | K)
func computeM2(params *Params, A, M1 *big.Int, K []byte) (*big.Int, error) {
	h := params.Hash.New()
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
// 	S = (A * v^u) ^ b % N
func computeServerS(params *Params, v, u, A, b *big.Int) (*big.Int, error) {
	base := new(big.Int)
	base.Exp(v, u, params.Group.N)
	base.Mul(base, A)

	S := new(big.Int).Exp(base, b, params.Group.N)
	return S, nil
}

// computeClientK returns the encryption key
// derived by a client from a session.
//
// Formula:
// 	S = (B - (k * g ^ x)) ^ (a + (u * x)) % N
func computeClientS(params *Params, k, x, u, B, a *big.Int) (*big.Int, error) {
	// (k * g ^ x)
	product := new(big.Int).Mul(k, new(big.Int).Exp(params.Group.Generator, x, params.Group.N))

	// (B - (k * g ^ x))
	base := new(big.Int).Sub(B, product)

	// (a + (u * x))
	exp := new(big.Int).Add(a, new(big.Int).Mul(u, x))

	// (B - (k * g ^ x)) ^ (a + (u * x)) % N
	S := new(big.Int).Exp(base, exp, params.Group.N)
	return S, nil
}

// computeLittleK computes the value of k.
//
// Formula:
// 	k = H(N | PAD(g))
func computeLittleK(params *Params) (*big.Int, error) {
	g, err := pad(params.Group.Generator.Bytes(), params.Group.N.BitLen())
	if err != nil {
		return nil, fmt.Errorf("failed to pad g")
	}

	h := params.Hash.New()
	if _, err := h.Write(params.Group.N.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to write N to hasher: %w", err)
	}
	if _, err = h.Write(g); err != nil {
		return nil, fmt.Errorf("failed to write g to hasher: %w", err)
	}

	digest := h.Sum(nil)[:h.Size()]
	return new(big.Int).SetBytes(digest), nil
}

// computeLittleU computes the value of u.
//
// Formula:
// 	u = SHA1(PAD(A) | PAD(B))
func computeLittleU(params *Params, A, B *big.Int) (*big.Int, error) {
	if A == nil {
		return nil, errors.New("client public ephemeral A must be set first")
	}

	bA, err := pad(A.Bytes(), params.Group.N.BitLen())
	if err != nil {
		return nil, fmt.Errorf("failed to pad A: %w", err)
	}

	bB, err := pad(B.Bytes(), params.Group.N.BitLen())
	if err != nil {
		return nil, fmt.Errorf("failed to pad B: %w", err)
	}

	h := params.Hash.New()
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

// newServerKeyPair creates a server's ephemeral key pair
// (b, B).
//
// Formula:
// 	b = random()
// 	B = k*v + g^b % N
func newServerKeyPair(params *Params, k, v *big.Int) (b *big.Int, B *big.Int) {
	size := params.Group.ExponentSize
	if params.Group.ExponentSize < minEphemeralKeySize {
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
	term1.Mod(term1, params.Group.N)
	term2.Exp(params.Group.Generator, b, params.Group.N)
	B.Add(term1, term2)
	B.Mod(B, params.Group.N)

	return
}

// newClientKeyPair creates a client's ephemeral key pair
// (a, A).
//
// Formula:
// 	a = random()
// 	A = g^a % N
func newClientKeyPair(params *Params) (a *big.Int, A *big.Int) {
	size := params.Group.ExponentSize
	if params.Group.ExponentSize < minEphemeralKeySize {
		size = minEphemeralKeySize
	}

	randKey := randomKey(size)
	a = new(big.Int).SetBytes(randKey)
	A = new(big.Int).Exp(params.Group.Generator, a, params.Group.N)
	return
}

// isValidEphemeral returns true if i is valid
// public ephemeral key for the given params.
func isValidEphemeralKey(params *Params, i *big.Int) bool {
	r := new(big.Int)
	if r.Mod(i, params.Group.N); r.Sign() == 0 {
		return false
	}

	if r.GCD(nil, nil, i, params.Group.N).Cmp(bigOne) != 0 {
		return false
	}

	return true
}

// randomKey returns a new random key
// with the given length.
func randomKey(length int) []byte {
	b := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
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
// the result of a[i] XOR b[i].
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
