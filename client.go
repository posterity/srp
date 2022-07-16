package srp

import (
	"errors"
	"math/big"
)

// ErrClientNotReady is returned when the client
// is not ready for the invoked action.
var ErrClientNotReady = errors.New("server's public ephemeral key (B) must be set first")

// Client represents the client-side perspective of an SRP
// session.
type Client struct {
	username []byte   // (a.k.a. identity)
	salt     []byte   // User salt
	x        *big.Int // User's derived secret
	a        *big.Int // Client private ephemeral
	xA       *big.Int // Client public ephemeral
	xB       *big.Int // Server public ephemeral
	m1       *big.Int // Client proof
	m2       *big.Int // Server proof
	xS       *big.Int // Pre-master key
	xK       []byte   // Session key
	group    *Group   // D-H group
}

// SetB configures the server's public ephemeral key (B).
func (c *Client) SetB(public []byte) error {
	B := new(big.Int).SetBytes(public)
	if !isValidEphemeralKey(c.group, B) {
		return errors.New("invalid public exponent")
	}

	k, err := computeLittleK(c.group)
	if err != nil {
		return err
	}

	u, err := computeLittleU(c.group, c.xA, B)
	if err != nil {
		return err
	}
	if u.Cmp(bigZero) == 0 {
		return errors.New("invalid u value")
	}

	S, err := computeClientS(c.group, k, c.x, u, B, c.a)
	if err != nil {
		return err
	}

	K := c.group.hashBytes(S.Bytes())

	M1, err := computeM1(c.group, c.username, c.salt, c.xA, B, K)
	if err != nil {
		return err
	}

	M2, err := computeM2(c.group, c.xA, M1, K)
	if err != nil {
		return err
	}

	c.xB = B
	c.m1 = M1
	c.m2 = M2
	c.xS = S
	c.xK = K
	return nil
}

// A returns the public ephemeral key
// (A) of this client.
func (c *Client) A() []byte {
	return c.xA.Bytes()
}

// ComputeM1 returns the proof (M1) which should be
// sent to the server.
func (c *Client) ComputeM1() ([]byte, error) {
	if c.m1 == nil {
		return nil, ErrClientNotReady
	}
	return c.m1.Bytes(), nil
}

// CheckM2 returns true if the server proof M2 is verified.
func (c *Client) CheckM2(M2 []byte) (bool, error) {
	if c.m2 == nil {
		return false, ErrClientNotReady
	}

	return checkProof(c.m2.Bytes(), M2), nil
}

// SessionKey returns the session key that will be shared with the
// server.
func (c *Client) SessionKey() ([]byte, error) {
	if c.xK == nil {
		return nil, ErrClientNotReady
	}

	h := c.group.Hash.New()
	digest := h.Sum(c.xK)[:h.Size()]
	return digest, nil
}

// NewClient a new SRP client instance.
func NewClient(group *Group, username, password string, salt []byte) (*Client, error) {
	if _, ok := Groups[group.Name]; !ok {
		return nil, ErrUnknownGroup
	}

	x, err := group.KDF(username, password, salt)
	if err != nil {
		return nil, err
	}

	a, A := newClientKeyPair(group)

	c := &Client{
		username: []byte(username),
		salt:     salt,
		x:        new(big.Int).SetBytes(x),
		a:        a,
		xA:       A,
		group:    group,
	}
	return c, nil
}

// ComputeVerifier computes a verifier value from the user's
// username, password and salt.
//
// The function is called client-side to generate a triplet
// containing the information that should be sent to the server
// over a secure connection (TLS), and stored in a secure
// persistent-storage (e.g. database).
func ComputeVerifier(group *Group, username, password string, salt []byte) (Triplet, error) {
	if _, ok := Groups[group.Name]; !ok {
		return nil, ErrUnknownGroup
	}

	x, err := group.KDF(username, password, salt)
	if err != nil {
		return nil, err
	}

	v := new(big.Int).Exp(group.Generator, new(big.Int).SetBytes(x), group.N)
	return NewTriplet(username, salt, v.Bytes()), nil
}
