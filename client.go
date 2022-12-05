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
	params   *Params  // Params combination
}

// SetB configures the server's public ephemeral key (B).
func (c *Client) SetB(public []byte) error {
	B := new(big.Int).SetBytes(public)
	if !isValidEphemeralKey(c.params, B) {
		return errors.New("invalid public exponent")
	}

	k, err := computeLittleK(c.params)
	if err != nil {
		return err
	}

	u, err := computeLittleU(c.params, c.xA, B)
	if err != nil {
		return err
	}
	if u.Cmp(bigZero) == 0 {
		return errors.New("invalid u value")
	}

	S, err := computeClientS(c.params, k, c.x, u, B, c.a)
	if err != nil {
		return err
	}

	K := c.params.hashBytes(S.Bytes())

	M1, err := computeM1(c.params, c.username, c.salt, c.xA, B, K)
	if err != nil {
		return err
	}

	M2, err := computeM2(c.params, c.xA, M1, K)
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

	h := c.params.Hash.New()
	digest := h.Sum(c.xK)[:h.Size()]
	return digest, nil
}

// NewClient a new SRP client instance.
func NewClient(params *Params, username, password string, salt []byte) (*Client, error) {
	x, err := params.KDF(NFKD(username), NFKD(password), salt)
	if err != nil {
		return nil, err
	}

	a, A := newClientKeyPair(params)

	c := &Client{
		username: []byte(username),
		salt:     salt,
		x:        new(big.Int).SetBytes(x),
		a:        a,
		xA:       A,
		params:   params,
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
func ComputeVerifier(params *Params, username, password string, salt []byte) (Triplet, error) {
	x, err := params.KDF(NFKD(username), NFKD(password), salt)
	if err != nil {
		return nil, err
	}

	v := new(big.Int).Exp(params.Group.Generator, new(big.Int).SetBytes(x), params.Group.N)
	return NewTriplet(username, salt, v.Bytes()), nil
}
