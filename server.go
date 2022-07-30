package srp

import (
	"encoding/json"
	"errors"
	"math/big"
)

// ErrServerNoReady is returned when the server
// is not ready for the invoked action.
var ErrServerNoReady = errors.New("client's public ephemeral key (A) must be set first")

// serverState holds information that allows
// a server instance to be restored.
type serverState struct {
	Triplet    []byte `json:"triplet"`
	LittleB    []byte `json:"b"`
	BigB       []byte `json:"B"`
	BigA       []byte `json:"A,omitempty"`
	VerifiedM1 bool   `json:"verifiedM1"`
}

// Server represents the server-side perspective of an SRP
// session.
type Server struct {
	triplet    Triplet  // User information
	xA         *big.Int // Client public ephemeral
	b          *big.Int // Server private ephemeral
	xB         *big.Int // Server public ephemeral
	m1         *big.Int // Client proof
	m2         *big.Int // Server proof
	xS         *big.Int // Pre-master key
	xK         []byte   // Session key
	params     *Params  // Params combination
	err        error    // Tracks any systemic errors
	verifiedM1 bool     // Tracks if the client proof was successfully checked
}

// SetA configures the public ephemeral key
// (B) of this server.
func (s *Server) SetA(public []byte) error {
	A := new(big.Int).SetBytes(public)
	if !isValidEphemeralKey(s.params, A) {
		return errors.New("invalid public exponent")
	}

	var (
		username = []byte(s.triplet.Username())
		salt     = s.triplet.Salt()
		v        = new(big.Int).SetBytes(s.triplet.Verifier())
	)

	u, err := computeLittleU(s.params, A, s.xB)
	if err != nil {
		return err
	}

	S, err := computeServerS(s.params, v, u, A, s.b)
	if err != nil {
		return err
	}

	K := s.params.hashBytes(S.Bytes())

	M1, err := computeM1(s.params, username, salt, A, s.xB, K)
	if err != nil {
		return err
	}

	M2, err := computeM2(s.params, A, M1, K)
	if err != nil {
		return err
	}

	s.xA = A
	s.m1 = M1
	s.m2 = M2
	s.xS = S
	s.xK = K
	return nil
}

// B returns the server's public ephemeral key B.
func (s *Server) B() []byte {
	return s.xB.Bytes()
}

// CheckM1 returns true if the client proof M1 is verified.
func (s *Server) CheckM1(M1 []byte) (bool, error) {
	if s.err != nil {
		return false, s.err
	}

	if s.m1 == nil {
		return false, ErrServerNoReady
	}

	if checkProof(s.m1.Bytes(), M1) {
		s.verifiedM1 = true
	} else {
		s.verifiedM1 = false
		s.err = errors.New("failed to verify client proof M1")
	}

	return s.verifiedM1, nil
}

// ComputeM2 returns the proof (M2) which should be sent
// to the client.
//
// An error is returned if the client's proof (M1) has
// not been checked by calling the s.CheckM1 method first.
func (s *Server) ComputeM2() ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.m2 == nil {
		return nil, ErrServerNoReady
	}
	if !s.verifiedM1 {
		return nil, errors.New("client must show their proof first")
	}
	return s.m2.Bytes(), nil
}

// SessionKey returns the session key that will be shared with the
// client.
//
// An error is returned if the client's proof (M1) has
// not been checked by calling the s.CheckM1 method first.
func (s *Server) SessionKey() ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.xK == nil {
		return nil, ErrServerNoReady
	}

	return s.xK, nil
}

// MarshalJSON returns a JSON object representing
// the current state of s.
func (s *Server) MarshalJSON() ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}

	state := &serverState{
		Triplet:    s.triplet,
		LittleB:    s.b.Bytes(),
		BigB:       s.xB.Bytes(),
		VerifiedM1: s.verifiedM1,
	}
	if s.xA != nil {
		state.BigA = s.xA.Bytes()
	}

	return json.Marshal(state)
}

// UnmarshalJSON restores from an existing state object
// obtained with MarshalJSON.
func (s *Server) UnmarshalJSON(data []byte) error {
	state := &serverState{}
	if err := json.Unmarshal(data, state); err != nil {
		return err
	}

	s.triplet = nil
	s.xA = nil
	s.b = nil
	s.xB = nil
	s.m1 = nil
	s.m2 = nil
	s.xS = nil
	s.xK = nil
	s.err = nil
	s.verifiedM1 = false

	s.triplet = state.Triplet
	s.b = new(big.Int).SetBytes(state.LittleB)
	s.xB = new(big.Int).SetBytes(state.BigB)
	s.verifiedM1 = state.VerifiedM1

	if state.BigA != nil {
		return s.SetA(state.BigA)
	}

	return nil
}

// Save encodes the current state of s in a JSON object.
// Use [RestoreServer] to restore a previously saved state.
func (s *Server) Save() ([]byte, error) {
	return s.MarshalJSON()
}

// RestoreServer restores a server from a previous state obtained
// with [Server.Save].
func RestoreServer(params *Params, state []byte) (*Server, error) {
	s := &Server{
		params: params,
	}
	if err := json.Unmarshal(state, s); err != nil {
		return nil, err
	}
	return s, nil
}

// Reset resets s to its initial state.
func (s *Server) Reset(params *Params, username string, salt, verifier []byte) error {
	k, err := computeLittleK(params)
	if err != nil {
		return err
	}

	s.triplet = NewTriplet(username, salt, verifier)
	s.xA = nil
	s.b, s.xB = newServerKeyPair(params, k, new(big.Int).SetBytes(verifier))
	s.m1 = nil
	s.m2 = nil
	s.xS = nil
	s.xK = nil
	s.params = params
	s.err = nil
	s.verifiedM1 = false

	return nil
}

// NewServer returns a new SRP server instance.
func NewServer(params *Params, username string, salt, verifier []byte) (*Server, error) {
	s := &Server{}
	return s, s.Reset(params, username, salt, verifier)
}
