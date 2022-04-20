package srp

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// session holds information that would
// allow a server instance to be restored.
type session struct {
	Group      string `json:"group"`
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
	xS         *big.Int // Premaster key (testing-only)
	xK         []byte   // Session key
	group      *Group   // D-H group
	err        error    // Tracks any systemic errors
	verifiedM1 bool     // Tracks if the client proof was successfully checked
}

// SetA configures the public ephemeral key
// (B) of this server.
func (s *Server) SetA(public []byte) error {
	A := new(big.Int).SetBytes(public)
	if !isValidEphemeralKey(s.group, A) {
		return errors.New("invalid public exponent")
	}

	var (
		username = []byte(s.triplet.Username())
		salt     = s.triplet.Salt()
		v        = new(big.Int).SetBytes(s.triplet.Verifier())
	)

	u, err := computeLittleU(s.group, A, s.xB)
	if err != nil {
		return err
	}

	S, err := computeServerS(s.group, v, u, A, s.b)
	if err != nil {
		return err
	}

	K := s.group.hashBytes(S.Bytes())

	M1, err := computeM1(s.group, username, salt, A, s.xB, K)
	if err != nil {
		return err
	}

	M2, err := computeM2(s.group, A, M1, K)
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
		return false, errors.New("client's public ephemeral key (A) must be set first")
	}

	if !checkProof(s.m1.Bytes(), M1) {
		s.err = errors.New("failed to verify client proof M1")
		return false, s.err
	}

	s.verifiedM1 = true
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
		return nil, errors.New("client's public ephemeral key (A) must be set first")
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
		return nil, errors.New("client's public ephemeral key (A) must be set first")
	}

	return s.xK, nil
}

// MarshalJSON returns a JSON object representing
// the current state of s.
func (s *Server) MarshalJSON() ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}

	ses := &session{
		Group:      s.group.Name,
		Triplet:    s.triplet,
		LittleB:    s.b.Bytes(),
		BigB:       s.xB.Bytes(),
		VerifiedM1: s.verifiedM1,
	}
	if s.xA != nil {
		ses.BigA = s.xA.Bytes()
	}

	return json.Marshal(ses)
}

// UnmarshalJSON restores from an existing state object
// obtained with MarshalJSON.
func (s *Server) UnmarshalJSON(data []byte) error {
	ses := &session{}
	if err := json.Unmarshal(data, ses); err != nil {
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
	s.group = nil
	s.err = nil
	s.verifiedM1 = false

	group, ok := registeredGroups[ses.Group]
	if !ok {
		return fmt.Errorf("unregistered custom group \"%s\"", ses.Group)
	}

	s.group = group
	s.triplet = ses.Triplet
	s.b = new(big.Int).SetBytes(ses.LittleB)
	s.xB = new(big.Int).SetBytes(ses.BigB)
	s.verifiedM1 = ses.VerifiedM1

	if ses.BigA != nil {
		return s.SetA(ses.BigA)
	}

	return nil
}

// GobEncode implements gob.Encoder.
func (s *Server) GobEncode() ([]byte, error) {
	return s.MarshalJSON()
}

// GobDecode implements gob.Decoder.
func (s *Server) GobDecode(data []byte) error {
	return s.UnmarshalJSON(data)
}

// NewServer returns a new SRP server instance.
func NewServer(group *Group, username string, salt, verifier []byte) (*Server, error) {
	if _, ok := registeredGroups[group.Name]; !ok {
		return nil, errUnregisteredGroup
	}

	k, err := computeLittleK(group)
	if err != nil {
		return nil, err
	}

	v := new(big.Int).SetBytes(verifier)
	b, B := makeServerKeyPair(group, k, v)

	s := &Server{
		triplet: NewTriplet(username, verifier, salt),
		b:       b,
		xB:      B,
		group:   group,
	}
	return s, nil
}
