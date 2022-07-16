package srp

import (
	"bytes"
	"fmt"
	"math"
)

// Triplet holds the parameters the server
// should store in a single byte array.
//
// Triplet implements the interfaces of
// Go's sql package, and can therefore be stored
// as-is in any compatible database.
//
// A triplet is structured as following:
// 	+------------------------+
// 	| usernameLen (1)        |
// 	+------------------------+
//  | username (usernameLen) |
// 	+------------------------+
//  | saltLen (1)            |
// 	+------------------------+
//  | salt (saltLen)         |
// 	+------------------------+
//  | verifier               |
// 	+------------------------+
type Triplet []byte

// Username returns the username string in p, or an empty
// string if p is mis-formatted.
func (t Triplet) Username() string {
	usernameLen := int(t[0])
	return string(t[1 : 1+usernameLen])
}

// Salt returns the Salt in p, or an empty
// string if p is mis-formatted.
func (t Triplet) Salt() []byte {
	usernameLen := int(t[0])
	saltLen := int(t[usernameLen+1])
	return t[usernameLen+2 : usernameLen+2+saltLen]
}

// Verifier returns the verifier in p, or an empty
// string if p is mis-formatted.
func (t Triplet) Verifier() []byte {
	usernameLen := int(t[0])
	saltLen := int(t[usernameLen+1])
	return t[usernameLen+saltLen+2:]
}

// NewTriplet returns a new Triplet instance from the given
// username, verifier and salt.
//
// NewTriplet panics if the length of username or salt exceeds
// math.MaxUint8.
func NewTriplet(username string, salt, verifier []byte) Triplet {
	if len(username) > math.MaxUint8 {
		panic(fmt.Errorf("username length cannot exceed %d bytes", math.MaxUint8))
	}
	if len(salt) > math.MaxInt8 {
		panic(fmt.Errorf("salt length cannot exceed %d", math.MaxUint8))
	}

	var b bytes.Buffer
	b.Grow(1 + len(username) + 1 + len(salt) + len(verifier))
	b.WriteByte(byte(len(username)))
	b.WriteString(username)
	b.WriteByte(byte(len(salt)))
	b.Write(salt)
	b.Write(verifier)
	return b.Bytes()
}
