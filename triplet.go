package srp

import (
	"bytes"
	"database/sql/driver"
	"errors"
	"fmt"
	"math"
	"unicode/utf8"
)

// Triplet holds the parameters the server
// should store in a single byte array.
//
// Triplet implements the interfaces of
// Go's sql package, and can therefore be stored
// as-is in any compatible database.
//
// A triplet is structured as follows:
// 	+------------------------+
// 	| usernameLen (1) 			 |
// 	+------------------------+
//  | username (usernameLen) |
// 	+------------------------+
//  | saltLen (1)						 |
// 	+------------------------+
//  | salt (saltLen)				 |
// 	+------------------------+
//  | verifier							 |
// 	+------------------------+
type Triplet []byte

// Value implements driver.Valuer
func (t Triplet) Value() (driver.Value, error) {
	return []byte(t), nil
}

// Scan implements sql.Scanner.
func (t *Triplet) Scan(v any) error {
	if v == nil {
		return nil
	}

	b, ok := v.([]byte)
	if !ok {
		return errors.New("v could not be cast to []byte")
	}

	*t = Triplet(b)
	return nil
}

// Username returns the username string in p, or an empty
// string if p is mis-formatted.
func (p Triplet) Username() string {
	usernameLen := int(p[0])
	return string(p[1 : 1+usernameLen])
}

// Salt returns the Salt in p, or an empty
// string if p is mis-formatted.
func (p Triplet) Salt() []byte {
	usernameLen := int(p[0])
	saltLen := int(p[usernameLen+1])
	return p[usernameLen+2 : usernameLen+2+saltLen]
}

// Verifier returns the verifier in p, or an empty
// string if p is mis-formatted.
func (p Triplet) Verifier() []byte {
	usernameLen := int(p[0])
	saltLen := int(p[usernameLen+1])
	return p[usernameLen+saltLen+2:]
}

// NewTriplet returns a new Triplet instance from the given
// username, verifier and salt.
//
// NewTriplet panics if the length of username or salt exceeds
// math.MaxUint8.
func NewTriplet(username string, verifier, salt []byte) Triplet {
	if utf8.RuneCountInString(username) > math.MaxUint8 {
		panic(fmt.Errorf("length of username cannot exceed %d", math.MaxUint8))
	}
	if len(salt) > math.MaxUint8 {
		panic(fmt.Errorf("length of salt cannot exceed %d", math.MaxUint8))
	}

	b := new(bytes.Buffer)
	b.WriteByte(byte(len(username)))
	b.WriteString(username)
	b.WriteByte(byte(len(salt)))
	b.Write(salt)
	b.Write(verifier)
	return b.Bytes()
}
