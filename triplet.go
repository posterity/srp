package srp

import (
	"bytes"
	"database/sql/driver"
	"errors"
	"strings"
)

// tripletSep is the separator.
const tripletSep = ","

// Triplet holds the parameters the server
// should store in a single byte array.
//
// Triplet implements the interfaces of
// Go's sql package, and can therefore be stored
// as-is in any compatible database.
type Triplet []byte

// Value implements driver.Valuer
func (t Triplet) Value() (driver.Value, error) {
	return []byte(t), nil
}

// Scan implements sql.Scanner.
func (t *Triplet) Scan(v any) error {
	b, ok := v.([]byte)
	if !ok {
		return errors.New("v could not be converted to a []byte")
	}

	*t = Triplet(b)
	return nil
}

// Username returns the Username string in p, or an empty
// string if p is mis-formatted.
func (p Triplet) Username() string {
	parts := strings.SplitN(string(p), tripletSep, 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[0]
}

// Verifier returns the verifier in p, or an empty
// string if p is mis-formatted.
func (p Triplet) Verifier() []byte {
	parts := bytes.SplitN(p, []byte(tripletSep), 3)
	if len(parts) != 3 {
		return nil
	}
	return parts[1]
}

// Salt returns the Salt in p, or an empty
// string if p is mis-formatted.
func (p Triplet) Salt() []byte {
	parts := bytes.SplitN(p, []byte(tripletSep), 3)
	if len(parts) != 3 {
		return nil
	}
	return parts[2]
}

// NewTriplet returns a new Triplet instance, essentially a concatenation
// of all three values.
func NewTriplet(Username string, verifier, salt []byte) Triplet {
	parts := [][]byte{[]byte(Username), verifier, salt}
	return bytes.Join(parts, []byte(tripletSep))
}
