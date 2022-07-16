package srp

import (
	"testing"
)

func TestTriplet(t *testing.T) {
	tp := NewTriplet(string(I), salt.Bytes(), v.Bytes())
	assertEqualBytes(t, "username", I, []byte(tp.Username()))
	assertEqualBytes(t, "salt", salt.Bytes(), tp.Salt())
	assertEqualBytes(t, "verifier", v.Bytes(), tp.Verifier())
}
