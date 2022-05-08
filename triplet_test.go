package srp

import (
	"testing"
)

func TestTriplet(t *testing.T) {
	tp := NewTriplet(string(I), v.Bytes(), salt.Bytes())
	assertEqualBytes(t, "username", I, []byte(tp.Username()))
	assertEqualBytes(t, "salt", salt.Bytes(), tp.Salt())
	assertEqualBytes(t, "verifier", v.Bytes(), tp.Verifier())
}

func TestTripleScanValue(t *testing.T) {
	wanted := NewTriplet(string(I), v.Bytes(), salt.Bytes())
	v, err := wanted.Value()
	if err != nil {
		t.Fatal(err)
	}

	got := make(Triplet, 0)
	if err := got.Scan(v); err != nil {
		t.Fatal(err)
	}

	assertEqualBytes(t, "Triplet", wanted, got)
}
