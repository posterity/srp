package srp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

func TestTriplet(t *testing.T) {
	tp := NewTriplet(string(I), v.Bytes(), salt.Bytes())
	assertEqualBytes(t, "username", I, []byte(tp.Username()))
	assertEqualBytes(t, "verifier", v.Bytes(), tp.Verifier())
	assertEqualBytes(t, "salt", salt.Bytes(), tp.Salt())
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

func TestTripletJSON(t *testing.T) {
	wanted := fmt.Sprintf(
		`{"salt":"%s","username":"%s"}`,
		base64.StdEncoding.EncodeToString(salt.Bytes()),
		string(I),
	)

	tp := NewTriplet(string(I), v.Bytes(), salt.Bytes())
	got, err := json.Marshal(tp)
	if err != nil {
		t.Fatal(err)
	}

	assertEqualBytes(t, "Triplet.json", []byte(wanted), got)
}
