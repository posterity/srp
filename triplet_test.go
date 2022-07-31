package srp

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestTriplet(t *testing.T) {
	tp := NewTriplet(string(I), salt.Bytes(), v.Bytes())
	assertEqualBytes(t, "username", I, []byte(tp.Username()))
	assertEqualBytes(t, "salt", salt.Bytes(), tp.Salt())
	assertEqualBytes(t, "verifier", v.Bytes(), tp.Verifier())
}

func TestTripletMarshalJSON(t *testing.T) {
	tp := NewTriplet(string(I), salt.Bytes(), v.Bytes())
	b, err := tp.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}

	wanted := fmt.Sprintf(`{"salt":"%s","username":"%s"}`, base64.StdEncoding.EncodeToString(salt.Bytes()), string(I))
	if !bytes.Equal(b, []byte(wanted)) {
		t.Fatalf("Wanted: %s. Got: %s", wanted, string(b))
	}
}
