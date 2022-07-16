package srp

import (
	"crypto"
	"testing"
)

func TestClone(t *testing.T) {
	var (
		name = "g"
		h    = crypto.SHA256
		kdf  = func(username, password string, salt []byte) ([]byte, error) {
			return []byte("test"), nil
		}
	)
	g := RFC5054Group2048.Clone(name, h, kdf)
	if g.Name != name {
		t.Error("failed to set name")
	}
	if g.Hash.String() != h.String() {
		t.Error("failed to set hash")
	}
	if b, err := g.KDF("", "", []byte("")); string(b) != "test" && err != nil {
		t.Error("failed to set KDF")
	}
}
