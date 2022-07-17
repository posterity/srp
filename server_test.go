package srp

import "testing"

func TestRestoreServerJSON(t *testing.T) {
	server, err := NewServer(params, string(I), salt.Bytes(), v.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if err := server.SetA(A.Bytes()); err != nil {
		t.Fatal(err)
	}

	state, err := server.Save()
	if err != nil {
		t.Fatal(err)
	}

	restored, err := RestoreServer(params, state)
	if err != nil {
		t.Fatal(err)
	}

	assertEqualBytes(t, "triplet", server.triplet, restored.triplet)
	assertEqualBytes(t, "b", server.b.Bytes(), restored.b.Bytes())
	assertEqualBytes(t, "B", server.xB.Bytes(), restored.xB.Bytes())
	assertEqualBytes(t, "A", server.xA.Bytes(), restored.xA.Bytes())
	assertEqualBytes(t, "S", server.xS.Bytes(), restored.xS.Bytes())
	assertEqualBytes(t, "K", server.xK, restored.xK)
}
