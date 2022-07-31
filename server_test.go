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

func TestServerReset(t *testing.T) {
	s, err := NewServer(params, string(I), salt.Bytes(), v.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	s.SetA(A.Bytes())

	M1, err := computeM1(params, I, salt.Bytes(), A, s.xB, s.xK)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := s.CheckM1(M1.Bytes()); !ok {
		t.Fatalf("M1 not verified: %v", err)
	}

	if !s.verifiedM1 {
		t.Fatal("expected M1 to be verified")
	}

	s.Reset(params, string(I), salt.Bytes(), v.Bytes())
	if _, err := s.CheckM1(M1.Bytes()); err != ErrServerNoReady {
		t.Fatal("expected server to not be ready")
	}
	if s.verifiedM1 {
		t.Fatal("expected M1 to not be verified")
	}
}
