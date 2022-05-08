package srp

import (
	"bytes"
	"crypto"
	_ "crypto/sha1"
	_ "embed"
	"encoding/hex"
	"errors"
	"log"
	"math/big"
	"strings"
	"testing"
)

//go:embed groups/1024.txt
var hex1024 string

// Deprecated: This group is part of the RFC, but
// should not be used in production. It's implemented for
// testing purposes only.
var group = &Group{
	Name:         "1024",
	Generator:    big.NewInt(2),
	N:            mustParseHex(hex1024),
	ExponentSize: 32,
	Hash:         crypto.SHA1,
	Derive: func(username, password string, salt []byte) ([]byte, error) {
		return RFC5054KDF(crypto.SHA1.New(), username, password, salt)
	},
}

// Test vectors imported from RFC 5054 – Appendix B
// https://datatracker.ietf.org/doc/html/rfc5054#appendix-B
var (
	I    = []byte("alice")
	P    = []byte("password123")
	x    = MustParseHex("94B7555A ABE9127C C58CCF49 93DB6CF8 4D16C124")
	salt = MustParseHex("BEB25379 D1A8581E B5A72767 3A2441EE")
	k    = MustParseHex("7556AA04 5AEF2CDD 07ABAF0F 665C3E81 8913186F")
	v    = MustParseHex(
		"7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812",
		"9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5",
		"C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5",
		"EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78",
		"E955A5E2 9E7AB245 DB2BE315 E2099AFB",
	)
	a = MustParseHex(
		"60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD",
		"DA2D4393",
	)
	A = MustParseHex(
		"61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4",
		"4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC",
		"8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44",
		"BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA",
		"B349EF5D 76988A36 72FAC47B 0769447B",
	)
	b = MustParseHex(
		"E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4 9E61F5D1",
		"05284D20",
	)
	B = MustParseHex(
		"BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011",
		"BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99",
		"6C6DA044 53728610 D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA",
		"37089E6F 9C6059F3 88838E7A 00030B33 1EB76840 910440B1 B27AAEAE",
		"EB4012B7 D7665238 A8E3FB00 4B117B58",
	)
	u = MustParseHex("CE38B959 3487DA98 554ED47D 70A7AE5F 462EF019")
	S = MustParseHex(
		"B0DC82BA BCF30674 AE450C02 87745E79 90A3381F 63B387AA F271A10D",
		"233861E3 59B48220 F7C4693C 9AE12B0A 6F67809F 0876E2D0 13800D6C",
		"41BB59B6 D5979B5C 00A172B4 A2A5903A 0BDCAF8A 709585EB 2AFAFA8F",
		"3499B200 210DCC1F 10EB3394 3CD67FC8 8A2F39A4 BE5BEC4E C0A3212D",
		"C346D7E4 74B29EDE 8A469FFE CA686E5A",
	)
	K = group.Hash.New().Sum(S.Bytes())[:group.Hash.New().Size()]
)

// MustParseHex returns a *big.Int instance
// from the given hex string, or panics.
func MustParseHex(parts ...string) *big.Int {
	builder := new(strings.Builder)
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.ReplaceAll(p, " ", "")
		p = strings.ReplaceAll(p, "\r", "")
		p = strings.ReplaceAll(p, "\n", "")
		builder.WriteString(p)
	}

	n, ok := new(big.Int).SetString(builder.String(), 16)
	if !ok {
		panic(errors.New("failed to load group N"))
	}

	return n
}

// assertEqualBytes fails t if wanted != got
func assertEqualBytes(t *testing.T, name string, wanted, got []byte) {
	t.Helper()

	if !bytes.Equal(got, wanted) {
		t.Fatalf("%s - bytes don't match", name)
	}
}

// assertNotNil fails t if got == nil
func assertNotNil(t *testing.T, name string, got []byte) {
	t.Helper()

	if got == nil {
		t.Fatalf("%s should not be nil", name)
	}
}

func TestServerKeyPair(t *testing.T) {
	b, B := makeServerKeyPair(group, k, v)
	if b == bigZero {
		t.Fatal("b should not be bigZero")
	}

	if !isValidEphemeralKey(group, B) {
		t.Fatal("B is an invalid ephemeral key")
	}
}

func TestClientKeyPair(t *testing.T) {
	a, A := makeClientKeyPair(group)
	if a == bigZero {
		t.Fatal("a should not be bigZero")
	}

	if !isValidEphemeralKey(group, A) {
		t.Fatal("A is an invalid ephemeral key")
	}
}

func TestComputeLittleU(t *testing.T) {
	got, err := computeLittleU(group, A, B)
	if err != nil {
		t.Fatal(err)
	}

	assertEqualBytes(t, "u", u.Bytes(), got.Bytes())
}

func TestComputeLittleK(t *testing.T) {
	got, err := computeLittleK(group)
	if err != nil {
		t.Fatal(err)
	}

	assertEqualBytes(t, "k", k.Bytes(), got.Bytes())
}

func TestComputeS(t *testing.T) {
	t.Run("Server", func(t *testing.T) {
		got, err := computeServerS(group, v, u, A, b)
		if err != nil {
			t.Fatal(err)
		}

		assertEqualBytes(t, "S", S.Bytes(), got.Bytes())
	})

	t.Run("Client", func(t *testing.T) {
		got, err := computeClientS(group, k, x, u, B, a)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(hex.EncodeToString(got.Bytes()))
		assertEqualBytes(t, "S", S.Bytes(), got.Bytes())
	})
}

func TestComputeLittleX(t *testing.T) {
	got, err := group.Derive(string(I), string(P), salt.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	assertEqualBytes(t, "x", x.Bytes(), got)
}

func TestComputeVerifier(t *testing.T) {
	got, err := ComputeVerifier(group, string(I), string(P), salt.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	assertEqualBytes(t, "v", v.Bytes(), got.Verifier())
}

func TestComputeM(t *testing.T) {
	M1, err := computeM1(group, I, salt.Bytes(), A, B, K)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := computeM2(group, A, M1, K); err != nil {
		t.Fatal(err)
	}
}

func TestNewServer(t *testing.T) {
	s, err := NewServer(group, string(I), salt.Bytes(), v.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	assertEqualBytes(t, "v", s.triplet.Verifier(), v.Bytes())
	if s.b == nil || s.b.Cmp(bigZero) == 0 {
		t.Fatal("s.b is nil or invalid")
	}
	if s.xB == nil || !isValidEphemeralKey(s.group, s.xB) {
		t.Fatal("s.xB is nil or invalid")
	}
	assertEqualBytes(t, "username", []byte(s.triplet.Username()), I)
	assertEqualBytes(t, "salt", s.triplet.Salt(), salt.Bytes())
}

func TestServerSetA(t *testing.T) {
	s, err := NewServer(group, string(I), salt.Bytes(), v.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if err := s.SetA(A.Bytes()); err != nil {
		t.Fatal(err)
	}
	assertEqualBytes(t, "A", s.xA.Bytes(), A.Bytes())

	assertNotNil(t, "s.m1", s.m1.Bytes())
	assertNotNil(t, "s.m2", s.m2.Bytes())
	assertNotNil(t, "s.xS", s.xS.Bytes())
	assertNotNil(t, "s.xK", s.xK)
}

func TestNewClient(t *testing.T) {
	c, err := NewClient(group, string(I), string(P), salt.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	assertEqualBytes(t, "x", c.x.Bytes(), x.Bytes())
	if c.a == nil || c.a.Cmp(bigZero) == 0 {
		t.Fatal("c.a is nil or invalid")
	}
	if c.xA == nil || !isValidEphemeralKey(c.group, c.xA) {
		t.Fatal("c.xA is nil or invalid")
	}
	assertEqualBytes(t, "username", c.username, I)
	assertEqualBytes(t, "salt", c.salt, salt.Bytes())
}

func TestClientSetB(t *testing.T) {
	c, err := NewClient(group, string(I), string(P), salt.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if err := c.SetB(B.Bytes()); err != nil {
		t.Fatal(err)
	}
	assertEqualBytes(t, "B", c.xB.Bytes(), B.Bytes())
	if c.m1 == nil {
		t.Fatal("c.m1 should not be nil")
	}
	if c.m2 == nil {
		t.Fatal("c.m1 should not be nil")
	}
	if c.xS == nil {
		t.Fatal("c.xS should not be nil")
	}
	if c.xK == nil {
		t.Fatal("c.xK should not be nil")
	}

	assertNotNil(t, "c.m1", c.m1.Bytes())
	assertNotNil(t, "c.m2", c.m2.Bytes())
	assertNotNil(t, "c.xS", c.xS.Bytes())
	assertNotNil(t, "c.xK", c.xK)
}

func TestCheckM1(t *testing.T) {
	M1, err := computeM1(group, I, salt.Bytes(), A, B, K)
	if err != nil {
		t.Fatal(err)
	}

	if !checkProof(M1.Bytes(), M1.Bytes()) {
		t.Fatal("checkProof failed")
	}

	if checkProof(M1.Bytes(), bigZero.Bytes()) {
		t.Fatal("checkProof should have failed")
	}
}

func TestSession(t *testing.T) {
	client, err := NewClient(group, string(I), string(P), salt.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	server, err := NewServer(group, string(I), salt.Bytes(), v.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if err := server.SetA(client.A()); err != nil {
		t.Fatal(err)
	}

	if err := client.SetB(server.B()); err != nil {
		t.Fatal(err)
	}

	M1, err := client.ComputeM1()
	if err != nil {
		t.Fatal(err)
	}

	// Server Check M1
	clientOK, err := server.CheckM1(M1)
	if err != nil {
		t.Fatal(err)
	}
	if !clientOK {
		t.Fatal("client is not authentic")
	}

	M2, err := server.ComputeM2()
	if err != nil {
		t.Fatal(err)
	}

	// Client checks M2
	serverOK, err := client.CheckM2(M2)
	if err != nil {
		t.Fatal(err)
	}
	if !serverOK {
		t.Fatal("server is not authentic")
	}

	// Compare keys
	cK, err := client.SessionKey()
	if err != nil {
		t.Fatal(err)
	}
	sK, err := server.SessionKey()
	if err != nil {
		t.Fatal(err)
	}
	assertEqualBytes(t, "K", cK, sK)
}

func TestSessionProofOrder(t *testing.T) {
	server, err := NewServer(group, string(I), salt.Bytes(), v.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if err := server.SetA(A.Bytes()); err != nil {
		t.Fatal(err)
	}

	if _, err := server.ComputeM2(); err == nil {
		t.Fatal("expected an error here, because server.CheckM1 has not been called yet")
	}
}

func TestUnregisteredGroup(t *testing.T) {
	g := &Group{
		Name: "Custom Group",
	}

	_, err := NewServer(g, string(I), salt.Bytes(), v.Bytes())
	if err != errUnregisteredGroup {
		t.Fatal("expected errUnregisteredGroup error")
	}

	_, err = NewClient(g, string(I), string(P), salt.Bytes())
	if err != errUnregisteredGroup {
		t.Fatal("expected errUnregisteredGroup error")
	}

	_, err = ComputeVerifier(g, string(I), string(P), salt.Bytes())
	if err != errUnregisteredGroup {
		t.Fatal("expected errUnregisteredGroup error")
	}
}

func TestRegisterGroup(t *testing.T) {
	g := &Group{
		Name: "Custom Group",
	}

	if err := Register(g); err != nil {
		t.Fatal(err)
	}

	if err := Register(g); err == nil {
		t.Fatal(err)
	}
}

func TestRestoreServerJSON(t *testing.T) {
	server, err := NewServer(group, string(I), salt.Bytes(), v.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if err := server.SetA(A.Bytes()); err != nil {
		t.Fatal(err)
	}

	saved, err := server.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}

	newServer := &Server{}
	if err := newServer.UnmarshalJSON(saved); err != nil {
		t.Fatal(err)
	}

	assertEqualBytes(t, "triplet", server.triplet, newServer.triplet)
	assertEqualBytes(t, "b", server.b.Bytes(), newServer.b.Bytes())
	assertEqualBytes(t, "B", server.xB.Bytes(), newServer.xB.Bytes())
	assertEqualBytes(t, "A", server.xA.Bytes(), newServer.xA.Bytes())
	assertEqualBytes(t, "S", server.xS.Bytes(), newServer.xS.Bytes())
	assertEqualBytes(t, "K", server.xK, newServer.xK)
}

func TestRestoreServerGob(t *testing.T) {
	server, err := NewServer(group, string(I), salt.Bytes(), v.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if err := server.SetA(A.Bytes()); err != nil {
		t.Fatal(err)
	}

	saved, err := server.GobEncode()
	if err != nil {
		t.Fatal(err)
	}

	newServer := &Server{}
	if err := newServer.GobDecode(saved); err != nil {
		t.Fatal(err)
	}

	assertEqualBytes(t, "triplet", server.triplet, newServer.triplet)
	assertEqualBytes(t, "b", server.b.Bytes(), newServer.b.Bytes())
	assertEqualBytes(t, "B", server.xB.Bytes(), newServer.xB.Bytes())
	assertEqualBytes(t, "A", server.xA.Bytes(), newServer.xA.Bytes())
	assertEqualBytes(t, "S", server.xS.Bytes(), newServer.xS.Bytes())
	assertEqualBytes(t, "K", server.xK, newServer.xK)
}

func init() {
	if err := Register(group); err != nil {
		log.Fatal(err)
	}
}

// Send is a noop used for examples.
func Send(any) {}

// Receive is a noop used for examples.
func Receive() []byte {
	return nil
}

// SendEncrypted is a nop used for examples.
func SendEncrypted(key, data []byte) {}

// Query is a nop used for examples.
func Query(any) Triplet { return nil }

// Example of a client session.
func ExampleClient() {
	var (
		group    = RFC5054Group2048
		username = "alice@example.com"
		password = "some-password"
	)

	// Request the user's salt from the server.
	// The server should send it to whoever asks.
	salt := Receive()

	// Create a client, specifying the same group used on the server.
	client, err := NewClient(group, username, password, salt)
	if err != nil {
		log.Fatal(err)
	}

	// Send A to the server.
	A := client.A()
	Send(A)

	// Receive B from the server,
	// then configure it on the client.
	B := Receive()
	if err := client.SetB(B); err != nil {
		log.Fatalf("invalid B received from the server: %v", err)
	}

	// Compute the proof M1,
	// then send it to the server.
	M1, err := client.ComputeM1()
	if err != nil {
		log.Fatalf("failed to compute M1: %v", err)
	}
	Send(M1)

	// If the server accepts the client's proof (M1), it will
	// send a proof of their own (M2).
	M2 := Receive()
	valid, err := client.CheckM2(M2)
	if err != nil {
		log.Fatalf("failed to verify server proof M2: %v", err)
	}
	if valid == false {
		log.Fatalf("server is not authentic: %v", err)
	}

	// At this stage, the client and the server
	// have proved to each other that they know
	// the same secret.
	//
	// They can both consider each other as authentic
	// and legitimate.

	// They also share a common key they both derived independently
	// from the process,
	K, err := client.SessionKey()
	if err != nil {
		log.Fatalf("failed to access shared session key: %v", err)
	}

	// K can optionally be used to encrypt/decrypt all exchanges between
	// them moving forward.
	SendEncrypted(K, []byte("hello, world!"))
}

// Example of a server session.
func ExampleServer() {
	var group = RFC5054Group2048

	// Typically, the client will start by requesting
	// a user's salt.
	var username = Receive()

	// Load the user's Triplet from the persistent
	// storage where it was kept (e.g. database).
	var user Triplet = Query(username)

	// Send the user the salt they previously used,
	// whenever requested. Triplet can marshaled to JSON
	// without revealing the secret verifier value.
	Send(user.Salt())

	// Create a server, specifying the same group used on the client.
	server, err := NewServer(group, user.Username(), user.Salt(), user.Verifier())
	if err != nil {
		log.Fatal(err)
	}

	// Send B to the client.
	B := server.B()
	Send(B)

	// Receive A from the client,
	// then configure it on the server.
	A := Receive()
	if err := server.SetA(A); err != nil {
		log.Fatalf("invalid A received from the client: %v", err)
	}

	// The server needs to verify the client's proof first,
	// so it must wait to receive M1.
	M1 := Receive()

	// Verify the client proof M1.
	// The process must be interrupted if valid is false, or
	// an error occurred.
	valid, err := server.CheckM1(M1)
	if err != nil {
		log.Fatalf("failed to verify client proof M1: %v", err)
	}
	if valid == false {
		log.Fatalf("client is not authentic: %v", err)
	}

	// The client proved they're authentic, so it's safe
	// to compute the server proof (M2) and send it over.
	M2, err := server.ComputeM2()
	if err != nil {
		log.Fatalf("failed to compute M1: %v", err)
	}
	Send(M2)

	// At this stage, the server should consider
	// the client as authentic and requests from it
	// should be fulfilled.

	// They both share a common key they both derived
	// independently from the process,
	K, err := server.SessionKey()
	if err != nil {
		log.Fatalf("failed to access shared session key: %v", err)
	}

	// K can optionally be used to encrypt/decrypt all exchanges between
	// them moving forward.
	SendEncrypted(K, []byte("hello, world!"))
}

// The verifier is calculated on the client, and sent to the
// server for storage along with the username and salt used to
// compute it as a triplet.
func ExampleComputeVerifier() {
	const (
		username = "bob@example.com"
		password = "p@$$w0rd"
	)
	tp, err := ComputeVerifier(RFC5054Group2048, username, password, NewRandomSalt())
	if err != nil {
		log.Fatalf("failed to compute verifier: %v", err)
	}

	// The verifier can be accessed via the returned triplet tp
	// as tp.Verifier().

	// On the server, it's recommended to store the verifier along with
	// the username and the salt used to compute it, so sending the whole
	// triplet ([]byte) is more appropriate.
	Send(tp)
}
