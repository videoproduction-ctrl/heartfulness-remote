package proto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTBSLayout(t *testing.T) {
	got := TBS("L", []byte("ab"), nil)
	want := []byte{'L', 0, 0, 0, 0, 2, 'a', 'b', 0, 0, 0, 0}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x want %x", got, want)
	}
	// Field boundaries are unambiguous.
	if bytes.Equal(TBS("L", []byte("ab"), []byte("c")), TBS("L", []byte("a"), []byte("bc"))) {
		t.Fatal("ambiguous encoding")
	}
}

func TestSignVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	sig := Sign(priv, LabelOffer, []byte("x"))
	if !Verify(pub, sig, LabelOffer, []byte("x")) {
		t.Fatal("verify failed")
	}
	if Verify(pub, sig, LabelAnswer, []byte("x")) {
		t.Fatal("label not bound")
	}
	if Verify(pub, sig, LabelOffer, []byte("y")) {
		t.Fatal("field not bound")
	}
	if Verify(pub[:31], sig, LabelOffer, []byte("x")) {
		t.Fatal("short key accepted")
	}
}

func TestSASAndCommit(t *testing.T) {
	v := Vectors()
	if len(v.SAS) != 6 {
		t.Fatalf("sas %q", v.SAS)
	}
	if FormatSAS("123456") != "123 456" {
		t.Fatal("format")
	}
}

func TestSetup(t *testing.T) {
	kc, ka, err := SetupKeys(make([]byte, 32))
	if err != nil || bytes.Equal(kc, ka) || len(kc) != 32 {
		t.Fatal("setup keys")
	}
	hp, dp := make([]byte, 32), make([]byte, 32)
	mac := SetupMAC(ka, hp, dp, "n", "browser")
	if !CheckSetupMAC(ka, hp, dp, "n", "browser", mac) {
		t.Fatal("mac")
	}
	if CheckSetupMAC(kc, hp, dp, "n", "browser", mac) {
		t.Fatal("Kc must not validate setup MAC")
	}
}

func TestCert(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	dpub, _, _ := ed25519.GenerateKey(nil)
	c := SignCert(priv, Cert{HostPub: B64(pub), DevicePub: B64(dpub), Name: "x", Kind: "browser", IssuedAt: 5})
	if err := c.Verify(pub); err != nil {
		t.Fatal(err)
	}
	c.Name = "y"
	if c.Verify(pub) == nil {
		t.Fatal("tampered cert accepted")
	}
	other, _, _ := ed25519.GenerateKey(nil)
	c.Name = "x"
	if c.Verify(other) == nil {
		t.Fatal("cert for other host accepted")
	}
}

func TestSDPFingerprint(t *testing.T) {
	ok := "v=0\r\na=fingerprint:sha-256 aa:bb\r\nm=video\r\na=fingerprint:sha-256 AA:BB\r\n"
	if fp, err := SDPFingerprint(ok); err != nil || fp != "AA:BB" {
		t.Fatal(fp, err)
	}
	for _, bad := range []string{
		"v=0\r\n",
		"a=fingerprint:sha-1 AA\r\n",
		"a=fingerprint:sha-256 AA\r\na=fingerprint:sha-256 BB\r\n",
		"a=fingerprint:sha-256 AA\r\na=fingerprint:sha-1 BB\r\n",
	} {
		if _, err := SDPFingerprint(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestFresh(t *testing.T) {
	now := time.Unix(1000, 0)
	if !FreshTimestamp(1100, now) || FreshTimestamp(1400, now) || FreshTimestamp(600, now) {
		t.Fatal("freshness")
	}
}

func TestFingerprint(t *testing.T) {
	fp := Fingerprint(make([]byte, 32))
	if len(fp) != 19 || fp[4] != '-' {
		t.Fatal(fp)
	}
}

// The committed vectors file must match what the code generates.
func TestVectorsUpToDate(t *testing.T) {
	data, err := os.ReadFile("../testdata/vectors.json")
	if err != nil {
		t.Skip("vectors.json missing: run go run ./proto/cmd/genvectors > testdata/vectors.json")
	}
	var onDisk VectorSet
	if err := json.Unmarshal(data, &onDisk); err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(Vectors())
	got, _ := json.Marshal(onDisk)
	if !bytes.Equal(want, got) {
		t.Fatal("testdata/vectors.json is stale; regenerate it")
	}
	// Every vector signature verifies.
	hp, _ := UnB64(onDisk.HostPub)
	dp, _ := UnB64(onDisk.DevicePub)
	for _, tv := range onDisk.TBS {
		var fields [][]byte
		for _, f := range tv.Fields {
			b, _ := UnB64(f)
			fields = append(fields, b)
		}
		key := hp
		if tv.Signer == "device" {
			key = dp
		}
		sig, _ := UnB64(tv.Sig)
		if !Verify(key, sig, tv.Label, fields...) {
			t.Fatalf("vector %s does not verify", tv.Label)
		}
	}
	if err := onDisk.Cert.Verify(hp); err != nil {
		t.Fatal(err)
	}
}

func TestMultiMac(t *testing.T) {
	pub := make([]byte, 32)
	id := MacID(pub)
	if len(id) != 9 || FormatMacID(id)[3] != ' ' {
		t.Fatal(id)
	}
	if MacID(append([]byte{1}, pub[1:]...)) == id {
		t.Fatal("mac id not key-dependent")
	}
	jt := []byte{0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9}
	code := JoinCode(jt)
	if len(code) != 19 || code[4] != '-' {
		t.Fatal(code)
	}
	for _, typed := range []string{code, strings.ToLower(code), strings.ReplaceAll(code, "-", " ")} {
		got, err := ParseJoinCode(typed)
		if err != nil || !bytes.Equal(got, jt) {
			t.Fatalf("%q: %v", typed, err)
		}
	}
	if _, err := ParseJoinCode("ABCD"); err == nil {
		t.Fatal("short code accepted")
	}
	_, ka, _ := SetupKeys(jt)
	dp := bytes.Repeat([]byte{7}, 32)
	m := HostConfirmMAC(ka, pub, dp)
	if !CheckHostConfirmMAC(ka, pub, dp, m) || CheckHostConfirmMAC(ka, dp, pub, m) {
		t.Fatal("host confirm mac")
	}
}
