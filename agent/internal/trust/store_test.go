package trust

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
)

func fixture(t *testing.T) (dir string, key []byte, hostPub ed25519.PublicKey, hostPriv ed25519.PrivateKey) {
	t.Helper()
	dir = t.TempDir()
	key = bytes.Repeat([]byte{7}, 32)
	hostPub, hostPriv, _ = ed25519.GenerateKey(nil)
	return
}

func device(t *testing.T, hostPriv ed25519.PrivateKey, name string) Device {
	t.Helper()
	dp, _, _ := ed25519.GenerateKey(nil)
	hp := hostPriv.Public().(ed25519.PublicKey)
	c := proto.SignCert(hostPriv, proto.Cert{HostPub: proto.B64(hp), DevicePub: proto.B64(dp), Name: name, Kind: "browser", IssuedAt: 1700000000})
	return Device{Pub: proto.B64(dp), Name: name, Kind: "browser", AddedAt: 1, LastUsed: 1, Cert: c}
}

func TestRoundTripAndPermissions(t *testing.T) {
	dir, key, hp, hpriv := fixture(t)
	s, err := Open(dir, key, hp)
	if err != nil {
		t.Fatal(err)
	}
	d := device(t, hpriv, "Phone")
	if err := s.Pin(d); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("pins.json mode %v", fi.Mode().Perm())
	}
	s2, err := Open(dir, key, hp)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := s2.Device(d.Pub); !ok || got.Name != "Phone" {
		t.Fatal("device not persisted")
	}
	// Revocation persists and hides the device.
	rev := proto.Revocation{HostPub: proto.B64(hp), DevicePub: d.Pub, RevokedAt: 5}
	if _, found, err := s2.Revoke(rev); err != nil || !found {
		t.Fatal(err)
	}
	s3, _ := Open(dir, key, hp)
	if _, ok := s3.Device(d.Pub); ok || !s3.IsRevoked(d.Pub) {
		t.Fatal("revocation not persisted")
	}
	if err := s3.Pin(d); err == nil {
		t.Fatal("revoked key re-pinned")
	}
}

func TestTamperDetected(t *testing.T) {
	dir, key, hp, hpriv := fixture(t)
	s, _ := Open(dir, key, hp)
	_ = s.Pin(device(t, hpriv, "Phone"))
	path := filepath.Join(dir, FileName)
	orig, _ := os.ReadFile(path)

	mutate := func(f func(m map[string]any)) []byte {
		var ff map[string]any
		_ = json.Unmarshal(orig, &ff)
		f(ff)
		b, _ := json.Marshal(ff)
		return b
	}
	cases := map[string][]byte{
		"flip-byte": func() []byte {
			b := bytes.Clone(orig)
			i := bytes.Index(b, []byte(`"Phone"`))
			b[i+1] = 'Q'
			return b
		}(),
		"killed-flag": mutate(func(m map[string]any) {
			d := m["data"].(map[string]any)
			d["killed"] = true
		}),
		"add-device-keep-mac": mutate(func(m map[string]any) {
			d := m["data"].(map[string]any)
			d["devices"] = append(d["devices"].([]any), d["devices"].([]any)[0])
		}),
		"wrong-mac":   mutate(func(m map[string]any) { m["mac"] = proto.B64(make([]byte, 32)) }),
		"no-mac":      mutate(func(m map[string]any) { delete(m, "mac") }),
		"garbage":     []byte("not json"),
		"empty":       {},
		"bad-version": mutate(func(m map[string]any) { m["v"] = 2 }),
	}
	for name, content := range cases {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(dir, key, hp); !errors.Is(err, ErrTampered) {
			t.Errorf("%s: want ErrTampered, got %v", name, err)
		}
	}
	// Wrong key = tampered too (e.g. the Keychain item was replaced).
	_ = os.WriteFile(path, orig, 0o600)
	if _, err := Open(dir, bytes.Repeat([]byte{8}, 32), hp); !errors.Is(err, ErrTampered) {
		t.Errorf("wrong key: %v", err)
	}
	// Another host key.
	other, _, _ := ed25519.GenerateKey(nil)
	if _, err := Open(dir, key, other); !errors.Is(err, ErrHostMismatch) {
		t.Errorf("host mismatch: %v", err)
	}
	// Original still loads.
	if _, err := Open(dir, key, hp); err != nil {
		t.Fatal(err)
	}
}

func TestForgedDeviceWithValidMACButBadCertRejected(t *testing.T) {
	// An attacker who somehow obtained the storage key still cannot pin a
	// device without a host-signed cert.
	dir, key, hp, hpriv := fixture(t)
	s, _ := Open(dir, key, hp)
	d := device(t, hpriv, "Phone")
	d.Cert.Sig = proto.B64(make([]byte, 64))
	s.data.Devices = append(s.data.Devices, d)
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, key, hp); !errors.Is(err, ErrTampered) {
		t.Fatalf("got %v", err)
	}
}

func TestDeletedStoreWithLogIsTamper(t *testing.T) {
	dir, key, hp, _ := fixture(t)
	if err := os.WriteFile(filepath.Join(dir, LogFileName), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, key, hp); !errors.Is(err, ErrTampered) {
		t.Fatalf("got %v", err)
	}
	// Quarantine moves both aside; then a fresh store opens.
	if err := Quarantine(dir, "1"); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, key, hp); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, LogFileName+".quarantined-1")); err != nil {
		t.Fatal("log not preserved")
	}
}

func TestAtomicWriteLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.json")
	for range 3 {
		if err := WriteFileAtomic(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("leftover files: %v", ents)
	}
}
