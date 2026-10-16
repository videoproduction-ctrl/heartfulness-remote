// Package trust is the host's trust store (pins.json): the pinned device keys
// with their host-issued certificates, revocations, the kill-switch flag, the
// pairing denial counters and the access-log chain head.
//
// The file is integrity-protected with HMAC-SHA256(storageKey, data) where
// storageKey comes from the Mac Keychain (PROTOCOL.md §9). A file whose MAC
// does not verify is never loaded: Open returns ErrTampered and the caller
// must refuse to trust anything.
package trust

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
)

// FileName is the trust store file inside dataDir.
const FileName = "pins.json"

// LogFileName is the access log; its presence without pins.json is suspicious.
const LogFileName = "access-log.jsonl"

var (
	// ErrTampered means pins.json failed integrity verification (or was deleted
	// while the access log still exists).
	ErrTampered = errors.New("trust store integrity check failed")
	// ErrHostMismatch means pins.json belongs to a different host key.
	ErrHostMismatch = errors.New("trust store belongs to a different host key")
)

// Device is a pinned (trusted) device.
type Device struct {
	Pub      string     `json:"pub"`
	Name     string     `json:"name"`
	Kind     string     `json:"kind"`
	AddedAt  int64      `json:"addedAt"`
	LastUsed int64      `json:"lastUsed"`
	Cert     proto.Cert `json:"cert"`
}

// Revoked is a revoked device key with the host-signed revocation.
type Revoked struct {
	Name       string           `json:"name"`
	Kind       string           `json:"kind"`
	Revocation proto.Revocation `json:"revocation"`
}

// LogHead anchors the access-log hash chain so truncation is detectable.
type LogHead struct {
	Count int64  `json:"count"`
	Head  string `json:"head"` // b64 SHA-256 of the last log line
}

// Data is the MAC-protected content of pins.json.
type Data struct {
	Version       int       `json:"version"`
	HostPub       string    `json:"hostPub"`
	Devices       []Device  `json:"devices"`
	Revoked       []Revoked `json:"revoked"`
	Killed        bool      `json:"killed"`
	Denials       []int64   `json:"denials"`       // unix seconds of recent pairing denials
	AutoDenyUntil int64     `json:"autoDenyUntil"` // unix seconds
	Log           LogHead   `json:"log"`
}

type fileFormat struct {
	V    int             `json:"v"`
	Data json.RawMessage `json:"data"`
	MAC  string          `json:"mac"`
}

// Store is the loaded trust store. Methods are safe for concurrent use.
type Store struct {
	mu   sync.Mutex
	dir  string
	key  []byte
	data Data
}

// Open loads dir/pins.json, verifying its MAC with key. A missing file yields
// an empty store, unless the access log exists (then ErrTampered: someone
// deleted the trust store to reset the log anchor).
func Open(dir string, key []byte, hostPub []byte) (*Store, error) {
	if len(key) < 32 {
		return nil, errors.New("storage key must be at least 32 bytes")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, key: slices.Clone(key)}
	raw, err := os.ReadFile(filepath.Join(dir, FileName))
	if errors.Is(err, os.ErrNotExist) {
		if fi, lerr := os.Stat(filepath.Join(dir, LogFileName)); lerr == nil && fi.Size() > 0 {
			return nil, fmt.Errorf("%w: %s missing but access log present", ErrTampered, FileName)
		}
		s.data = Data{Version: 1, HostPub: proto.B64(hostPub)}
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var ff fileFormat
	if err := json.Unmarshal(raw, &ff); err != nil || ff.V != 1 || len(ff.Data) == 0 {
		return nil, fmt.Errorf("%w: unreadable", ErrTampered)
	}
	mac, err := proto.UnB64(ff.MAC)
	if err != nil || !hmac.Equal(mac, s.mac(ff.Data)) {
		return nil, fmt.Errorf("%w: MAC mismatch", ErrTampered)
	}
	if err := json.Unmarshal(ff.Data, &s.data); err != nil {
		return nil, fmt.Errorf("%w: bad data", ErrTampered)
	}
	if s.data.HostPub != proto.B64(hostPub) {
		return nil, ErrHostMismatch
	}
	// Defence in depth: every pinned device must carry a valid cert from us.
	for _, d := range s.data.Devices {
		if d.Cert.DevicePub != d.Pub || d.Cert.Verify(hostPub) != nil {
			return nil, fmt.Errorf("%w: invalid certificate for a pinned device", ErrTampered)
		}
	}
	return s, nil
}

func (s *Store) mac(data []byte) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write(data)
	return m.Sum(nil)
}

// Save writes pins.json atomically (temp file, fsync, rename, fsync dir), 0600.
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	data, err := json.Marshal(s.data)
	if err != nil {
		return err
	}
	out, err := json.Marshal(fileFormat{V: 1, Data: data, MAC: proto.B64(s.mac(data))})
	if err != nil {
		return err
	}
	return WriteFileAtomic(filepath.Join(s.dir, FileName), append(out, '\n'), 0o600)
}

// Update applies f to the data and saves. If saving fails the in-memory data
// is rolled back.
func (s *Store) Update(f func(d *Data)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, _ := json.Marshal(s.data)
	f(&s.data)
	if err := s.saveLocked(); err != nil {
		var restored Data
		_ = json.Unmarshal(old, &restored)
		s.data = restored
		return err
	}
	return nil
}

// Snapshot returns a deep copy of the data.
func (s *Store) Snapshot() Data {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(s.data)
	var d Data
	_ = json.Unmarshal(b, &d)
	return d
}

// Device returns the pinned, non-revoked device with this key.
func (s *Store) Device(pub string) (Device, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isRevokedLocked(pub) {
		return Device{}, false
	}
	for _, d := range s.data.Devices {
		if d.Pub == pub {
			return d, true
		}
	}
	return Device{}, false
}

// IsRevoked reports whether pub was revoked.
func (s *Store) IsRevoked(pub string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isRevokedLocked(pub)
}

func (s *Store) isRevokedLocked(pub string) bool {
	for _, r := range s.data.Revoked {
		if r.Revocation.DevicePub == pub {
			return true
		}
	}
	return false
}

// DeviceCount returns the number of pinned devices.
func (s *Store) DeviceCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.data.Devices)
}

// Killed reports the kill-switch state.
func (s *Store) Killed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Killed
}

// LogHead implements accesslog.HeadStore.
func (s *Store) LogHead() (int64, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Log.Count, s.data.Log.Head
}

// SetLogHead implements accesslog.HeadStore.
func (s *Store) SetLogHead(count int64, head string) error {
	return s.Update(func(d *Data) { d.Log = LogHead{Count: count, Head: head} })
}

// Pin adds (or replaces) a device with its cert. A revoked key is never pinned.
func (s *Store) Pin(dev Device) error {
	if s.IsRevoked(dev.Pub) {
		return errors.New("device key was revoked")
	}
	return s.Update(func(d *Data) {
		d.Devices = slices.DeleteFunc(d.Devices, func(x Device) bool { return x.Pub == dev.Pub })
		d.Devices = append(d.Devices, dev)
	})
}

// Revoke moves a device to the revoked list.
func (s *Store) Revoke(rev proto.Revocation) (Device, bool, error) {
	var removed Device
	var found bool
	err := s.Update(func(d *Data) {
		for _, x := range d.Devices {
			if x.Pub == rev.DevicePub {
				removed, found = x, true
			}
		}
		d.Devices = slices.DeleteFunc(d.Devices, func(x Device) bool { return x.Pub == rev.DevicePub })
		if !slices.ContainsFunc(d.Revoked, func(r Revoked) bool { return r.Revocation.DevicePub == rev.DevicePub }) {
			d.Revoked = append(d.Revoked, Revoked{Name: removed.Name, Kind: removed.Kind, Revocation: rev})
		}
	})
	return removed, found, err
}

// Touch updates a device's lastUsed time.
func (s *Store) Touch(pub string, now int64) error {
	return s.Update(func(d *Data) {
		for i := range d.Devices {
			if d.Devices[i].Pub == pub {
				d.Devices[i].LastUsed = now
			}
		}
	})
}

// Certs returns all current certificates (for trust-sync).
func (s *Store) Certs() []proto.Cert {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]proto.Cert, 0, len(s.data.Devices))
	for _, d := range s.data.Devices {
		out = append(out, d.Cert)
	}
	return out
}

// Revocations returns all revocations (for trust-sync).
func (s *Store) Revocations() []proto.Revocation {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]proto.Revocation, 0, len(s.data.Revoked))
	for _, r := range s.data.Revoked {
		out = append(out, r.Revocation)
	}
	return out
}

// WriteFileAtomic writes data to path via a temp file in the same directory,
// fsyncs it, renames it into place and fsyncs the directory.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(perm); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Quarantine renames pins.json and the access log aside, preserving them as
// evidence (used by the explicit "reset-trust-store" command only; never
// automatically).
func Quarantine(dir string, suffix string) error {
	for _, name := range []string{FileName, LogFileName} {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if err := os.Rename(p, p+".quarantined-"+suffix); err != nil {
			return err
		}
	}
	return nil
}
