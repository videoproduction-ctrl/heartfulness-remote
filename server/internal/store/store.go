// Package store keeps the server's small persistent state in a single JSON
// file (HR_DATA_DIR/state.json), written atomically (temp file + fsync +
// rename, mode 0600) and guarded by a mutex. It never holds screen data,
// SDPs, raw tokens, cookies or setup claims: sessions are stored as SHA-256
// hashes only.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
)

// Device statuses.
const (
	StatusUnknown  = "unknown"
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusRevoked  = "revoked"
)

// Session kinds.
const (
	KindCookie = "cookie"
	KindBearer = "bearer"
)

// Retention and lifetimes.
const (
	EventRetention    = 7 * 24 * time.Hour
	PendingDeviceTTL  = 24 * time.Hour
	RevokedRetention  = 7 * 24 * time.Hour
	CookieIdleTimeout = 12 * time.Hour
	CookieLifetime    = 7 * 24 * time.Hour
	BearerLifetime    = 30 * 24 * time.Hour
	MaxEvents         = 2000
	stateFile         = "state.json"
	stateVersion      = 1
)

// Passkey is one WebAuthn credential of the owner.
type Passkey struct {
	ID         string              `json:"id"` // b64 credential ID
	Name       string              `json:"name"`
	CreatedAt  time.Time           `json:"createdAt"`
	Credential webauthn.Credential `json:"credential"`
}

// Owner is the single owner account (WebAuthn user).
type Owner struct {
	UserHandle []byte    `json:"userHandle"`
	Passkeys   []Passkey `json:"passkeys"`
	CreatedAt  time.Time `json:"createdAt"`
}

// HostBinding records the Mac that claimed this server.
type HostBinding struct {
	Pub       string    `json:"pub"` // b64 Ed25519
	Name      string    `json:"name"`
	ClaimedAt time.Time `json:"claimedAt"`
}

// Device mirrors the Mac's trust decision about a device key.
type Device struct {
	Pub       string      `json:"pub"`
	Name      string      `json:"name"`
	Kind      string      `json:"kind"`
	Status    string      `json:"status"`
	Cert      *proto.Cert `json:"cert,omitempty"`
	CreatedAt time.Time   `json:"createdAt"`
	LastSeen  time.Time   `json:"lastSeen,omitzero"`
	RevokedAt time.Time   `json:"revokedAt,omitzero"`
}

// Session is a login session. Only the SHA-256 of the token is stored.
type Session struct {
	Hash     string    `json:"hash"` // hex SHA-256(token)
	Kind     string    `json:"kind"`
	Name     string    `json:"name,omitempty"` // bearer: app name from the link flow
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"lastUsed"`
	Expires  time.Time `json:"expires"` // absolute expiry
}

// Valid reports whether the session can still be used at now.
func (s *Session) Valid(now time.Time) bool {
	if !now.Before(s.Expires) {
		return false
	}
	if s.Kind == KindCookie && now.Sub(s.LastUsed) >= CookieIdleTimeout {
		return false
	}
	return true
}

// Event is a minimal audit record.
type Event struct {
	Time   time.Time `json:"time"`
	Type   string    `json:"type"`
	Device string    `json:"device,omitempty"`
	IP     string    `json:"ip,omitempty"`
}

// State is the whole persisted state.
type State struct {
	Version  int                 `json:"version"`
	Owner    *Owner              `json:"owner,omitempty"`
	Host     *HostBinding        `json:"host,omitempty"`
	Devices  map[string]*Device  `json:"devices"`
	Sessions map[string]*Session `json:"sessions"`
	Events   []Event             `json:"events"`
}

// Claimed reports whether an owner and host are bound.
func (s *State) Claimed() bool { return s.Owner != nil && s.Host != nil }

// AddEvent appends an audit event, capping the list.
func (s *State) AddEvent(e Event) {
	s.Events = append(s.Events, e)
	if n := len(s.Events); n > MaxEvents {
		s.Events = append([]Event(nil), s.Events[n-MaxEvents:]...)
	}
}

// DeviceStatus returns the status of a device key.
func (s *State) DeviceStatus(pub string) string {
	if d, ok := s.Devices[pub]; ok {
		return d.Status
	}
	return StatusUnknown
}

// Reset wipes owner, passkeys, host binding, devices and sessions.
func (s *State) Reset(now time.Time) {
	s.Owner = nil
	s.Host = nil
	s.Devices = map[string]*Device{}
	s.Sessions = map[string]*Session{}
	s.Events = []Event{{Time: now, Type: "reset"}}
}

// PurgeResult counts what Purge removed.
type PurgeResult struct {
	Events, Sessions, PendingDevices, RevokedDevices int
}

// Purge deletes old events, expired sessions, stale pending devices and old
// revoked devices.
func (s *State) Purge(now time.Time) PurgeResult {
	var r PurgeResult
	kept := s.Events[:0]
	for _, e := range s.Events {
		if now.Sub(e.Time) < EventRetention {
			kept = append(kept, e)
		} else {
			r.Events++
		}
	}
	s.Events = kept
	for k, ss := range s.Sessions {
		if !ss.Valid(now) {
			delete(s.Sessions, k)
			r.Sessions++
		}
	}
	for k, d := range s.Devices {
		switch {
		case d.Status == StatusPending && now.Sub(d.CreatedAt) >= PendingDeviceTTL:
			delete(s.Devices, k)
			r.PendingDevices++
		case d.Status == StatusRevoked && !d.RevokedAt.IsZero() && now.Sub(d.RevokedAt) >= RevokedRetention:
			delete(s.Devices, k)
			r.RevokedDevices++
		}
	}
	return r
}

// SortedDevices returns devices ordered by creation time.
func (s *State) SortedDevices() []*Device {
	out := make([]*Device, 0, len(s.Devices))
	for _, d := range s.Devices {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].Pub < out[j].Pub
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

func newState() *State {
	return &State{Version: stateVersion, Devices: map[string]*Device{}, Sessions: map[string]*Session{}, Events: []Event{}}
}

// Store is the mutex-guarded persistent state.
type Store struct {
	mu    sync.Mutex
	dir   string
	path  string
	state *State
}

// Open loads (or initializes) the state in dir, creating dir with mode 0700.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	st := &Store{dir: dir, path: filepath.Join(dir, stateFile)}
	s, err := ReadFile(st.path)
	if err != nil {
		return nil, err
	}
	st.state = s
	return st, nil
}

// ReadFile reads a state file without locking (used by the status command).
// A missing file yields an empty state.
func ReadFile(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return newState(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	s := newState()
	if err := json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("parse state %s: %w", path, err)
	}
	if s.Devices == nil {
		s.Devices = map[string]*Device{}
	}
	if s.Sessions == nil {
		s.Sessions = map[string]*Session{}
	}
	if s.Events == nil {
		s.Events = []Event{}
	}
	return s, nil
}

// Path returns the state file path.
func (st *Store) Path() string { return st.path }

// View runs fn with read access to the state. fn must not retain pointers.
func (st *Store) View(fn func(s *State)) {
	st.mu.Lock()
	defer st.mu.Unlock()
	fn(st.state)
}

// ErrNoChange can be returned by an Update callback to skip the write.
var ErrNoChange = errors.New("no change")

// Update runs fn with write access and persists the result atomically. If fn
// returns an error (or the write fails) the in-memory state is rolled back.
// Returning ErrNoChange skips the write and reports success.
func (st *Store) Update(fn func(s *State) error) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	snapshot, err := json.Marshal(st.state)
	if err != nil {
		return err
	}
	if err := fn(st.state); err != nil {
		st.restore(snapshot)
		if errors.Is(err, ErrNoChange) {
			return nil
		}
		return err
	}
	if err := writeAtomic(st.dir, st.path, st.state); err != nil {
		st.restore(snapshot)
		return err
	}
	return nil
}

func (st *Store) restore(snapshot []byte) {
	s := newState()
	if err := json.Unmarshal(snapshot, s); err == nil {
		st.state = s
	}
}

// writeAtomic writes v as JSON to path via a 0600 temp file, fsync and rename.
func writeAtomic(dir, path string, v any) (err error) {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err = f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err = f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// WriteFile atomically replaces the state file at dir (used by reset).
func WriteFile(dir string, s *State) error {
	return writeAtomic(dir, filepath.Join(dir, stateFile), s)
}
