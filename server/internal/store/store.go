// Package store keeps the server's small persistent state in a single JSON
// file (HR_DATA_DIR/state.json), written atomically (temp file + fsync +
// rename, mode 0600) and guarded by a mutex. It never holds screen data,
// SDPs, raw tokens, cookies or setup claims: sessions are stored as SHA-256
// hashes only.
//
// State version 2 (PROTOCOL.md §10, HR1.1) holds one owner, up to MaxHosts
// Macs ("hosts") and, per device, one approval per Mac. A version-1 file (a
// single "host" and one status per device) is migrated when it is read.
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
	MaxHosts          = 20 // Macs per owner account (PROTOCOL.md §10)
	stateFile         = "state.json"
	stateVersion      = 2
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

// HostBinding records one Mac bound to the owner account.
type HostBinding struct {
	Pub       string    `json:"pub"` // b64 Ed25519
	Name      string    `json:"name"`
	MacID     string    `json:"macId"` // proto.MacID(pub), display only
	ClaimedAt time.Time `json:"claimedAt"`
	LastSeen  time.Time `json:"lastSeen,omitzero"`
}

// Approval mirrors one Mac's trust decision about a device key.
type Approval struct {
	Status    string      `json:"status"` // pending | approved | revoked
	Cert      *proto.Cert `json:"cert,omitempty"`
	CreatedAt time.Time   `json:"createdAt"`
	RevokedAt time.Time   `json:"revokedAt,omitzero"`
}

// Device is a client device key known to the server, with one approval per
// Mac (keyed by the Mac's b64 host key).
type Device struct {
	Pub       string               `json:"pub"`
	Name      string               `json:"name"`
	Kind      string               `json:"kind"`
	Approvals map[string]*Approval `json:"approvals"`
	CreatedAt time.Time            `json:"createdAt"`
	LastSeen  time.Time            `json:"lastSeen,omitzero"`
}

// Approval returns the device's approval for hostPub, or nil.
func (d *Device) Approval(hostPub string) *Approval {
	if d == nil {
		return nil
	}
	return d.Approvals[hostPub]
}

// SetApproval replaces the device's approval for hostPub.
func (d *Device) SetApproval(hostPub string, a *Approval) {
	if d.Approvals == nil {
		d.Approvals = map[string]*Approval{}
	}
	d.Approvals[hostPub] = a
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
	Hosts    []*HostBinding      `json:"hosts"`
	Devices  map[string]*Device  `json:"devices"`
	Sessions map[string]*Session `json:"sessions"`
	Events   []Event             `json:"events"`
}

// Claimed reports whether an owner exists and at least one Mac is bound.
func (s *State) Claimed() bool { return s.Owner != nil && len(s.Hosts) > 0 }

// Host returns the bound Mac with this key, or nil.
func (s *State) Host(pub string) *HostBinding {
	for _, h := range s.Hosts {
		if h.Pub == pub {
			return h
		}
	}
	return nil
}

// AddHost binds a Mac (no-op if already bound). It fails beyond MaxHosts.
func (s *State) AddHost(h HostBinding) error {
	if s.Host(h.Pub) != nil {
		return nil
	}
	if len(s.Hosts) >= MaxHosts {
		return ErrTooManyHosts
	}
	if h.MacID == "" {
		h.MacID = macID(h.Pub)
	}
	s.Hosts = append(s.Hosts, &h)
	return nil
}

// RemoveHost unbinds a Mac and drops every device approval for it. Devices
// left with no approval at all are deleted. Reports whether it was bound.
func (s *State) RemoveHost(pub string) bool {
	idx := -1
	for i, h := range s.Hosts {
		if h.Pub == pub {
			idx = i
		}
	}
	if idx < 0 {
		return false
	}
	s.Hosts = append(s.Hosts[:idx:idx], s.Hosts[idx+1:]...)
	for k, d := range s.Devices {
		delete(d.Approvals, pub)
		if len(d.Approvals) == 0 {
			delete(s.Devices, k)
		}
	}
	return true
}

// AddEvent appends an audit event, capping the list.
func (s *State) AddEvent(e Event) {
	s.Events = append(s.Events, e)
	if n := len(s.Events); n > MaxEvents {
		s.Events = append([]Event(nil), s.Events[n-MaxEvents:]...)
	}
}

// ApprovalStatus returns a device's status on one Mac ("unknown" if none).
func (s *State) ApprovalStatus(devicePub, hostPub string) string {
	if a := s.Devices[devicePub].Approval(hostPub); a != nil {
		return a.Status
	}
	return StatusUnknown
}

// ApprovedOnAny reports whether the device is approved on at least one bound Mac.
func (s *State) ApprovedOnAny(devicePub string) bool {
	d := s.Devices[devicePub]
	if d == nil {
		return false
	}
	for _, h := range s.Hosts {
		if a := d.Approvals[h.Pub]; a != nil && a.Status == StatusApproved {
			return true
		}
	}
	return false
}

// Reset wipes owner, passkeys, Macs, devices and sessions.
func (s *State) Reset(now time.Time) {
	s.Owner = nil
	s.Hosts = []*HostBinding{}
	s.Devices = map[string]*Device{}
	s.Sessions = map[string]*Session{}
	s.Events = []Event{{Time: now, Type: "reset"}}
}

// PurgeResult counts what Purge removed.
type PurgeResult struct {
	Events, Sessions, PendingApprovals, RevokedApprovals, Devices int
}

// Purge deletes old events, expired sessions, stale pending approvals, old
// revocations, and devices left without any approval.
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
		for h, a := range d.Approvals {
			switch {
			case a.Status == StatusPending && now.Sub(a.CreatedAt) >= PendingDeviceTTL:
				delete(d.Approvals, h)
				r.PendingApprovals++
			case a.Status == StatusRevoked && !a.RevokedAt.IsZero() && now.Sub(a.RevokedAt) >= RevokedRetention:
				delete(d.Approvals, h)
				r.RevokedApprovals++
			}
		}
		if len(d.Approvals) == 0 {
			delete(s.Devices, k)
			r.Devices++
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
	return &State{Version: stateVersion, Hosts: []*HostBinding{}, Devices: map[string]*Device{}, Sessions: map[string]*Session{}, Events: []Event{}}
}

// ErrTooManyHosts is returned when binding more than MaxHosts Macs.
var ErrTooManyHosts = errors.New("too many Macs in this account")

func macID(pub string) string {
	b, err := proto.UnB64Len(pub, proto.PubKeySize)
	if err != nil {
		return ""
	}
	return proto.MacID(b)
}

// v1State is the single-Mac layout of state.json (HR1, version 1).
type v1State struct {
	Host *struct {
		Pub       string    `json:"pub"`
		Name      string    `json:"name"`
		ClaimedAt time.Time `json:"claimedAt"`
	} `json:"host"`
	Devices map[string]*struct {
		Status    string      `json:"status"`
		Cert      *proto.Cert `json:"cert"`
		RevokedAt time.Time   `json:"revokedAt"`
	} `json:"devices"`
}

// migrate upgrades a single-Mac (version 1) state in place: the bound Mac
// becomes hosts[0] and each device status becomes its approval for that Mac.
// It is driven by content, not only the version number, so a file rewritten
// by an older server is migrated again. Reports whether anything changed.
func migrate(s *State, raw []byte) (bool, error) {
	var old v1State
	if err := json.Unmarshal(raw, &old); err != nil {
		return false, err
	}
	changed := s.Version < stateVersion
	s.Version = stateVersion
	if old.Host != nil && old.Host.Pub != "" && len(s.Hosts) == 0 {
		s.Hosts = []*HostBinding{{Pub: old.Host.Pub, Name: old.Host.Name, MacID: macID(old.Host.Pub), ClaimedAt: old.Host.ClaimedAt}}
		changed = true
	}
	for _, h := range s.Hosts {
		if h.MacID == "" {
			h.MacID = macID(h.Pub)
			changed = true
		}
	}
	for pub, d := range s.Devices {
		if d.Approvals != nil {
			continue
		}
		changed = true
		od := old.Devices[pub]
		switch {
		case old.Host == nil || od == nil:
		case od.Status == StatusPending || od.Status == StatusApproved || od.Status == StatusRevoked:
			a := &Approval{Status: od.Status, CreatedAt: d.CreatedAt, RevokedAt: od.RevokedAt}
			if od.Status == StatusApproved {
				a.Cert = od.Cert
			}
			d.SetApproval(old.Host.Pub, a)
		}
		if len(d.Approvals) == 0 {
			delete(s.Devices, pub) // no Mac vouches for it any more
		}
	}
	return changed, nil
}

// Store is the mutex-guarded persistent state.
type Store struct {
	mu    sync.Mutex
	dir   string
	path  string
	state *State
}

// Open loads (or initializes) the state in dir, creating dir with mode 0700.
// A single-Mac (version 1) state file is migrated and rewritten at once.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	st := &Store{dir: dir, path: filepath.Join(dir, stateFile)}
	s, migrated, err := readFile(st.path)
	if err != nil {
		return nil, err
	}
	if migrated {
		if err := writeAtomic(dir, st.path, s); err != nil {
			return nil, fmt.Errorf("write migrated state: %w", err)
		}
	}
	st.state = s
	return st, nil
}

// ReadFile reads a state file without locking (used by the status command),
// migrating a version-1 layout in memory. A missing file yields an empty state.
func ReadFile(path string) (*State, error) {
	s, _, err := readFile(path)
	return s, err
}

func readFile(path string) (*State, bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return newState(), false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read state: %w", err)
	}
	s := newState()
	s.Version = 0
	if err := json.Unmarshal(b, s); err != nil {
		return nil, false, fmt.Errorf("parse state %s: %w", path, err)
	}
	if s.Version > stateVersion {
		return nil, false, fmt.Errorf("state %s has version %d; this server understands up to %d (was it written by a newer server?)", path, s.Version, stateVersion)
	}
	if s.Hosts == nil {
		s.Hosts = []*HostBinding{}
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
	migrated, err := migrate(s, b)
	if err != nil {
		return nil, false, fmt.Errorf("migrate state %s: %w", path, err)
	}
	return s, migrated, nil
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
