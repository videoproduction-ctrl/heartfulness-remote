package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
)

func TestAtomicWriteAndPerms(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("data dir mode: %v %v", fi.Mode(), err)
	}
	now := time.Now()
	for i := 0; i < 5; i++ {
		if err := st.Update(func(s *State) error {
			s.AddEvent(Event{Time: now, Type: "test"})
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	fi, err := os.Stat(st.Path())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode %v, want 0600", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
	b, _ := os.ReadFile(st.Path())
	var parsed State
	if err := json.Unmarshal(b, &parsed); err != nil || len(parsed.Events) != 5 {
		t.Fatalf("file content: %v %d", err, len(parsed.Events))
	}
	st2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st2.View(func(s *State) {
		if len(s.Events) != 5 {
			t.Fatalf("reload: %d events", len(s.Events))
		}
	})
}

func TestUpdateRollback(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Update(func(s *State) error {
		return s.AddHost(HostBinding{Pub: "a", Name: "Mac"})
	})
	before, _ := os.ReadFile(st.Path())
	err = st.Update(func(s *State) error {
		s.Hosts[0].Name = "changed"
		s.Devices["x"] = &Device{Pub: "x"}
		return errors.New("boom")
	})
	if err == nil {
		t.Fatal("expected error")
	}
	st.View(func(s *State) {
		if s.Hosts[0].Name != "Mac" || len(s.Devices) != 0 {
			t.Fatal("in-memory state not rolled back")
		}
	})
	after, _ := os.ReadFile(st.Path())
	if string(before) != string(after) {
		t.Fatal("file changed on failed update")
	}
	if err := st.Update(func(s *State) error { s.Hosts[0].Name = "nope"; return ErrNoChange }); err != nil {
		t.Fatal(err)
	}
	st.View(func(s *State) {
		if s.Hosts[0].Name != "Mac" {
			t.Fatal("ErrNoChange must discard changes")
		}
	})
}

func TestPurge(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	s := newState()
	s.Events = []Event{
		{Time: now.Add(-8 * 24 * time.Hour), Type: "old"},
		{Time: now.Add(-7*24*time.Hour - time.Second), Type: "old"},
		{Time: now.Add(-6 * 24 * time.Hour), Type: "keep"},
		{Time: now.Add(-time.Minute), Type: "keep"},
	}
	s.Sessions = map[string]*Session{
		"expired": {Kind: KindBearer, LastUsed: now, Expires: now.Add(-time.Second)},
		"idle":    {Kind: KindCookie, LastUsed: now.Add(-13 * time.Hour), Expires: now.Add(time.Hour)},
		"live":    {Kind: KindCookie, LastUsed: now.Add(-time.Hour), Expires: now.Add(time.Hour)},
		"bearer":  {Kind: KindBearer, LastUsed: now.Add(-20 * 24 * time.Hour), Expires: now.Add(time.Hour)},
	}
	ap := func(status string, created, revoked time.Time) map[string]*Approval {
		return map[string]*Approval{"H1": {Status: status, CreatedAt: created, RevokedAt: revoked}}
	}
	var zero time.Time
	s.Devices = map[string]*Device{
		"stale-pending": {Approvals: ap(StatusPending, now.Add(-25*time.Hour), zero)},
		"new-pending":   {Approvals: ap(StatusPending, now.Add(-time.Hour), zero)},
		"old-revoked":   {Approvals: ap(StatusRevoked, now.Add(-30*24*time.Hour), now.Add(-8*24*time.Hour))},
		"new-revoked":   {Approvals: ap(StatusRevoked, now.Add(-30*24*time.Hour), now.Add(-time.Hour))},
		"approved":      {Approvals: ap(StatusApproved, now.Add(-300*24*time.Hour), zero)},
		// Approvals are purged per Mac: the device stays while another Mac vouches for it.
		"mixed": {Approvals: map[string]*Approval{
			"H1": {Status: StatusPending, CreatedAt: now.Add(-25 * time.Hour)},
			"H2": {Status: StatusApproved, CreatedAt: now.Add(-25 * time.Hour)},
		}},
	}
	r := s.Purge(now)
	if r.Events != 2 || r.Sessions != 2 || r.PendingApprovals != 2 || r.RevokedApprovals != 1 || r.Devices != 2 {
		t.Fatalf("purge result %+v", r)
	}
	for _, e := range s.Events {
		if e.Type != "keep" {
			t.Fatal("old event kept")
		}
	}
	if _, ok := s.Sessions["live"]; !ok {
		t.Fatal("live session purged")
	}
	if _, ok := s.Sessions["bearer"]; !ok {
		t.Fatal("bearer sessions have no idle timeout")
	}
	for _, k := range []string{"new-pending", "new-revoked", "approved", "mixed"} {
		if _, ok := s.Devices[k]; !ok {
			t.Fatalf("%s purged", k)
		}
	}
	if m := s.Devices["mixed"]; len(m.Approvals) != 1 || m.Approvals["H2"] == nil {
		t.Fatalf("mixed approvals: %+v", m.Approvals)
	}
}

func TestEventCap(t *testing.T) {
	s := newState()
	for i := 0; i < MaxEvents+10; i++ {
		s.AddEvent(Event{Type: "x"})
	}
	if len(s.Events) != MaxEvents {
		t.Fatalf("events %d", len(s.Events))
	}
}

func TestLockExclusive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("flock not available")
	}
	dir := t.TempDir()
	release, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("second lock: %v", err)
	}
	release()
	r2, err := Lock(dir)
	if err != nil {
		t.Fatalf("relock: %v", err)
	}
	r2()
}

func TestReset(t *testing.T) {
	s := newState()
	s.Owner = &Owner{UserHandle: []byte{1}}
	_ = s.AddHost(HostBinding{Pub: "h"})
	s.Devices["d"] = &Device{}
	s.Sessions["s"] = &Session{}
	if !s.Claimed() {
		t.Fatal("owner + Mac should be claimed")
	}
	s.Reset(time.Now())
	if s.Claimed() || len(s.Devices) != 0 || len(s.Sessions) != 0 || s.Owner != nil || len(s.Hosts) != 0 {
		t.Fatal("reset incomplete")
	}
}

func TestHostsAndApprovals(t *testing.T) {
	s := newState()
	pub := func(i byte) string { return proto.B64(append(make([]byte, 31), i)) }
	for i := 0; i < MaxHosts; i++ {
		if err := s.AddHost(HostBinding{Pub: pub(byte(i)), Name: "Mac"}); err != nil {
			t.Fatalf("host %d: %v", i, err)
		}
	}
	if err := s.AddHost(HostBinding{Pub: pub(0)}); err != nil || len(s.Hosts) != MaxHosts {
		t.Fatal("re-adding a bound Mac must be a no-op")
	}
	if err := s.AddHost(HostBinding{Pub: pub(99)}); !errors.Is(err, ErrTooManyHosts) {
		t.Fatalf("host %d: %v", MaxHosts+1, err)
	}
	if s.Hosts[3].MacID != proto.MacID(append(make([]byte, 31), 3)) {
		t.Fatalf("macId not filled: %q", s.Hosts[3].MacID)
	}
	a, b := pub(0), pub(1)
	s.Devices["only-a"] = &Device{Pub: "only-a", Approvals: map[string]*Approval{a: {Status: StatusApproved}}}
	s.Devices["both"] = &Device{Pub: "both", Approvals: map[string]*Approval{a: {Status: StatusApproved}, b: {Status: StatusPending}}}
	if !s.ApprovedOnAny("only-a") || s.ApprovalStatus("both", b) != StatusPending || s.ApprovalStatus("both", pub(5)) != StatusUnknown || s.ApprovalStatus("nobody", a) != StatusUnknown {
		t.Fatal("approval lookups")
	}
	// An approval for a Mac that is not bound does not count.
	s.Devices["stray"] = &Device{Pub: "stray", Approvals: map[string]*Approval{pub(99): {Status: StatusApproved}}}
	if s.ApprovedOnAny("stray") {
		t.Fatal("approval on an unbound Mac counted")
	}
	if !s.RemoveHost(a) || s.RemoveHost(a) || s.Host(a) != nil || len(s.Hosts) != MaxHosts-1 {
		t.Fatal("remove host")
	}
	if _, ok := s.Devices["only-a"]; ok {
		t.Fatal("device approved only on the removed Mac kept")
	}
	if d := s.Devices["both"]; d == nil || len(d.Approvals) != 1 || d.Approvals[b] == nil {
		t.Fatalf("other Mac's approval lost: %+v", d)
	}
}

// A single-Mac (version 1) state.json is migrated on Open: the bound Mac
// becomes hosts[0] and device statuses become approvals for it.
func TestMigrateV1(t *testing.T) {
	dir := t.TempDir()
	hostPub := proto.B64(append(make([]byte, 31), 7))
	cert := proto.Cert{HostPub: hostPub, DevicePub: "dev-approved", Name: "Phone", Kind: "phone", IssuedAt: 1760000000, Sig: "c2ln"}
	certJSON, _ := json.Marshal(cert)
	v1 := `{
 "version": 1,
 "owner": {"userHandle": "AQID", "passkeys": [], "createdAt": "2026-10-01T10:00:00Z"},
 "host": {"pub": "` + hostPub + `", "name": "Studio Mac", "claimedAt": "2026-10-01T10:00:00Z"},
 "devices": {
  "dev-approved": {"pub": "dev-approved", "name": "Phone", "kind": "phone", "status": "approved", "cert": ` + string(certJSON) + `, "createdAt": "2026-10-01T10:00:00Z", "lastSeen": "2026-10-15T10:00:00Z"},
  "dev-pending": {"pub": "dev-pending", "name": "Laptop", "kind": "browser", "status": "pending", "createdAt": "2026-10-16T09:00:00Z"},
  "dev-revoked": {"pub": "dev-revoked", "name": "Old", "kind": "browser", "status": "revoked", "createdAt": "2026-10-02T10:00:00Z", "revokedAt": "2026-10-14T10:00:00Z"}
 },
 "sessions": {"h1": {"hash": "h1", "kind": "cookie", "created": "2026-10-16T09:00:00Z", "lastUsed": "2026-10-16T09:00:00Z", "expires": "2026-10-23T09:00:00Z"}},
 "events": [{"time": "2026-10-16T09:00:00Z", "type": "login"}]
}`
	if err := os.WriteFile(filepath.Join(dir, stateFile), []byte(v1), 0o600); err != nil {
		t.Fatal(err)
	}
	// The read-only path (status command) migrates in memory without writing.
	if s, err := ReadFile(filepath.Join(dir, stateFile)); err != nil || len(s.Hosts) != 1 {
		t.Fatalf("ReadFile: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, stateFile)); string(b) != v1 {
		t.Fatal("ReadFile must not rewrite the file")
	}
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	check := func(s *State) {
		t.Helper()
		if s.Version != 2 || !s.Claimed() || len(s.Hosts) != 1 {
			t.Fatalf("migrated: version %d claimed %v hosts %d", s.Version, s.Claimed(), len(s.Hosts))
		}
		h := s.Hosts[0]
		if h.Pub != hostPub || h.Name != "Studio Mac" || h.MacID != proto.MacID(append(make([]byte, 31), 7)) || h.ClaimedAt.IsZero() {
			t.Fatalf("hosts[0]: %+v", h)
		}
		ap := s.Devices["dev-approved"].Approval(hostPub)
		if ap == nil || ap.Status != StatusApproved || ap.Cert == nil || *ap.Cert != cert || s.Devices["dev-approved"].LastSeen.IsZero() {
			t.Fatalf("approved device: %+v", s.Devices["dev-approved"])
		}
		if s.ApprovalStatus("dev-pending", hostPub) != StatusPending || s.Devices["dev-pending"].Approval(hostPub).CreatedAt.IsZero() {
			t.Fatal("pending device")
		}
		rv := s.Devices["dev-revoked"].Approval(hostPub)
		if rv == nil || rv.Status != StatusRevoked || rv.RevokedAt.IsZero() || rv.Cert != nil {
			t.Fatalf("revoked device: %+v", rv)
		}
		if len(s.Sessions) != 1 || len(s.Events) != 1 || s.Owner == nil {
			t.Fatal("owner, sessions or events lost")
		}
	}
	st.View(check)
	// The migrated layout is written back at once (atomically, 0600) and reloads cleanly.
	b, _ := os.ReadFile(st.Path())
	var onDisk map[string]json.RawMessage
	_ = json.Unmarshal(b, &onDisk)
	var devs map[string]map[string]json.RawMessage
	_ = json.Unmarshal(onDisk["devices"], &devs)
	if onDisk["host"] != nil || onDisk["hosts"] == nil || string(onDisk["version"]) != "2" || devs["dev-approved"]["status"] != nil || devs["dev-approved"]["approvals"] == nil {
		t.Fatalf("state file not rewritten in the new layout:\n%s", b)
	}
	if fi, _ := os.Stat(st.Path()); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	st2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st2.View(check)
	b2, _ := os.ReadFile(st2.Path())
	if string(b) != string(b2) {
		t.Fatal("re-opening a migrated file changed it")
	}

	// An unclaimed version-1 file stays unclaimed.
	dir2 := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir2, stateFile), []byte(`{"version":1,"devices":{},"sessions":{},"events":[]}`), 0o600)
	st3, err := Open(dir2)
	if err != nil {
		t.Fatal(err)
	}
	st3.View(func(s *State) {
		if s.Claimed() || len(s.Hosts) != 0 || s.Version != 2 {
			t.Fatal("unclaimed v1 state")
		}
	})

	// A file from a newer server is refused rather than misread.
	dir3 := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir3, stateFile), []byte(`{"version":3}`), 0o600)
	if _, err := Open(dir3); err == nil {
		t.Fatal("future state version accepted")
	}
}
