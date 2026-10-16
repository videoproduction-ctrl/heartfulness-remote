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
		s.Host = &HostBinding{Pub: "a", Name: "Mac"}
		return nil
	})
	before, _ := os.ReadFile(st.Path())
	err = st.Update(func(s *State) error {
		s.Host.Name = "changed"
		s.Devices["x"] = &Device{Pub: "x"}
		return errors.New("boom")
	})
	if err == nil {
		t.Fatal("expected error")
	}
	st.View(func(s *State) {
		if s.Host.Name != "Mac" || len(s.Devices) != 0 {
			t.Fatal("in-memory state not rolled back")
		}
	})
	after, _ := os.ReadFile(st.Path())
	if string(before) != string(after) {
		t.Fatal("file changed on failed update")
	}
	if err := st.Update(func(s *State) error { s.Host.Name = "nope"; return ErrNoChange }); err != nil {
		t.Fatal(err)
	}
	st.View(func(s *State) {
		if s.Host.Name != "Mac" {
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
	s.Devices = map[string]*Device{
		"stale-pending": {Status: StatusPending, CreatedAt: now.Add(-25 * time.Hour)},
		"new-pending":   {Status: StatusPending, CreatedAt: now.Add(-time.Hour)},
		"old-revoked":   {Status: StatusRevoked, CreatedAt: now.Add(-30 * 24 * time.Hour), RevokedAt: now.Add(-8 * 24 * time.Hour)},
		"new-revoked":   {Status: StatusRevoked, CreatedAt: now.Add(-30 * 24 * time.Hour), RevokedAt: now.Add(-time.Hour)},
		"approved":      {Status: StatusApproved, CreatedAt: now.Add(-300 * 24 * time.Hour)},
	}
	r := s.Purge(now)
	if r.Events != 2 || r.Sessions != 2 || r.PendingDevices != 1 || r.RevokedDevices != 1 {
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
	for _, k := range []string{"new-pending", "new-revoked", "approved"} {
		if _, ok := s.Devices[k]; !ok {
			t.Fatalf("%s purged", k)
		}
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
	s.Host = &HostBinding{Pub: "h"}
	s.Devices["d"] = &Device{}
	s.Sessions["s"] = &Session{}
	s.Reset(time.Now())
	if s.Claimed() || len(s.Devices) != 0 || len(s.Sessions) != 0 || s.Owner != nil {
		t.Fatal("reset incomplete")
	}
}
