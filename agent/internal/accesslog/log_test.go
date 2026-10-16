package accesslog

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type memHeads struct {
	count int64
	head  string
}

func (m *memHeads) LogHead() (int64, string) { return m.count, m.head }
func (m *memHeads) SetLogHead(c int64, h string) error {
	m.count, m.head = c, h
	return nil
}

var key = bytes.Repeat([]byte{9}, 32)

func newLog(t *testing.T, n int) (*Log, string, *memHeads) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "access-log.jsonl")
	h := &memHeads{}
	l, err := Open(p, key, h)
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		e := Entry{Event: EvSessionStart, Device: "Phone \"quoted\",\"mac\":\"x", DeviceFP: "abcd-efgh", Transport: "direct"}
		if i%2 == 1 {
			e = Entry{Event: EvFileReceived, File: "report.pdf", Size: int64(1000 + i)}
		}
		if err := l.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	return l, p, h
}

func lines(t *testing.T, p string) []string {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func write(t *testing.T, p string, ls []string) {
	if err := os.WriteFile(p, []byte(strings.Join(ls, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestValidLog(t *testing.T) {
	l, p, h := newLog(t, 6)
	r := l.Verify()
	if !r.Verified || len(r.Entries) != 6 || r.Error != "" {
		t.Fatalf("%+v", r)
	}
	if r.Entries[0].Device != "Phone \"quoted\",\"mac\":\"x" || r.Entries[5].Seq != 6 {
		t.Fatalf("entries %+v", r.Entries)
	}
	if h.count != 6 {
		t.Fatal("anchor not updated")
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	// Reopen continues the chain.
	l2, _ := Open(p, key, h)
	_ = l2.Append(Entry{Event: EvKilled})
	if r := l2.Verify(); !r.Verified || len(r.Entries) != 7 {
		t.Fatalf("%+v", r)
	}
	if got := Tail(r.Entries, 2); len(got) != 2 || got[1].Seq != 6 {
		t.Fatal("tail")
	}
}

func TestEditDetected(t *testing.T) {
	l, p, _ := newLog(t, 5)
	ls := lines(t, p)
	ls[2] = strings.Replace(ls[2], "report.pdf", "harmless.txt", 1)
	if !strings.Contains(ls[1]+ls[2]+ls[3], "harmless.txt") {
		// entry 3 (index 2) is a session-start; edit another field instead
		ls[2] = strings.Replace(ls[2], `"transport":"direct"`, `"transport":"relay"`, 1)
	}
	write(t, p, ls)
	r := l.Verify()
	if r.Verified || !strings.Contains(r.Error, "MAC") {
		t.Fatalf("edit not detected: %+v", r.Error)
	}
}

func TestDeleteDetected(t *testing.T) {
	l, p, _ := newLog(t, 5)
	ls := lines(t, p)
	write(t, p, append(ls[:2:2], ls[3:]...))
	r := l.Verify()
	if r.Verified || !strings.Contains(r.Error, "chain") {
		t.Fatalf("deletion not detected: %+v", r.Error)
	}
}

func TestReorderDetected(t *testing.T) {
	l, p, _ := newLog(t, 5)
	ls := lines(t, p)
	ls[1], ls[2] = ls[2], ls[1]
	write(t, p, ls)
	if r := l.Verify(); r.Verified {
		t.Fatal("reorder not detected")
	}
}

func TestTruncateDetected(t *testing.T) {
	l, p, _ := newLog(t, 5)
	ls := lines(t, p)
	write(t, p, ls[:3])
	r := l.Verify()
	if r.Verified || !strings.Contains(r.Error, "truncated") {
		t.Fatalf("truncation not detected: %+v", r.Error)
	}
	// Deleting the whole file is truncation too.
	_ = os.Remove(p)
	if r := l.Verify(); r.Verified {
		t.Fatal("deleted log verified")
	}
}

func TestReplaceTailDetected(t *testing.T) {
	// Truncate and re-append the same number of lines from another log
	// with the same key: the anchor head no longer matches.
	l, p, _ := newLog(t, 4)
	p2 := filepath.Join(t.TempDir(), "other.jsonl")
	l2, _ := Open(p2, key, &memHeads{})
	for range 4 {
		_ = l2.Append(Entry{Event: EvResumed, Detail: "innocent"})
	}
	write(t, p, lines(t, p2))
	if r := l.Verify(); r.Verified {
		t.Fatal("replaced log verified")
	}
}

func TestForgedLineWithoutKey(t *testing.T) {
	l, p, _ := newLog(t, 2)
	ls := lines(t, p)
	other, err := Open(filepath.Join(t.TempDir(), "x"), bytes.Repeat([]byte{1}, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	other.count, other.head = l.count, l.head
	_ = other.Append(Entry{Event: EvResumed})
	extra := lines(t, other.path)
	write(t, p, append(ls, extra...))
	if r := l.Verify(); r.Verified {
		t.Fatal("forged entry accepted")
	}
}

func TestCrashAfterAppendBeforeAnchorIsOK(t *testing.T) {
	l, _, h := newLog(t, 3)
	saved := *h
	_ = l.Append(Entry{Event: EvKilled})
	*h = saved // anchor update "lost"
	if r := l.Verify(); !r.Verified {
		t.Fatalf("valid continuation rejected: %s", r.Error)
	}
}

func TestNoAnchorIsUnverified(t *testing.T) {
	p := filepath.Join(t.TempDir(), "l")
	l, _ := Open(p, key, nil)
	_ = l.Append(Entry{Event: EvKilled})
	if r := l.Verify(); r.Verified {
		t.Fatal("verified without an anchor")
	}
}
