// Package accesslog is the host's local tamper-evident access log
// (access-log.jsonl, PROTOCOL.md §9).
//
// Each line is a JSON object whose last member is "mac":
//
//	entry.prev = b64(SHA-256(previous line))       (genesis: 32 zero bytes)
//	entry.mac  = b64(HMAC-SHA256(storageKey, line-without-mac))
//
// where line-without-mac is the exact byte string of the line with the
// trailing `,"mac":"…"` member removed. The number of entries and the hash of
// the last line are additionally kept in the HMAC-protected trust store, so
// truncation (dropping the newest lines) is detected too.
package accesslog

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
)

// MaxLine bounds a single log line when reading.
const MaxLine = 64 << 10

// Entry is one access-log record. Field order is fixed (struct order).
type Entry struct {
	Seq       int64  `json:"seq"`
	TS        int64  `json:"ts"`
	Event     string `json:"event"`
	Device    string `json:"device,omitempty"`
	DeviceFP  string `json:"deviceFp,omitempty"`
	Transport string `json:"transport,omitempty"`
	Duration  int64  `json:"durationSec,omitempty"`
	File      string `json:"file,omitempty"`
	Size      int64  `json:"size,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Prev      string `json:"prev"`
	MAC       string `json:"mac,omitempty"`
}

// Event names written by the agent.
const (
	EvSessionStart     = "session-start"
	EvSessionEnd       = "session-end"
	EvPairApproved     = "pairing-approved"
	EvPairDenied       = "pairing-denied"
	EvDeviceAdded      = "device-added"
	EvDeviceRemoved    = "device-removed"
	EvKilled           = "killed"
	EvResumed          = "resumed"
	EvFileReceived     = "file-received"
	EvFileSent         = "file-sent"
	EvTrustTampered    = "trust-store-tampered"
	EvLogTampered      = "log-tamper-detected"
	EvSetupFailed      = "setup-failed"
	EvTrustStoreReset  = "trust-store-reset"
	EvAgentStart       = "agent-start"
	EvOfferRejected    = "offer-rejected"
	EvApprovalRejected = "approval-rejected"
	// Multiple Macs (PROTOCOL.md §10).
	EvJoinedAccount      = "joined-account"
	EvRemovedFromAccount = "removed-from-account"
)

// HeadStore persists the chain anchor (count + head hash) in a MAC-protected
// place (the trust store).
type HeadStore interface {
	LogHead() (count int64, head string)
	SetLogHead(count int64, head string) error
}

var (
	// ErrTampered wraps every verification failure.
	ErrTampered = errors.New("access log verification failed")
	macSep      = []byte(`,"mac":"`)
	genesis     = proto.B64(make([]byte, 32))
)

// Log appends to and verifies access-log.jsonl.
type Log struct {
	mu    sync.Mutex
	path  string
	key   []byte
	heads HeadStore // may be nil when the trust store is unavailable
	count int64
	head  string
	now   func() time.Time
}

// Open prepares the log. It does not fail on tampering: call Verify to find
// out; appends continue the chain from the physical last line.
func Open(path string, key []byte, heads HeadStore) (*Log, error) {
	l := &Log{path: path, key: slices.Clone(key), heads: heads, head: genesis, now: time.Now}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	lines, err := readLines(f)
	if err != nil {
		return nil, err
	}
	for _, ln := range lines {
		l.count++
		l.head = hashLine(ln)
	}
	return l, nil
}

// SetClock overrides the clock (tests).
func (l *Log) SetClock(now func() time.Time) { l.now = now }

func hashLine(line []byte) string {
	h := sha256.Sum256(line)
	return proto.B64(h[:])
}

func (l *Log) mac(b []byte) []byte {
	m := hmac.New(sha256.New, l.key)
	m.Write(b)
	return m.Sum(nil)
}

// Append writes e (Seq, TS, Prev and MAC are filled in), fsyncs, then updates
// the anchor in the head store.
func (l *Log) Append(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.Seq = l.count + 1
	if e.TS == 0 {
		e.TS = l.now().Unix()
	}
	e.Prev = l.head
	e.MAC = ""
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	line := sealLine(body, l.mac(body))
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	l.count++
	l.head = hashLine(line)
	if l.heads != nil {
		return l.heads.SetLogHead(l.count, l.head)
	}
	return nil
}

// sealLine turns {…} into {…,"mac":"<b64>"}.
func sealLine(body, mac []byte) []byte {
	out := make([]byte, 0, len(body)+len(macSep)+48)
	out = append(out, body[:len(body)-1]...)
	out = append(out, macSep...)
	out = append(out, proto.B64(mac)...)
	out = append(out, '"', '}')
	return out
}

// splitLine returns line-without-mac and the decoded mac.
func splitLine(line []byte) ([]byte, []byte, error) {
	if !bytes.HasSuffix(line, []byte(`"}`)) {
		return nil, nil, errors.New("malformed line")
	}
	i := bytes.LastIndex(line, macSep)
	if i < 0 {
		return nil, nil, errors.New("missing mac")
	}
	mac, err := proto.UnB64(string(line[i+len(macSep) : len(line)-2]))
	if err != nil {
		return nil, nil, errors.New("bad mac encoding")
	}
	body := append(slices.Clone(line[:i]), '}')
	return body, mac, nil
}

func readLines(r io.Reader) ([][]byte, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), MaxLine)
	var out [][]byte
	for sc.Scan() {
		out = append(out, slices.Clone(sc.Bytes()))
	}
	return out, sc.Err()
}

// Result of a verification.
type Result struct {
	Entries  []Entry
	Verified bool
	Error    string
}

// Verify checks the whole log: every MAC, every chain link, sequence numbers,
// and the anchor (count + head) from the head store. Lines after the anchored
// count are accepted only if they are valid continuations (crash between
// log fsync and anchor update); fewer lines than anchored = truncation.
func (l *Log) Verify() Result {
	l.mu.Lock()
	defer l.mu.Unlock()
	var cnt int64 = -1
	var head string
	if l.heads != nil {
		cnt, head = l.heads.LogHead()
	}
	return verifyFile(l.path, l.key, cnt, head)
}

// VerifyFile verifies path with key against an anchor (anchorCount < 0 skips
// the anchor check, which then makes the result unverified).
func VerifyFile(path string, key []byte, anchorCount int64, anchorHead string) Result {
	return verifyFile(path, key, anchorCount, anchorHead)
}

func verifyFile(path string, key []byte, anchorCount int64, anchorHead string) Result {
	fail := func(entries []Entry, format string, a ...any) Result {
		return Result{Entries: entries, Verified: false, Error: fmt.Sprintf(format, a...)}
	}
	f, err := os.Open(path)
	var lines [][]byte
	if err == nil {
		lines, err = readLines(f)
		_ = f.Close()
		if err != nil {
			return fail(nil, "unreadable: %v", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fail(nil, "unreadable: %v", err)
	}
	m := hmac.New(sha256.New, key)
	entries := make([]Entry, 0, len(lines))
	prev := genesis
	var firstErr string
	for i, ln := range lines {
		var e Entry
		if err := json.Unmarshal(ln, &e); err != nil {
			if firstErr == "" {
				firstErr = fmt.Sprintf("line %d: not valid JSON", i+1)
			}
			prev = hashLine(ln)
			continue
		}
		entries = append(entries, e)
		if firstErr != "" {
			prev = hashLine(ln)
			continue
		}
		body, mac, err := splitLine(ln)
		if err != nil {
			firstErr = fmt.Sprintf("line %d: %v", i+1, err)
		} else {
			m.Reset()
			m.Write(body)
			if !hmac.Equal(m.Sum(nil), mac) {
				firstErr = fmt.Sprintf("line %d: MAC mismatch (entry modified or forged)", i+1)
			} else if e.Prev != prev {
				firstErr = fmt.Sprintf("line %d: chain broken (entry deleted, inserted or reordered)", i+1)
			} else if e.Seq != int64(i+1) {
				firstErr = fmt.Sprintf("line %d: unexpected sequence number %d", i+1, e.Seq)
			}
		}
		prev = hashLine(ln)
	}
	if firstErr != "" {
		return fail(entries, "%s", firstErr)
	}
	if anchorCount < 0 {
		return fail(entries, "trust store unavailable; truncation cannot be checked")
	}
	if int64(len(lines)) < anchorCount {
		return fail(entries, "log truncated: %d entries, %d expected", len(lines), anchorCount)
	}
	if anchorCount > 0 && hashLine(lines[anchorCount-1]) != anchorHead {
		return fail(entries, "log head does not match the trust store anchor")
	}
	if anchorCount == 0 && anchorHead != "" && anchorHead != genesis {
		return fail(entries, "log anchor inconsistent")
	}
	return Result{Entries: entries, Verified: true}
}

// Count returns the number of physical entries.
func (l *Log) Count() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.count
}

// ReAnchor sets the head store anchor to the current physical end of the log.
// Used after a tamper was detected and recorded, so later appends are anchored.
func (l *Log) ReAnchor() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.heads == nil {
		return nil
	}
	return l.heads.SetLogHead(l.count, l.head)
}

// Tail returns the last n entries of r (all when n <= 0).
func Tail(entries []Entry, n int) []Entry {
	if n <= 0 || n >= len(entries) {
		return entries
	}
	return entries[len(entries)-n:]
}
