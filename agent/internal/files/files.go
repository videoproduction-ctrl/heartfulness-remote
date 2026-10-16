// Package files implements the file-transfer safety rules (PROTOCOL.md §8.1):
// sanitised, de-duplicated upload names written via a temp file and renamed
// only after the SHA-256 verifies; downloads and listings confined to a root
// (the Mac user's home) with symlinks resolved and escapes refused.
package files

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
)

// Limits.
const (
	MaxNameBytes   = 200
	MaxUploadSize  = 64 << 30 // 64 GiB
	MaxListEntries = 2000
	ChunkSize      = 16 << 10
)

var (
	// ErrOutsideRoot is returned when a path resolves outside the root.
	ErrOutsideRoot = errors.New("path is outside the allowed folder")
	// ErrNotRegular is returned for directories, devices, sockets, …
	ErrNotRegular = errors.New("not a regular file")
	// ErrBadPath is returned for malformed paths.
	ErrBadPath = errors.New("invalid path")
)

// SanitizeName returns a safe single-component file name: no path separators,
// no control characters, no leading dots/spaces, at most MaxNameBytes bytes
// (extension preserved), never empty, "." or "..".
func SanitizeName(name string) string {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r == utf8.RuneError, r == 0:
			continue
		case unicode.IsControl(r), r == ':' || r == '/' || r == '\\':
			b.WriteRune('_')
		case unicode.Is(unicode.Cf, r): // bidi overrides, zero-width chars
			continue
		default:
			b.WriteRune(r)
		}
	}
	s := strings.TrimLeft(b.String(), ". \t")
	s = strings.TrimRight(s, ". \t")
	if s == "" {
		s = "file"
	}
	if len(s) > MaxNameBytes {
		ext := filepath.Ext(s)
		if len(ext) > 20 || !utf8.ValidString(ext) {
			ext = ""
		}
		base := s[:MaxNameBytes-len(ext)]
		for !utf8.ValidString(base) {
			base = base[:len(base)-1]
		}
		s = base + ext
	}
	return s
}

// UniqueName returns name, or "name (n).ext" for the first n that does not
// exist in dir.
func UniqueName(dir, name string) string {
	if _, err := os.Lstat(filepath.Join(dir, name)); errors.Is(err, fs.ErrNotExist) {
		return name
	}
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	for i := 1; i < 10000; i++ {
		c := fmt.Sprintf("%s (%d)%s", base, i, ext)
		if _, err := os.Lstat(filepath.Join(dir, c)); errors.Is(err, fs.ErrNotExist) {
			return c
		}
	}
	return fmt.Sprintf("%s (%s)%s", base, randHex(4), ext)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Resolve maps rel (relative to root, "/"-separated, "" = root) to a real
// path inside root. Symlinks are resolved; anything that ends up outside the
// root is refused.
func Resolve(root, rel string) (string, error) {
	if strings.ContainsRune(rel, 0) || len(rel) > 4096 {
		return "", ErrBadPath
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	realRoot, err = filepath.Abs(realRoot)
	if err != nil {
		return "", err
	}
	rel = strings.TrimLeft(filepath.FromSlash(rel), string(filepath.Separator))
	p := filepath.Join(realRoot, rel) // Join cleans ".." components
	if !within(realRoot, p) {
		return "", ErrOutsideRoot
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", err
	}
	real, err = filepath.Abs(real)
	if err != nil {
		return "", err
	}
	if !within(realRoot, real) {
		return "", ErrOutsideRoot
	}
	return real, nil
}

func within(root, p string) bool {
	if p == root {
		return true
	}
	return strings.HasPrefix(p, strings.TrimSuffix(root, string(filepath.Separator))+string(filepath.Separator))
}

// OpenForDownload opens a regular file inside root for reading.
func OpenForDownload(root, rel string) (*os.File, fs.FileInfo, error) {
	real, err := Resolve(root, rel)
	if err != nil {
		return nil, nil, err
	}
	pre, err := os.Lstat(real)
	if err != nil {
		return nil, nil, err
	}
	if !pre.Mode().IsRegular() {
		return nil, nil, ErrNotRegular
	}
	f, err := openNoFollow(real)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || !os.SameFile(fi, pre) {
		_ = f.Close()
		if err == nil {
			err = ErrNotRegular
		}
		return nil, nil, err
	}
	return f, fi, nil
}

// ListEntry is one entry of an ls-result.
type ListEntry struct {
	Name  string `json:"name"`
	Dir   bool   `json:"dir"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime"` // unix seconds
}

// List lists a directory inside root. Entries are sorted (dirs first, then by
// name); symlinks are followed only when their target stays inside root
// (otherwise they are omitted). truncated is true when MaxListEntries was hit.
func List(root, rel string) (entries []ListEntry, truncated bool, err error) {
	real, err := Resolve(root, rel)
	if err != nil {
		return nil, false, err
	}
	fi, err := os.Stat(real)
	if err != nil {
		return nil, false, err
	}
	if !fi.IsDir() {
		return nil, false, errors.New("not a folder")
	}
	des, err := os.ReadDir(real)
	if err != nil {
		return nil, false, err
	}
	realRoot, _ := Resolve(root, "")
	for _, de := range des {
		if len(entries) >= MaxListEntries {
			truncated = true
			break
		}
		p := filepath.Join(real, de.Name())
		info, err := os.Lstat(p)
		if err != nil {
			continue
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			t, err := filepath.EvalSymlinks(p)
			if err != nil || !within(realRoot, t) {
				continue
			}
			if info, err = os.Stat(t); err != nil {
				continue
			}
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			continue
		}
		e := ListEntry{Name: de.Name(), Dir: info.IsDir(), MTime: info.ModTime().Unix()}
		if !e.Dir {
			e.Size = info.Size()
		}
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Dir != entries[j].Dir {
			return entries[i].Dir
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	return entries, truncated, nil
}

// Upload is an in-progress incoming file: data goes to a private temp file in
// the destination folder and is renamed to a sanitised, de-duplicated name
// only after size and SHA-256 match.
type Upload struct {
	dir      string
	name     string // sanitised requested name
	size     int64
	received int64
	f        *os.File
	h        hash.Hash
}

// NewUpload creates the destination folder (0700) and a temp file (0600).
func NewUpload(dir, requestedName string, size int64) (*Upload, error) {
	if size < 0 || size > MaxUploadSize {
		return nil, errors.New("file too large")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if free, ok := freeBytes(dir); ok && uint64(size)+(64<<20) > free {
		return nil, errors.New("not enough disk space")
	}
	f, err := os.OpenFile(filepath.Join(dir, ".hr-upload-"+randHex(12)+".part"),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	return &Upload{dir: dir, name: SanitizeName(requestedName), size: size, f: f, h: sha256.New()}, nil
}

// Write appends a chunk; writing past the announced size is an error.
func (u *Upload) Write(chunk []byte) error {
	if u.received+int64(len(chunk)) > u.size {
		return errors.New("more data than announced")
	}
	if _, err := u.f.Write(chunk); err != nil {
		return err
	}
	u.h.Write(chunk)
	u.received += int64(len(chunk))
	return nil
}

// Received returns the number of bytes written so far.
func (u *Upload) Received() int64 { return u.received }

// Size returns the announced size.
func (u *Upload) Size() int64 { return u.size }

// Finish verifies size and hash (b64url SHA-256) and moves the file to its
// final, unique name. It returns the final name.
func (u *Upload) Finish(sha256B64 string) (string, error) {
	defer u.cleanup()
	if u.received != u.size {
		return "", fmt.Errorf("size mismatch: got %d of %d bytes", u.received, u.size)
	}
	want, err := DecodeDigest(sha256B64)
	if err != nil {
		return "", err
	}
	if subtle.ConstantTimeCompare(u.h.Sum(nil), want) != 1 {
		return "", errors.New("checksum mismatch")
	}
	if err := u.f.Sync(); err != nil {
		return "", err
	}
	if err := u.f.Close(); err != nil {
		return "", err
	}
	tmp := u.f.Name()
	for range 5 {
		name := UniqueName(u.dir, u.name)
		dst := filepath.Join(u.dir, name)
		// Link never overwrites an existing file; fall back to rename on
		// filesystems without hard links.
		if err := os.Link(tmp, dst); err == nil {
			_ = os.Remove(tmp)
			return name, nil
		} else if errors.Is(err, fs.ErrExist) {
			continue
		}
		if _, err := os.Lstat(dst); errors.Is(err, fs.ErrNotExist) {
			if err := os.Rename(tmp, dst); err != nil {
				return "", err
			}
			return name, nil
		}
	}
	return "", errors.New("could not pick a unique file name")
}

// Abort deletes the temp file.
func (u *Upload) Abort() { u.cleanup() }

func (u *Upload) cleanup() {
	if u.f != nil {
		_ = u.f.Close()
		_ = os.Remove(u.f.Name())
	}
}

// DecodeDigest accepts a SHA-256 digest as b64url (no padding, PROTOCOL.md
// §2) or, leniently, lowercase/uppercase hex.
func DecodeDigest(s string) ([]byte, error) {
	if b, err := proto.UnB64Len(s, sha256.Size); err == nil {
		return b, nil
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == sha256.Size {
		return b, nil
	}
	return nil, errors.New("bad sha256 encoding")
}

// HashReader is a helper that hashes everything read through it.
type HashReader struct {
	R io.Reader
	H hash.Hash
}

// NewHashReader wraps r.
func NewHashReader(r io.Reader) *HashReader { return &HashReader{R: r, H: sha256.New()} }

func (h *HashReader) Read(p []byte) (int, error) {
	n, err := h.R.Read(p)
	h.H.Write(p[:n])
	return n, err
}
