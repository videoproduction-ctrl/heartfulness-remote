package files

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
)

func TestSanitizeName(t *testing.T) {
	cases := map[string]string{
		"report.pdf":              "report.pdf",
		"../../etc/passwd":        "passwd",
		`..\..\windows\win.ini`:   "win.ini",
		"/abs/path/x.txt":         "x.txt",
		".bashrc":                 "bashrc",
		"...":                     "file",
		"..":                      "file",
		".":                       "file",
		"":                        "file",
		"a\x00b.txt":              "ab.txt",
		"a\nb\tc.txt":             "a_b_c.txt",
		"name:with:colons":        "name_with_colons",
		"evil‮txt.exe":            "eviltxt.exe",
		"  spaced name.txt  ":     "spaced name.txt",
		"trailing.":               "trailing",
		"Résumé — final (2).docx": "Résumé — final (2).docx",
	}
	for in, want := range cases {
		if got := SanitizeName(in); got != want {
			t.Errorf("SanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
	long := strings.Repeat("é", 300) + ".mov"
	got := SanitizeName(long)
	if len(got) > MaxNameBytes || !strings.HasSuffix(got, ".mov") || !utf8.ValidString(got) {
		t.Errorf("long name: %d bytes %q", len(got), got[len(got)-8:])
	}
	if got := SanitizeName(string([]byte{0xff, 0xfe, 'a'})); got != "a" {
		t.Errorf("invalid utf8: %q", got)
	}
}

func TestUniqueName(t *testing.T) {
	dir := t.TempDir()
	if UniqueName(dir, "a.txt") != "a.txt" {
		t.Fatal()
	}
	_ = os.WriteFile(filepath.Join(dir, "a.txt"), nil, 0o600)
	_ = os.WriteFile(filepath.Join(dir, "a (1).txt"), nil, 0o600)
	if got := UniqueName(dir, "a.txt"); got != "a (2).txt" {
		t.Fatal(got)
	}
}

func setupHome(t *testing.T) (home, outside string) {
	t.Helper()
	base := t.TempDir()
	home = filepath.Join(base, "home")
	outside = filepath.Join(base, "outside")
	for _, d := range []string{home, outside, filepath.Join(home, "Documents")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(home, "Documents", "ok.txt"), []byte("hello"), 0o600))
	must(os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0o600))
	must(os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(home, "escape-file")))
	must(os.Symlink(outside, filepath.Join(home, "escape-dir")))
	must(os.Symlink(filepath.Join(home, "Documents", "ok.txt"), filepath.Join(home, "inside-link")))
	must(os.Symlink("../../outside/secret.txt", filepath.Join(home, "Documents", "rel-escape")))
	return home, outside
}

func TestDownloadConfinement(t *testing.T) {
	home, _ := setupHome(t)
	ok := []string{"Documents/ok.txt", "/Documents/ok.txt", "Documents/../Documents/ok.txt", "inside-link"}
	for _, p := range ok {
		f, fi, err := OpenForDownload(home, p)
		if err != nil {
			t.Errorf("%q: %v", p, err)
			continue
		}
		if fi.Size() != 5 {
			t.Errorf("%q size %d", p, fi.Size())
		}
		_ = f.Close()
	}
	bad := map[string]error{
		"../outside/secret.txt":         ErrOutsideRoot,
		"../../../../../../etc/passwd":  ErrOutsideRoot,
		"Documents/../../outside/x":     ErrOutsideRoot,
		"escape-file":                   ErrOutsideRoot,
		"escape-dir/secret.txt":         ErrOutsideRoot,
		"Documents/rel-escape":          ErrOutsideRoot,
		"Documents":                     ErrNotRegular,
		"":                              ErrNotRegular,
		"Documents/missing.txt":         os.ErrNotExist,
		"Documents/ok.txt\x00.png":      ErrBadPath,
		strings.Repeat("a/", 3000) + "": ErrBadPath,
	}
	for p, want := range bad {
		f, _, err := OpenForDownload(home, p)
		if err == nil {
			_ = f.Close()
			t.Errorf("%q: opened", p)
			continue
		}
		if !errors.Is(err, want) {
			t.Errorf("%q: got %v, want %v", p, err, want)
		}
	}
	if _, _, err := OpenForDownload(home, "/dev/null"); err == nil {
		t.Error("/dev/null relative to home opened")
	}
}

func TestDeviceFileRefused(t *testing.T) {
	home := t.TempDir()
	if err := os.Symlink("/dev/zero", filepath.Join(home, "zero")); err != nil {
		t.Skip(err)
	}
	if _, _, err := OpenForDownload(home, "zero"); err == nil {
		t.Fatal("device opened")
	}
}

func TestList(t *testing.T) {
	home, _ := setupHome(t)
	ents, trunc, err := List(home, "")
	if err != nil || trunc {
		t.Fatal(err)
	}
	names := map[string]ListEntry{}
	for _, e := range ents {
		names[e.Name] = e
	}
	if _, ok := names["escape-file"]; ok {
		t.Error("escaping symlink listed")
	}
	if _, ok := names["escape-dir"]; ok {
		t.Error("escaping dir symlink listed")
	}
	if e, ok := names["Documents"]; !ok || !e.Dir {
		t.Error("Documents missing")
	}
	if e, ok := names["inside-link"]; !ok || e.Dir || e.Size != 5 {
		t.Error("inside link missing")
	}
	if !ents[0].Dir {
		t.Error("dirs not first")
	}
	if _, _, err := List(home, "escape-dir"); !errors.Is(err, ErrOutsideRoot) {
		t.Errorf("list escape: %v", err)
	}
	if _, _, err := List(home, "../outside"); !errors.Is(err, ErrOutsideRoot) {
		t.Errorf("list ..: %v", err)
	}
}

func TestUpload(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Downloads", "Heartfulness Remote")
	data := bytes.Repeat([]byte("0123456789abcdef"), 3000)
	sum := sha256.Sum256(data)
	up, err := NewUpload(dir, "../../.ssh/authorized_keys", int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(data); i += ChunkSize {
		if err := up.Write(data[i:min(i+ChunkSize, len(data))]); err != nil {
			t.Fatal(err)
		}
	}
	if err := up.Write([]byte("x")); err == nil {
		t.Fatal("wrote past announced size")
	}
	name, err := up.Finish(proto.B64(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	if name != "authorized_keys" {
		t.Fatalf("name %q", name)
	}
	got, _ := os.ReadFile(filepath.Join(dir, name))
	if !bytes.Equal(got, data) {
		t.Fatal("content")
	}
	fi, _ := os.Stat(dir)
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", fi.Mode().Perm())
	}
	// Same name again: de-duplicated, hex digest accepted.
	up2, _ := NewUpload(dir, "authorized_keys", 3)
	_ = up2.Write([]byte("abc"))
	s2 := sha256.Sum256([]byte("abc"))
	name2, err := up2.Finish(strings.ToUpper(hexs(s2[:])))
	if err != nil || name2 != "authorized_keys (1)" {
		t.Fatalf("%q %v", name2, err)
	}
	// Bad checksum: nothing left behind.
	up3, _ := NewUpload(dir, "bad.bin", 3)
	_ = up3.Write([]byte("abc"))
	if _, err := up3.Finish(proto.B64(make([]byte, 32))); err == nil {
		t.Fatal("bad checksum accepted")
	}
	// Short upload rejected.
	up4, _ := NewUpload(dir, "short.bin", 10)
	_ = up4.Write([]byte("abc"))
	if _, err := up4.Finish(proto.B64(s2[:])); err == nil {
		t.Fatal("short upload accepted")
	}
	// Aborted upload removes its temp file.
	up5, _ := NewUpload(dir, "abort.bin", 10)
	up5.Abort()
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".hr-upload-") || e.Name() == "bad.bin" || e.Name() == "short.bin" {
			t.Errorf("leftover %q", e.Name())
		}
	}
	if len(ents) != 2 {
		t.Errorf("entries: %v", ents)
	}
	if _, err := NewUpload(dir, "huge", MaxUploadSize+1); err == nil {
		t.Error("oversize upload accepted")
	}
}

func hexs(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, h[c>>4], h[c&15])
	}
	return string(out)
}
