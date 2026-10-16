package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"
)

var contentTypes = map[string]string{
	".html":        "text/html; charset=utf-8",
	".js":          "text/javascript; charset=utf-8",
	".mjs":         "text/javascript; charset=utf-8",
	".css":         "text/css; charset=utf-8",
	".json":        "application/json",
	".map":         "application/json",
	".webmanifest": "application/manifest+json",
	".svg":         "image/svg+xml",
	".png":         "image/png",
	".jpg":         "image/jpeg",
	".jpeg":        "image/jpeg",
	".gif":         "image/gif",
	".webp":        "image/webp",
	".ico":         "image/x-icon",
	".woff2":       "font/woff2",
	".woff":        "font/woff",
	".wasm":        "application/wasm",
	".txt":         "text/plain; charset=utf-8",
	".wav":         "audio/wav",
	".mp3":         "audio/mpeg",
}

// hashedName matches content-hashed build outputs such as app-3F2A9C1B.js
// (esbuild/vite "[name]-[hash]" naming). The hash part must mix letters and
// digits so ordinary names like "app-settings.js" are not cached forever.
var hashedName = regexp.MustCompile(`[.-]([A-Za-z0-9_]{8,})\.[a-z0-9]+$`)

func isHashedAsset(base string) bool {
	m := hashedName.FindStringSubmatch(base)
	if m == nil {
		return false
	}
	return strings.ContainsAny(m[1], "0123456789") && strings.IndexFunc(m[1], func(r rune) bool { return r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' }) >= 0
}

type staticFile struct {
	data  []byte
	etag  string
	ctype string
}

type staticHandler struct {
	fsys  fs.FS
	cache bool
	mu    sync.Mutex
	files map[string]*staticFile
}

func newStaticHandler(fsys fs.FS, cache bool) *staticHandler {
	return &staticHandler{fsys: fsys, cache: cache, files: map[string]*staticFile{}}
}

func dirFS(dir string) fs.FS { return os.DirFS(dir) }

func (h *staticHandler) load(name string) (*staticFile, error) {
	if h.cache {
		h.mu.Lock()
		f, ok := h.files[name]
		h.mu.Unlock()
		if ok {
			return f, nil
		}
	}
	if h.fsys == nil {
		return nil, fs.ErrNotExist
	}
	st, err := fs.Stat(h.fsys, name)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, fs.ErrNotExist
	}
	data, err := fs.ReadFile(h.fsys, name)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	ext := strings.ToLower(path.Ext(name))
	ct := contentTypes[ext]
	if ct == "" {
		ct = mime.TypeByExtension(ext)
	}
	if ct == "" {
		ct = "application/octet-stream"
	}
	f := &staticFile{data: data, etag: `"` + hex.EncodeToString(sum[:16]) + `"`, ctype: ct}
	if h.cache {
		h.mu.Lock()
		h.files[name] = f
		h.mu.Unlock()
	}
	return f, nil
}

func (h *staticHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, "method-not-allowed")
		return
	}
	p := path.Clean("/" + r.URL.Path)
	name := strings.TrimPrefix(p, "/")
	if name == "" {
		name = "index.html"
	}
	for _, seg := range strings.Split(name, "/") {
		if strings.HasPrefix(seg, ".") {
			http.NotFound(w, r)
			return
		}
	}
	f, err := h.load(name)
	if errors.Is(err, fs.ErrNotExist) && path.Ext(name) == "" {
		// SPA fallback: extension-less client routes get the app shell.
		name = "index.html"
		f, err = h.load(name)
	}
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case name == "index.html" || strings.HasSuffix(name, ".html"):
		w.Header().Set("Cache-Control", "no-cache")
	case isHashedAsset(path.Base(name)):
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	default:
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.Header().Set("Content-Type", f.ctype)
	w.Header().Set("ETag", f.etag)
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(f.data))
}
