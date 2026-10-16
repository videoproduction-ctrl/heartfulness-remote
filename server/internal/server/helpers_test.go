package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/coder/websocket"

	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
	"github.com/videoproduction-ctrl/heartfulness-remote/server/internal/config"
	"github.com/videoproduction-ctrl/heartfulness-remote/server/internal/store"
)

const (
	testOrigin = "http://localhost:8080"
	testSecret = "test-turn-secret-0123456789"
	tauri      = "tauri://localhost"
)

type testEnv struct {
	t     *testing.T
	cfg   *config.Config
	srv   *Server
	st    *store.Store
	ts    *httptest.Server
	dir   string
	clock *testClock
}

type storeState = store.State

// testClock is real time plus an adjustable offset (safe for concurrent use).
type testClock struct {
	mu  sync.Mutex
	off time.Duration
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.off)
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	c.off += d
	c.mu.Unlock()
}

var testWeb = fstest.MapFS{
	"index.html":           {Data: []byte("<!doctype html><title>HR</title>")},
	"app-3F2A9C1B.js":      {Data: []byte("console.log(1)")},
	"style.css":            {Data: []byte("body{}")},
	"manifest.webmanifest": {Data: []byte("{}")},
	"icons/icon.svg":       {Data: []byte("<svg/>")},
}

// newEnv starts a server. extra overrides HR_* settings. 127.0.0.1 is a
// trusted proxy so tests can choose client IPs with X-Forwarded-For.
func newEnv(t *testing.T, extra map[string]string) *testEnv {
	t.Helper()
	dir := t.TempDir()
	vars := map[string]string{
		"HR_ORIGIN":          testOrigin,
		"HR_DATA_DIR":        dir,
		"HR_TURN_SECRET":     testSecret,
		"HR_TURN_HOST":       "turn.example.org",
		"HR_TRUSTED_PROXIES": "127.0.0.1/32,::1/128",
	}
	for k, v := range extra {
		vars[k] = v
	}
	cfg, err := config.Load(func(k string) string { return vars[k] })
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	clock := &testClock{}
	srv, err := New(cfg, st, Options{WebFS: testWeb, Now: clock.now})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	e := &testEnv{t: t, cfg: cfg, srv: srv, st: st, ts: ts, dir: dir, clock: clock}
	t.Cleanup(func() {
		srv.hub.closeAll()
		ts.Close()
	})
	return e
}

// client is a browser-like HTTP client with one IP and an optional session.
type client struct {
	e      *testEnv
	ip     string
	origin string
	cookie string
	bearer string
}

func (e *testEnv) client(ip string) *client {
	return &client{e: e, ip: ip, origin: e.cfg.Origin}
}

type resp struct {
	code int
	hdr  http.Header
	body []byte
}

func (r resp) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.body, &m); err != nil {
		t.Fatalf("json: %v (%d %s)", err, r.code, r.body)
	}
	return m
}

func (c *client) do(method, path string, body any, mod ...func(*http.Request)) resp {
	t := c.e.t
	t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	req, err := http.NewRequest(method, c.e.ts.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.ip != "" {
		req.Header.Set("X-Forwarded-For", c.ip)
	}
	if c.origin != "" && method != http.MethodGet {
		req.Header.Set("Origin", c.origin)
	}
	if method == http.MethodPost && c.origin == c.e.cfg.Origin {
		req.Header.Set("X-HR", "1")
	}
	if c.cookie != "" {
		req.AddCookie(&http.Cookie{Name: c.e.cfg.CookieName(), Value: c.cookie})
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	for _, m := range mod {
		m(req)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	for _, ck := range res.Cookies() {
		if ck.Name == c.e.cfg.CookieName() {
			c.cookie = ck.Value
			if ck.MaxAge < 0 {
				c.cookie = ""
			}
		}
	}
	return resp{code: res.StatusCode, hdr: res.Header, body: b}
}

func (c *client) post(path string, body any) resp { return c.do(http.MethodPost, path, body) }
func (c *client) get(path string) resp            { return c.do(http.MethodGet, path, nil) }

// ---- WebSocket peers ----

type peer struct {
	t  *testing.T
	ws *websocket.Conn
	in chan map[string]any
}

func (e *testEnv) dial(path string, hdr http.Header) (*peer, *http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	u := "ws" + strings.TrimPrefix(e.ts.URL, "http") + path
	ws, res, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPHeader: hdr})
	if err != nil {
		return nil, res, err
	}
	ws.SetReadLimit(1 << 20)
	p := &peer{t: e.t, ws: ws, in: make(chan map[string]any, 512)}
	go func() {
		defer close(p.in)
		for {
			_, data, err := ws.Read(context.Background())
			if err != nil {
				return
			}
			var m map[string]any
			if json.Unmarshal(data, &m) == nil {
				p.in <- m
			}
		}
	}()
	e.t.Cleanup(func() { _ = ws.CloseNow() })
	return p, res, nil
}

func (p *peer) send(v any) {
	p.t.Helper()
	b, _ := json.Marshal(v)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.ws.Write(ctx, websocket.MessageText, b); err != nil {
		p.t.Fatalf("send: %v", err)
	}
}

// background messages that may interleave with anything.
var noise = map[string]bool{"host-status": true, "devices-changed": true, "turn": true}

// expect waits for a message of the given type, skipping broadcast noise.
// Any other unexpected message fails the test.
func (p *peer) expect(typ string) map[string]any {
	p.t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case m, ok := <-p.in:
			if !ok {
				p.t.Fatalf("connection closed while waiting for %q", typ)
			}
			if m["type"] == typ {
				return m
			}
			if !noise[m["type"].(string)] {
				p.t.Fatalf("waiting for %q, got %v", typ, m)
			}
		case <-timeout:
			p.t.Fatalf("timed out waiting for %q", typ)
		}
	}
}

// expectError waits for an error message with the given code.
func (p *peer) expectError(code string) map[string]any {
	p.t.Helper()
	m := p.expect("error")
	if m["code"] != code {
		p.t.Fatalf("error code %v, want %q", m["code"], code)
	}
	return m
}

// expectNone asserts no message of typ (other than noise) arrives within d.
func (p *peer) expectNone(d time.Duration) {
	p.t.Helper()
	timeout := time.After(d)
	for {
		select {
		case m, ok := <-p.in:
			if !ok {
				return
			}
			if !noise[m["type"].(string)] {
				p.t.Fatalf("unexpected message %v", m)
			}
		case <-timeout:
			return
		}
	}
}

// expectClosed waits until the server closes the connection.
func (p *peer) expectClosed() {
	p.t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-p.in:
			if !ok {
				return
			}
		case <-timeout:
			p.t.Fatal("connection not closed")
		}
	}
}

// ---- fake Mac host ----

type fakeHost struct {
	*peer
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
	kc, ka  []byte
	commit  []byte
	setupT  []byte
	pubB64  string
	certsOK map[string]proto.Cert
}

func newFakeHost(t *testing.T) *fakeHost {
	pub, priv, _ := ed25519.GenerateKey(nil)
	tt := randBytes(32)
	kc, ka, err := proto.SetupKeys(tt)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeHost{pub: pub, priv: priv, kc: kc, ka: ka, commit: proto.ClaimCommit(kc), setupT: tt, pubB64: proto.B64(pub), certsOK: map[string]proto.Cert{}}
}

// connect dials /ws/host and authenticates; returns the first reply
// (host-ready or error).
func (h *fakeHost) connect(e *testEnv, ip, signOrigin string, withCommit bool) map[string]any {
	e.t.Helper()
	hdr := http.Header{"X-Forwarded-For": {ip}}
	p, _, err := e.dial("/ws/host", hdr)
	if err != nil {
		e.t.Fatalf("dial host: %v", err)
	}
	h.peer = p
	ch := p.expect("challenge")
	nonce, _ := proto.UnB64(ch["nonce"].(string))
	sig := proto.Sign(h.priv, proto.LabelHostAuth, proto.Str(signOrigin), nonce)
	m := map[string]any{"type": "host-auth", "hostPub": h.pubB64, "name": "Studio Mac", "version": "test", "sig": proto.B64(sig)}
	if withCommit {
		m["claimCommit"] = proto.B64(h.commit)
	}
	p.send(m)
	select {
	case r, ok := <-p.in:
		if !ok {
			e.t.Fatal("host connection closed without reply")
		}
		return r
	case <-time.After(5 * time.Second):
		e.t.Fatal("no host-auth reply")
	}
	return nil
}

func (h *fakeHost) cert(devPub []byte, name, kind string) proto.Cert {
	c := proto.SignCert(h.priv, proto.Cert{HostPub: h.pubB64, DevicePub: proto.B64(devPub), Name: name, Kind: kind, IssuedAt: time.Now().Unix()})
	h.certsOK[c.DevicePub] = c
	return c
}

// ---- fake client device ----

type device struct {
	*peer
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	name string
	kind string
}

func newDevice(name string) *device {
	pub, priv, _ := ed25519.GenerateKey(nil)
	return &device{pub: pub, priv: priv, name: name, kind: "browser"}
}

func (d *device) pubB64() string { return proto.B64(d.pub) }

// connect opens /ws/client with the client's cookie (or token) and completes
// device authentication; returns the ready message.
func (d *device) connect(e *testEnv, c *client, token string) map[string]any {
	e.t.Helper()
	p := d.dialAuth(e, c, token)
	return p.expect("ready")
}

func (d *device) dialAuth(e *testEnv, c *client, token string) *peer {
	e.t.Helper()
	hdr := http.Header{"X-Forwarded-For": {c.ip}, "Origin": {c.origin}}
	if c.cookie != "" {
		hdr.Set("Cookie", e.cfg.CookieName()+"="+c.cookie)
	}
	p, _, err := e.dial("/ws/client", hdr)
	if err != nil {
		e.t.Fatalf("dial client: %v", err)
	}
	d.peer = p
	auth := map[string]any{"type": "auth"}
	if token != "" {
		auth["token"] = token
	}
	p.send(auth)
	ch := p.expect("challenge")
	nonce, _ := proto.UnB64(ch["nonce"].(string))
	p.send(map[string]any{"type": "device-auth", "devicePub": d.pubB64(), "sig": proto.B64(proto.Sign(d.priv, proto.LabelClientAuth, proto.Str(e.cfg.Origin), nonce))})
	return p
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := proto.UnB64(s)
	if err != nil {
		t.Fatalf("b64 %q: %v", s, err)
	}
	return b
}

// claim runs the full bootstrap: host connects with a commit, the phone
// claims with a passkey, the host approves the phone via setup-device.
// Returns the host, the logged-in phone client, its authenticator and device.
func (e *testEnv) claim() (*fakeHost, *client, *softAuthn, *device) {
	t := e.t
	t.Helper()
	h := newFakeHost(t)
	if r := h.connect(e, "203.0.113.1", e.cfg.Origin, true); r["type"] != "host-ready" || r["claimed"] != false {
		t.Fatalf("host-ready: %v", r)
	}
	phone := e.client("198.51.100.10")
	r := phone.post("/api/setup/begin", map[string]any{"hostPub": h.pubB64, "claim": proto.B64(h.kc)})
	if r.code != 200 {
		t.Fatalf("setup/begin: %d %s", r.code, r.body)
	}
	begin := r.json(t)
	opts, _ := json.Marshal(begin["options"])
	authn := newSoftAuthn(t)
	cred := authn.create(t, opts, e.cfg.Origin)
	dev := newDevice("Phone")
	dev.kind = "phone"
	mac := proto.SetupMAC(h.ka, h.pub, dev.pub, dev.name, dev.kind)
	r = phone.post("/api/setup/finish", map[string]any{
		"flowId": begin["flowId"], "credential": json.RawMessage(cred),
		"device":   map[string]any{"pub": dev.pubB64(), "name": dev.name, "kind": dev.kind},
		"setupMac": proto.B64(mac),
	})
	if r.code != 200 || phone.cookie == "" {
		t.Fatalf("setup/finish: %d %s", r.code, r.body)
	}
	if hr := h.expect("host-ready"); hr["claimed"] != true {
		t.Fatalf("host-ready after claim: %v", hr)
	}
	sd := h.expect("setup-device")
	if str(sd, "devicePub") != dev.pubB64() || !proto.CheckSetupMAC(h.ka, h.pub, dev.pub, str(sd, "name"), str(sd, "kind"), mustB64(t, str(sd, "setupMac"))) {
		t.Fatalf("setup-device: %v", sd)
	}
	ready := dev.connect(e, phone, "")
	if ready["device"].(map[string]any)["status"] != store.StatusPending {
		t.Fatalf("phone status before approval: %v", ready)
	}
	h.send(map[string]any{"type": "device-approved", "cert": h.cert(dev.pub, dev.name, dev.kind)})
	pa := dev.expect("pair-approved")
	if pa["cert"].(map[string]any)["devicePub"] != dev.pubB64() {
		t.Fatalf("pair-approved: %v", pa)
	}
	return h, phone, authn, dev
}

// login performs a passkey login from a new client.
func (e *testEnv) login(authn *softAuthn, ip string) *client {
	t := e.t
	t.Helper()
	c := e.client(ip)
	r := c.post("/api/login/begin", nil)
	if r.code != 200 {
		t.Fatalf("login/begin: %d %s", r.code, r.body)
	}
	b := r.json(t)
	opts, _ := json.Marshal(b["options"])
	r = c.post("/api/login/finish", map[string]any{"flowId": b["flowId"], "credential": json.RawMessage(authn.get(t, opts, e.cfg.Origin, false))})
	if r.code != 200 || c.cookie == "" {
		t.Fatalf("login/finish: %d %s", r.code, r.body)
	}
	return c
}
