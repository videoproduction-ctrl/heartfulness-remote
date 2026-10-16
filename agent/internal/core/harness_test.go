package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/videoproduction-ctrl/heartfulness-remote/agent/internal/trust"
	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
)

const testOrigin = "https://remote.example.test"

// fakeHost is the "Mac side" in tests: it signs with a test host key and
// records everything the agent emits.
type fakeHost struct {
	priv ed25519.PrivateKey

	mu        sync.Mutex
	states    []State
	inputs    []json.RawMessage
	encoder   []EncoderCmd
	audioCtl  []string
	clipboard []string
	events    []Event
	logs      []LogResult
	signBad   bool
	notify    chan struct{}
}

func newFakeHost() *fakeHost {
	_, priv, _ := ed25519.GenerateKey(nil)
	return &fakeHost{priv: priv, notify: make(chan struct{}, 1)}
}

func (h *fakeHost) pub() []byte { return h.priv.Public().(ed25519.PublicKey) }

func (h *fakeHost) poke() {
	select {
	case h.notify <- struct{}{}:
	default:
	}
}

func (h *fakeHost) Sign(_ context.Context, data []byte) ([]byte, error) {
	h.mu.Lock()
	bad := h.signBad
	h.mu.Unlock()
	if bad {
		return make([]byte, 64), nil
	}
	return ed25519.Sign(h.priv, data), nil
}

func (h *fakeHost) EmitState(s State) {
	h.mu.Lock()
	h.states = append(h.states, s)
	h.mu.Unlock()
	h.poke()
}

func (h *fakeHost) EmitInput(m json.RawMessage) {
	h.mu.Lock()
	h.inputs = append(h.inputs, m)
	h.mu.Unlock()
	h.poke()
}

func (h *fakeHost) EmitEncoder(c EncoderCmd) {
	h.mu.Lock()
	h.encoder = append(h.encoder, c)
	h.mu.Unlock()
	h.poke()
}

func (h *fakeHost) EmitAudioCtl(c string) {
	h.mu.Lock()
	h.audioCtl = append(h.audioCtl, c)
	h.mu.Unlock()
	h.poke()
}

func (h *fakeHost) EmitClipboard(t string) {
	h.mu.Lock()
	h.clipboard = append(h.clipboard, t)
	h.mu.Unlock()
	h.poke()
}

func (h *fakeHost) EmitEvent(e Event) {
	h.mu.Lock()
	h.events = append(h.events, e)
	h.mu.Unlock()
	h.poke()
}

func (h *fakeHost) EmitLog(l LogResult) {
	h.mu.Lock()
	h.logs = append(h.logs, l)
	h.mu.Unlock()
	h.poke()
}

func (h *fakeHost) lastState() State {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.states) == 0 {
		return State{}
	}
	return h.states[len(h.states)-1]
}

func (h *fakeHost) hasEvent(name string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, e := range h.events {
		if e.Event == name {
			return true
		}
	}
	return false
}

// waitFor polls cond until true or timeout.
func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// fakeSender records host → server messages.
type fakeSender struct {
	ch chan map[string]any
}

func newFakeSender() *fakeSender { return &fakeSender{ch: make(chan map[string]any, 1024)} }

func (s *fakeSender) Send(msg any) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	m["_raw"] = string(b)
	s.ch <- m
	return nil
}

// next returns the next message of the given type (skipping others).
func (s *fakeSender) next(t *testing.T, typ string, timeout time.Duration) map[string]any {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case m := <-s.ch:
			if m["type"] == typ {
				return m
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %q", typ)
		}
	}
}

// none asserts that no message of typ arrives within d.
func (s *fakeSender) none(t *testing.T, typ string, d time.Duration) {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case m := <-s.ch:
			if m["type"] == typ {
				t.Fatalf("unexpected %q: %v", typ, m["_raw"])
			}
		case <-deadline:
			return
		}
	}
}

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type testEnv struct {
	a      *Agent
	host   *fakeHost
	srv    *fakeSender
	dir    string
	home   string
	dlDir  string
	clock  *testClock
	cancel context.CancelFunc
}

type envOpt func(*Config, *Options)

func newEnv(t *testing.T, claimed bool, opts ...envOpt) *testEnv {
	t.Helper()
	return newEnvHost(t, newFakeHost(), claimed, opts...)
}

// newEnvHost is newEnv with a given host key (e.g. the test-vector key).
func newEnvHost(t *testing.T, host *fakeHost, claimed bool, opts ...envOpt) *testEnv {
	t.Helper()
	base := t.TempDir()
	e := &testEnv{host: host, srv: newFakeSender(), dir: filepath.Join(base, "data"),
		home: filepath.Join(base, "home"), dlDir: filepath.Join(base, "dl"),
		clock: &testClock{t: time.Now()}}
	_ = os.MkdirAll(e.home, 0o700)
	cfg := Config{
		ServerURL: testOrigin, HostPub: proto.B64(host.pub()), HostName: "Test Mac",
		DataDir: e.dir, StorageKey: proto.B64(bytes.Repeat([]byte{3}, 32)),
		Settings:       Settings{AllowBrowserClients: true, IdleTimeoutMin: 30, MaxKbps: 40000, Codec: "auto"},
		AudioAvailable: true,
	}
	o := Options{NoSignaling: true, HomeDir: e.home, DownloadsDir: e.dlDir, IncludeLoopback: true,
		Codecs: []Codec{CodecH264}, Now: e.clock.now, Logf: t.Logf}
	for _, f := range opts {
		f(&cfg, &o)
	}
	e.a = New(host, o)
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	if err := e.a.Start(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		e.a.Stop()
		cancel()
	})
	e.ready(claimed)
	return e
}

func (e *testEnv) ready(claimed bool) {
	e.connect(map[string]any{"claimed": claimed})
}

// connect simulates one signaling connection like signaling.Client does:
// host-auth (returned), then host-ready with the given fields.
func (e *testEnv) connect(fields map[string]any) hostAuthMsg {
	msg, err := e.a.HostAuth(context.Background(), testOrigin, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		panic(err)
	}
	m := map[string]any{"type": "host-ready", "origin": testOrigin, "iceServers": []any{}}
	for k, v := range fields {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	e.a.OnReady(e.srv, b)
	e.sync()
	return msg.(hostAuthMsg)
}

// reconnects returns how many forced reconnects the agent requested.
func (e *testEnv) reconnects() int {
	var n int
	e.a.call(func() { n = e.a.reconnects })
	return n
}

// sync waits until the agent loop processed everything posted so far.
func (e *testEnv) sync() { e.a.call(e.a.flushState) }

func (e *testEnv) msg(m map[string]any) {
	b, _ := json.Marshal(m)
	e.a.OnMessage(m["type"].(string), b)
	e.sync()
}

func (e *testEnv) cmd(m map[string]any) {
	b, _ := json.Marshal(m)
	e.a.OnCommand(b)
	e.sync()
}

// pin adds a device signed by the test host key directly to the store.
func (e *testEnv) pin(t *testing.T, name, kind string) ed25519.PrivateKey {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	c := proto.SignCert(e.host.priv, proto.Cert{HostPub: proto.B64(e.host.pub()), DevicePub: proto.B64(pub), Name: name, Kind: kind, IssuedAt: 1700000000})
	var err error
	e.a.call(func() {
		err = e.a.store.Pin(trust.Device{Pub: proto.B64(pub), Name: name, Kind: kind, AddedAt: 1, LastUsed: 1, Cert: c})
		e.a.dirty = true
		e.a.flushState()
	})
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func pubOf(k ed25519.PrivateKey) []byte { return k.Public().(ed25519.PublicKey) }

func b64(b []byte) string { return proto.B64(b) }

func unb64(t *testing.T, v any) []byte {
	t.Helper()
	s, _ := v.(string)
	b, err := proto.UnB64(s)
	if err != nil {
		t.Fatalf("bad b64 %v", v)
	}
	return b
}

func errIs(err, target error) bool { return errors.Is(err, target) }

func contains(s, sub string) bool { return strings.Contains(s, sub) }

func jsonRoundTrip[T any](v any) (T, error) {
	var out T
	b, err := json.Marshal(v)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(b, &out)
	return out, err
}
