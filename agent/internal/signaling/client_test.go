package signaling

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
)

func TestEndpoints(t *testing.T) {
	cases := []struct {
		in, origin, ws string
		insecure       bool
		bad            bool
	}{
		{in: "https://Remote.Example.org", origin: "https://remote.example.org", ws: "wss://remote.example.org/ws/host"},
		{in: "https://remote.example.org/", origin: "https://remote.example.org", ws: "wss://remote.example.org/ws/host"},
		{in: "https://remote.example.org:443/app", origin: "https://remote.example.org", ws: "wss://remote.example.org/ws/host"},
		{in: "https://remote.example.org:8443", origin: "https://remote.example.org:8443", ws: "wss://remote.example.org:8443/ws/host"},
		{in: "http://localhost:8080", origin: "http://localhost:8080", ws: "ws://localhost:8080/ws/host"},
		{in: "http://127.0.0.1:8080", origin: "http://127.0.0.1:8080", ws: "ws://127.0.0.1:8080/ws/host"},
		{in: "http://[::1]:8080", origin: "http://[::1]:8080", ws: "ws://[::1]:8080/ws/host"},
		{in: "http://192.168.1.5:8080", bad: true},
		{in: "http://192.168.1.5:8080", insecure: true, origin: "http://192.168.1.5:8080", ws: "ws://192.168.1.5:8080/ws/host"},
		{in: "https://user:pw@remote.example.org", bad: true},
		{in: "ftp://remote.example.org", bad: true},
		{in: "remote.example.org", bad: true},
		{in: "", bad: true},
	}
	for _, c := range cases {
		o, w, err := Endpoints(c.in, c.insecure)
		if c.bad {
			if err == nil {
				t.Errorf("%q accepted", c.in)
			}
			continue
		}
		if err != nil || o != c.origin || w != c.ws {
			t.Errorf("%q → %q %q %v", c.in, o, w, err)
		}
	}
}

func TestBackoff(t *testing.T) {
	c := New("", "", nil, "t")
	prevMax := time.Duration(0)
	for n := range 12 {
		d := c.backoff(n)
		if d < MinBackoff/2 || d > MaxBackoff {
			t.Fatalf("backoff(%d) = %v", n, d)
		}
		if n >= 7 && d < MaxBackoff/2 {
			t.Fatalf("backoff(%d) = %v not capped high", n, d)
		}
		prevMax = max(prevMax, d)
	}
	if prevMax > MaxBackoff {
		t.Fatal("over max")
	}
}

type fakeHandler struct {
	priv     ed25519.PrivateKey
	mu       sync.Mutex
	statuses []string
	readies  int
	msgs     []string
	sender   Sender
}

func (h *fakeHandler) HostAuth(_ context.Context, origin string, nonce []byte) (any, error) {
	pub := h.priv.Public().(ed25519.PublicKey)
	return map[string]any{
		"type": "host-auth", "hostPub": proto.B64(pub), "name": "Mac", "version": "t",
		"sig": proto.B64(proto.Sign(h.priv, proto.LabelHostAuth, []byte(origin), nonce)),
	}, nil
}

func (h *fakeHandler) OnReady(s Sender, _ []byte) {
	h.mu.Lock()
	h.readies++
	h.sender = s
	h.mu.Unlock()
}

func (h *fakeHandler) OnMessage(typ string, _ []byte) {
	h.mu.Lock()
	h.msgs = append(h.msgs, typ)
	h.mu.Unlock()
}

func (h *fakeHandler) OnStatus(s, code string) {
	h.mu.Lock()
	if code != "" {
		s += ":" + code
	}
	h.statuses = append(h.statuses, s)
	h.mu.Unlock()
}

func (h *fakeHandler) snapshot() (int, []string, []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.readies, append([]string{}, h.statuses...), append([]string{}, h.msgs...)
}

// fakeServer implements the host side of /ws/host: challenge, verify
// host-auth, host-ready. The first connection is dropped after a message.
type fakeServer struct {
	t       *testing.T
	pub     ed25519.PublicKey
	origin  string
	mu      sync.Mutex
	conns   int
	nonces  map[string]bool
	authOK  int
	authBad int
	errCode string
	got     chan map[string]any
}

func (s *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/ws/host" {
		http.NotFound(w, r)
		return
	}
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer c.CloseNow()
	s.mu.Lock()
	s.conns++
	n := s.conns
	errCode := s.errCode
	s.mu.Unlock()
	ctx := r.Context()
	nonce := make([]byte, 32)
	nonce[0], nonce[1] = byte(n), 0xAA
	write := func(v any) {
		b, _ := json.Marshal(v)
		_ = c.Write(ctx, websocket.MessageText, b)
	}
	write(map[string]any{"type": "challenge", "nonce": proto.B64(nonce)})
	_, raw, err := c.Read(ctx)
	if err != nil {
		return
	}
	var auth map[string]string
	_ = json.Unmarshal(raw, &auth)
	sig, _ := proto.UnB64(auth["sig"])
	hp, _ := proto.UnB64(auth["hostPub"])
	ok := auth["type"] == "host-auth" && string(hp) == string(s.pub) &&
		proto.Verify(hp, sig, proto.LabelHostAuth, []byte(s.origin), nonce)
	s.mu.Lock()
	if ok && !s.nonces[string(nonce)] {
		s.authOK++
		s.nonces[string(nonce)] = true
	} else {
		s.authBad++
	}
	s.mu.Unlock()
	if !ok {
		write(map[string]any{"type": "error", "code": "bad-signature"})
		return
	}
	if errCode != "" {
		write(map[string]any{"type": "error", "code": errCode})
		return
	}
	write(map[string]any{"type": "host-ready", "claimed": true, "origin": s.origin, "iceServers": []any{}})
	write(map[string]any{"type": "turn", "iceServers": []any{}})
	if n == 1 {
		time.Sleep(50 * time.Millisecond)
		_ = c.Close(websocket.StatusGoingAway, "drop") // simulate a server restart
		return
	}
	for {
		_, raw, err := c.Read(ctx)
		if err != nil {
			return
		}
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		s.got <- m
	}
}

func startServer(t *testing.T, pub ed25519.PublicKey) (*fakeServer, *httptest.Server) {
	fs := &fakeServer{t: t, pub: pub, nonces: map[string]bool{}, got: make(chan map[string]any, 16)}
	ts := httptest.NewServer(fs)
	t.Cleanup(ts.Close)
	fs.origin = ts.URL
	return fs, ts
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out: %s", what)
}

func TestHostAuthAndReconnect(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	fs, ts := startServer(t, pub)
	origin, wsURL, err := Endpoints(ts.URL, false)
	if err != nil {
		t.Fatal(err)
	}
	h := &fakeHandler{priv: priv}
	c := New(origin, wsURL, h, "test")
	c.MinBackoff, c.MaxBackoff = 10*time.Millisecond, 40*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	waitUntil(t, "two successful host-auths", func() bool {
		r, _, _ := h.snapshot()
		return r >= 2
	})
	fs.mu.Lock()
	if fs.authOK < 2 || fs.authBad != 0 {
		t.Fatalf("auth ok=%d bad=%d", fs.authOK, fs.authBad)
	}
	fs.mu.Unlock()
	_, statuses, msgs := h.snapshot()
	joined := strings.Join(statuses, ",")
	if !strings.HasPrefix(joined, "connecting,online,offline,connecting,online") {
		t.Fatalf("statuses %v", statuses)
	}
	if len(msgs) < 1 || msgs[0] != "turn" {
		t.Fatalf("messages %v", msgs)
	}
	// Sending on the live connection.
	waitUntil(t, "send", func() bool {
		return c.Send(map[string]any{"type": "host-status", "state": "available"}) == nil
	})
	select {
	case m := <-fs.got:
		if m["type"] != "host-status" {
			t.Fatalf("got %v", m)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not receive message")
	}
	// Oversize messages are refused client-side.
	if err := c.Send(map[string]string{"type": "x", "pad": strings.Repeat("a", MaxMessage)}); err == nil {
		t.Fatal("oversize message sent")
	}
	// Explicit reconnect (new setup code) produces a fresh authentication.
	c.Reconnect()
	waitUntil(t, "reconnect", func() bool {
		r, _, _ := h.snapshot()
		return r >= 3
	})
}

func TestServerErrorCode(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	fs, ts := startServer(t, pub)
	fs.errCode = "claimed-by-other-host"
	origin, wsURL, _ := Endpoints(ts.URL, false)
	h := &fakeHandler{priv: priv}
	c := New(origin, wsURL, h, "test")
	c.MinBackoff, c.MaxBackoff = 10*time.Millisecond, 20*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	waitUntil(t, "error status", func() bool {
		_, st, _ := h.snapshot()
		return strings.Contains(strings.Join(st, ","), "error:claimed-by-other-host")
	})
	if r, _, _ := h.snapshot(); r != 0 {
		t.Fatal("ready despite error")
	}
}

func TestWrongKeyRejectedByServer(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	_, other, _ := ed25519.GenerateKey(nil)
	fs, ts := startServer(t, pub)
	origin, wsURL, _ := Endpoints(ts.URL, false)
	h := &fakeHandler{priv: other}
	c := New(origin, wsURL, h, "test")
	c.MinBackoff, c.MaxBackoff = 10*time.Millisecond, 20*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	waitUntil(t, "bad-signature", func() bool {
		_, st, _ := h.snapshot()
		return strings.Contains(strings.Join(st, ","), "error:bad-signature")
	})
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.authOK != 0 {
		t.Fatal("server accepted the wrong key")
	}
}
