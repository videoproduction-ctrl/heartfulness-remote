package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/videoproduction-ctrl/heartfulness-remote/agent/internal/ipc"
	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
)

// joinServer is a fake HR1.1 /ws/host for a claimed server that does not
// know the Mac yet (PROTOCOL.md §10.2): every connection gets
// host-ready {claimed:true, joined:false}.
type joinServer struct {
	ts    *httptest.Server
	auths chan map[string]any // host-auth of each connection
	got   chan map[string]any // everything else the host sends

	mu   sync.Mutex
	conn *websocket.Conn
}

func newJoinServer(t *testing.T, pub ed25519.PublicKey) *joinServer {
	s := &joinServer{auths: make(chan map[string]any, 16), got: make(chan map[string]any, 64)}
	s.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		ctx := r.Context()
		nonce := bytes.Repeat([]byte{0x24}, 32)
		b, _ := json.Marshal(map[string]any{"type": "challenge", "nonce": proto.B64(nonce)})
		_ = c.Write(ctx, websocket.MessageText, b)
		_, raw, err := c.Read(ctx)
		if err != nil {
			return
		}
		var auth map[string]any
		_ = json.Unmarshal(raw, &auth)
		sig, _ := proto.UnB64(auth["sig"].(string))
		auth["_sigOK"] = proto.Verify(pub, sig, proto.LabelHostAuth, []byte(s.ts.URL), nonce)
		s.mu.Lock()
		s.conn = c
		s.mu.Unlock()
		s.auths <- auth
		b, _ = json.Marshal(map[string]any{"type": "host-ready", "claimed": true, "joined": false,
			"origin": s.ts.URL, "macId": proto.MacID(pub), "iceServers": []any{}})
		_ = c.Write(ctx, websocket.MessageText, b)
		for {
			_, raw, err := c.Read(ctx)
			if err != nil {
				return
			}
			var m map[string]any
			_ = json.Unmarshal(raw, &m)
			s.got <- m
		}
	}))
	t.Cleanup(s.ts.Close)
	return s
}

// send writes to the newest connection.
func (s *joinServer) send(t *testing.T, m map[string]any) {
	t.Helper()
	s.mu.Lock()
	c := s.conn
	s.mu.Unlock()
	b, _ := json.Marshal(m)
	if err := c.Write(t.Context(), websocket.MessageText, b); err != nil {
		t.Fatal(err)
	}
}

func (s *joinServer) nextAuth(t *testing.T) map[string]any {
	t.Helper()
	select {
	case a := <-s.auths:
		if a["type"] != "host-auth" || a["_sigOK"] != true {
			t.Fatalf("host-auth %v", a)
		}
		return a
	case <-time.After(10 * time.Second):
		t.Fatal("no host-auth")
	}
	return nil
}

func (s *joinServer) next(t *testing.T, typ string) map[string]any {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case m := <-s.got:
			if m["type"] == typ {
				return m
			}
		case <-deadline:
			t.Fatalf("no %q", typ)
		}
	}
}

// waitState returns the first STATE satisfying cond.
func waitState(t *testing.T, states chan map[string]any, what string, cond func(map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case st := <-states:
			if cond(st) {
				return st
			}
		case <-deadline:
			t.Fatalf("no STATE with %s", what)
		}
	}
}

func TestJoinOverIPCAndSignaling(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	srv := newJoinServer(t, pub)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	var stderr bytes.Buffer
	var smu sync.Mutex
	logger := log.New(writerFunc(func(p []byte) (int, error) {
		smu.Lock()
		defer smu.Unlock()
		return stderr.Write(p)
	}), "", 0)
	exit := make(chan int, 1)
	go func() { exit <- run(inR, outW, logger); _ = outW.Close() }()
	sw := ipc.NewWriter(inW)
	cfg, _ := json.Marshal(map[string]any{
		"serverURL": srv.ts.URL, "hostPub": proto.B64(pub), "hostName": "Edit Suite Mac",
		"dataDir": t.TempDir(), "storageKey": proto.B64(bytes.Repeat([]byte{9}, 32)),
		"settings": map[string]any{"allowBrowserClients": true, "idleTimeoutMin": 30, "maxKbps": 40000, "codec": "auto"},
	})
	if err := sw.WriteFrame(ipc.TConfig, cfg); err != nil {
		t.Fatal(err)
	}
	states := make(chan map[string]any, 256)
	go func() {
		for {
			f, err := ipc.ReadFrame(outR)
			if err != nil {
				return
			}
			var m map[string]any
			_ = json.Unmarshal(f.Payload, &m)
			switch f.Type {
			case ipc.TSignRequest:
				data, _ := proto.UnB64(m["data"].(string))
				res, _ := json.Marshal(map[string]any{"id": m["id"], "sig": proto.B64(ed25519.Sign(priv, data))})
				_ = sw.WriteFrame(ipc.TSignResult, res)
			case ipc.TState:
				states <- m
			}
		}
	}()

	// 1st connection: a fresh Mac offers a 32-byte setup commit; the server
	// says "claimed, not in the account" → the agent reconnects with a join commit.
	first := srv.nextAuth(t)
	second := srv.nextAuth(t)
	c1, _ := first["claimCommit"].(string)
	c2, _ := second["claimCommit"].(string)
	if len(c1) != 43 || len(c2) != 43 || c1 == c2 {
		t.Fatalf("claim commits %q then %q", c1, c2)
	}
	st := waitState(t, states, "joinURL", func(st map[string]any) bool {
		return st["server"] == "online" && st["joinURL"] != nil
	})
	if st["macId"] != proto.MacID(pub) || st["joined"] != false || st["claimed"] != true || st["setupURL"] != nil {
		t.Fatalf("STATE %v", st)
	}
	joinURL := st["joinURL"].(string)
	tB64, hp, _ := strings.Cut(strings.TrimPrefix(joinURL, srv.ts.URL+"/#join="), ".")
	T, err := proto.UnB64Len(tB64, proto.JoinSecretSize)
	if err != nil || hp != proto.B64(pub) || st["joinCode"] != proto.JoinCode(T) {
		t.Fatalf("joinURL %q joinCode %v", joinURL, st["joinCode"])
	}
	kc, ka, _ := proto.SetupKeys(T)
	if c2 != proto.B64(proto.ClaimCommit(kc)) {
		t.Fatal("second host-auth does not commit to the displayed join code")
	}
	select {
	case a := <-srv.auths:
		t.Fatalf("unexpected third connection %v", a)
	case <-time.After(300 * time.Millisecond):
	}

	// An approved device joins: setup-device → device-approved {cert, hostMac}.
	dev, _, _ := ed25519.GenerateKey(nil)
	srv.send(t, map[string]any{"type": "setup-device", "hostPub": proto.B64(pub), "devicePub": proto.B64(dev),
		"name": "Owner's iPhone", "kind": "browser", "setupMac": proto.B64(proto.SetupMAC(ka, pub, dev, "Owner's iPhone", "browser"))})
	da := srv.next(t, "device-approved")
	certRaw, _ := json.Marshal(da["cert"])
	var cert proto.Cert
	_ = json.Unmarshal(certRaw, &cert)
	hostMac, _ := proto.UnB64(da["hostMac"].(string))
	if cert.Verify(pub) != nil || !proto.CheckHostConfirmMAC(ka, pub, dev, hostMac) {
		t.Fatalf("device-approved %v", da)
	}
	srv.next(t, "trust-sync")
	srv.next(t, "host-status")
	waitState(t, states, "joined", func(st map[string]any) bool {
		return st["joined"] == true && st["joinURL"] == nil && st["joinCode"] == nil
	})

	// The owner removes this Mac from the account → new join code.
	srv.send(t, map[string]any{"type": "error", "code": "removed"})
	third := srv.nextAuth(t)
	c3, _ := third["claimCommit"].(string)
	if len(c3) != 43 || c3 == c2 {
		t.Fatalf("claim commit after removal %q", c3)
	}
	st = waitState(t, states, "new joinCode", func(st map[string]any) bool {
		code, _ := st["joinCode"].(string)
		return st["server"] == "online" && code != "" && code != proto.JoinCode(T)
	})
	if st["joined"] != false {
		t.Fatalf("STATE after removal %v", st)
	}

	_ = sw.WriteFrame(ipc.TCommand, []byte(`{"cmd":"quit"}`))
	select {
	case <-exit:
	case <-time.After(10 * time.Second):
		t.Fatal("agent did not quit")
	}
	_ = inW.Close()
	smu.Lock()
	logText := stderr.String()
	smu.Unlock()
	for _, secret := range []string{tB64, proto.JoinCode(T), joinURL} {
		if strings.Contains(logText, secret) {
			t.Fatal("join secret leaked to stderr")
		}
	}
}
