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

// fake /ws/host that records what the host sends.
func fakeServer(t *testing.T, pub ed25519.PublicKey, claimed bool) (*httptest.Server, chan map[string]any) {
	got := make(chan map[string]any, 64)
	var origin string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		ctx := r.Context()
		nonce := bytes.Repeat([]byte{0x42}, 32)
		b, _ := json.Marshal(map[string]any{"type": "challenge", "nonce": proto.B64(nonce)})
		_ = c.Write(ctx, websocket.MessageText, b)
		_, raw, err := c.Read(ctx)
		if err != nil {
			return
		}
		var auth map[string]any
		_ = json.Unmarshal(raw, &auth)
		sig, _ := proto.UnB64(auth["sig"].(string))
		auth["_sigOK"] = proto.Verify(pub, sig, proto.LabelHostAuth, []byte(origin), nonce)
		got <- auth
		b, _ = json.Marshal(map[string]any{"type": "host-ready", "claimed": claimed, "origin": origin, "iceServers": []any{}})
		_ = c.Write(ctx, websocket.MessageText, b)
		if !claimed {
			// Like the real server after /api/setup/finish: in-band host-ready.
			time.Sleep(300 * time.Millisecond)
			got <- map[string]any{"type": "_claimed"}
			b, _ = json.Marshal(map[string]any{"type": "host-ready", "claimed": true, "origin": origin, "iceServers": []any{}})
			_ = c.Write(ctx, websocket.MessageText, b)
		}
		for {
			_, raw, err := c.Read(ctx)
			if err != nil {
				return
			}
			var m map[string]any
			_ = json.Unmarshal(raw, &m)
			got <- m
		}
	}))
	origin = ts.URL
	t.Cleanup(ts.Close)
	return ts, got
}

func TestIPCEndToEnd(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	ts, got := fakeServer(t, pub, false)

	inR, inW := io.Pipe()   // Swift → agent (agent stdin)
	outR, outW := io.Pipe() // agent → Swift (agent stdout)
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
	storageKey := bytes.Repeat([]byte{5}, 32)
	cfg, _ := json.Marshal(map[string]any{
		"serverURL": ts.URL, "hostPub": proto.B64(pub), "hostName": "Studio Mac",
		"dataDir": t.TempDir(), "storageKey": proto.B64(storageKey),
		"settings":      map[string]any{"allowBrowserClients": true, "idleTimeoutMin": 30, "maxKbps": 40000, "codec": "auto"},
		"hevcAvailable": true, "audioAvailable": true,
	})
	if err := sw.WriteFrame(ipc.TConfig, cfg); err != nil {
		t.Fatal(err)
	}

	// Act as the Swift app: answer SIGN_REQUESTs, collect STATE/LOG.
	states := make(chan map[string]any, 64)
	logs := make(chan map[string]any, 4)
	var signed sync.Map
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
				label, _, _ := strings.Cut(string(data), "\x00")
				signed.Store(label, true)
				res, _ := json.Marshal(map[string]any{"id": m["id"], "sig": proto.B64(ed25519.Sign(priv, data))})
				_ = sw.WriteFrame(ipc.TSignResult, res)
			case ipc.TState:
				states <- m
			case ipc.TLog:
				logs <- m
			}
		}
	}()

	select {
	case auth := <-got:
		if auth["type"] != "host-auth" || auth["_sigOK"] != true || auth["name"] != "Studio Mac" {
			t.Fatalf("host-auth %v", auth)
		}
		if c, _ := auth["claimCommit"].(string); len(c) != 43 {
			t.Fatalf("claimCommit missing on first run: %v", auth["claimCommit"])
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no host-auth")
	}
	if _, ok := signed.Load(proto.LabelHostAuth); !ok {
		t.Fatal("host-auth not signed via SIGN_REQUEST")
	}
	// An unclaimed host sends nothing until the server reports the claim;
	// then trust-sync and host-status follow.
	want := map[string]bool{"trust-sync": false, "host-status": false}
	claimedSeen := false
	deadline := time.After(5 * time.Second)
	for !want["trust-sync"] || !want["host-status"] {
		select {
		case m := <-got:
			typ := m["type"].(string)
			if typ == "_claimed" {
				claimedSeen = true
				continue
			}
			if !claimedSeen {
				t.Fatalf("%s sent while unclaimed", typ)
			}
			want[typ] = true
		case <-deadline:
			t.Fatalf("missing messages %v", want)
		}
	}
	// STATE goes online with a setup URL (claimed:false).
	deadline = time.After(5 * time.Second)
	for {
		var st map[string]any
		select {
		case st = <-states:
		case <-deadline:
			t.Fatal("no online STATE with setupURL")
		}
		if st["server"] == "online" {
			if u, _ := st["setupURL"].(string); strings.HasPrefix(u, ts.URL+"/#setup=") && strings.HasSuffix(u, "."+proto.B64(pub)) {
				break
			}
		}
	}

	// COMMAND log-read → LOG.
	cmd, _ := json.Marshal(map[string]any{"cmd": "log-read", "limit": 10})
	_ = sw.WriteFrame(ipc.TCommand, cmd)
	select {
	case l := <-logs:
		if l["verified"] != true {
			t.Fatalf("log %v", l)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no LOG")
	}
	// Garbage VIDEO/AUDIO frames are ignored without crashing.
	_ = sw.WriteFrame(ipc.TVideo, []byte{1})
	_ = sw.WriteFrame(ipc.TAudio, []byte{1})
	_ = sw.WriteFrame(0x7f, []byte("unknown"))

	// COMMAND quit → clean exit.
	cmd, _ = json.Marshal(map[string]any{"cmd": "quit"})
	_ = sw.WriteFrame(ipc.TCommand, cmd)
	select {
	case code := <-exit:
		if code != 0 {
			t.Fatalf("exit %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("agent did not quit")
	}
	smu.Lock()
	logText := stderr.String()
	smu.Unlock()
	if strings.Contains(logText, proto.B64(storageKey)) {
		t.Fatal("storage key leaked to stderr")
	}
	_ = inW.Close()
}

func TestStdinEOFStopsAgent(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	inR, inW := io.Pipe()
	exit := make(chan int, 1)
	go func() { exit <- run(inR, io.Discard, log.New(io.Discard, "", 0)) }()
	sw := ipc.NewWriter(inW)
	cfg, _ := json.Marshal(map[string]any{"serverURL": "https://127.0.0.1:1", "hostPub": proto.B64(pub),
		"dataDir": t.TempDir(), "storageKey": proto.B64(bytes.Repeat([]byte{1}, 32))})
	_ = sw.WriteFrame(ipc.TConfig, cfg)
	time.Sleep(100 * time.Millisecond)
	_ = inW.Close() // the Mac app died
	select {
	case code := <-exit:
		if code != 0 {
			t.Fatalf("exit %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("agent kept running after stdin EOF")
	}
}

func TestConfigRequiredFirst(t *testing.T) {
	var in bytes.Buffer
	_ = ipc.NewWriter(&in).WriteFrame(ipc.TCommand, []byte(`{"cmd":"quit"}`))
	if code := run(&in, io.Discard, log.New(io.Discard, "", 0)); code != 2 {
		t.Fatalf("exit %d", code)
	}
	in.Reset()
	_ = ipc.NewWriter(&in).WriteFrame(ipc.TConfig, []byte(`{"hostPub":"short"}`))
	if code := run(&in, io.Discard, log.New(io.Discard, "", 0)); code != 2 {
		t.Fatalf("bad config exit %d", code)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
