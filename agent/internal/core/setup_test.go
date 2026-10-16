package core

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
)

func TestSetupClaimFlow(t *testing.T) {
	e := newEnv(t, false)
	hostPub := e.host.pub()

	// host-auth carries the claim commit and a valid host signature.
	nonce := randBytes(32)
	msg, err := e.a.HostAuth(t.Context(), testOrigin, nonce)
	if err != nil {
		t.Fatal(err)
	}
	ha := msg.(hostAuthMsg)
	if ha.ClaimCommit == "" || ha.HostPub != b64(hostPub) || ha.Type != "host-auth" {
		t.Fatalf("host-auth %+v", ha)
	}
	if !proto.Verify(hostPub, unb64(t, ha.Sig), proto.LabelHostAuth, []byte(testOrigin), nonce) {
		t.Fatal("host-auth signature")
	}

	// claimed:false → setup URL with T and hostPub.
	st := e.host.lastState()
	prefix := testOrigin + "/#setup="
	if !strings.HasPrefix(st.SetupURL, prefix) {
		t.Fatalf("setupURL %q", st.SetupURL)
	}
	tB64, hpB64, ok := strings.Cut(strings.TrimPrefix(st.SetupURL, prefix), ".")
	if !ok || hpB64 != b64(hostPub) {
		t.Fatal("setupURL format")
	}
	T := unb64(t, tB64)
	kc, ka, _ := proto.SetupKeys(T)
	if ha.ClaimCommit != b64(proto.ClaimCommit(kc)) {
		t.Fatal("claimCommit != H(Kc(T))")
	}

	dev, _, _ := ed25519.GenerateKey(nil)
	// A MAC made with Kc (all the server knows) is rejected.
	bad := proto.SetupMAC(kc, hostPub, dev, "My iPhone", "browser")
	e.msg(map[string]any{"type": "setup-device", "devicePub": b64(dev), "name": "My iPhone", "kind": "browser", "setupMac": b64(bad)})
	e.srv.none(t, "device-approved", 100*time.Millisecond)
	// MAC over a different name (server tampering) is rejected.
	good := proto.SetupMAC(ka, hostPub, dev, "My iPhone", "browser")
	e.msg(map[string]any{"type": "setup-device", "devicePub": b64(dev), "name": "Server's choice", "kind": "browser", "setupMac": b64(good)})
	e.srv.none(t, "device-approved", 100*time.Millisecond)
	if !e.host.hasEvent("setup-failed") {
		t.Fatal("no setup-failed event")
	}

	e.msg(map[string]any{"type": "setup-device", "devicePub": b64(dev), "name": "My iPhone", "kind": "browser", "setupMac": b64(good)})
	da := e.srv.next(t, "device-approved", time.Second)
	cert, _ := jsonRoundTrip[proto.Cert](da["cert"])
	if err := cert.Verify(hostPub); err != nil || cert.DevicePub != b64(dev) {
		t.Fatalf("cert: %v", err)
	}
	st = e.host.lastState()
	if st.SetupURL != "" || len(st.Devices) != 1 || !st.Claimed {
		t.Fatalf("state after setup %+v", st)
	}
	// T is forgotten: a replay of the same setup-device does nothing.
	dev2, _, _ := ed25519.GenerateKey(nil)
	e.msg(map[string]any{"type": "setup-device", "devicePub": b64(dev2), "name": "x", "kind": "browser", "setupMac": b64(proto.SetupMAC(ka, hostPub, dev2, "x", "browser"))})
	e.srv.none(t, "device-approved", 100*time.Millisecond)
	msg, _ = e.a.HostAuth(t.Context(), testOrigin, nonce)
	if msg.(hostAuthMsg).ClaimCommit != "" {
		t.Fatal("claimCommit still sent after setup")
	}

	// new-setup-code generates a fresh T (owner action on the Mac).
	e.cmd(map[string]any{"cmd": "new-setup-code"})
	msg, _ = e.a.HostAuth(t.Context(), testOrigin, nonce)
	if c := msg.(hostAuthMsg).ClaimCommit; c == "" || c == ha.ClaimCommit {
		t.Fatal("new setup code not generated")
	}
}

func TestNoSetupWhenDevicesExist(t *testing.T) {
	e := newEnv(t, true)
	e.pin(t, "Phone", "browser")
	// Restart the agent on the same data dir: devices exist → no T.
	e.a.Stop()
	a2 := New(e.host, Options{NoSignaling: true, HomeDir: e.home, Now: e.clock.now})
	if err := a2.Start(t.Context(), Config{ServerURL: testOrigin, HostPub: b64(e.host.pub()), DataDir: e.dir,
		StorageKey: e.a.cfg.StorageKey}); err != nil {
		t.Fatal(err)
	}
	defer a2.Stop()
	msg, err := a2.HostAuth(t.Context(), testOrigin, randBytes(32))
	if err != nil || msg.(hostAuthMsg).ClaimCommit != "" {
		t.Fatalf("claimCommit with devices present: %v", err)
	}
}

func TestBadHostSignatureRejected(t *testing.T) {
	e := newEnv(t, true)
	e.host.mu.Lock()
	e.host.signBad = true
	e.host.mu.Unlock()
	if _, err := e.a.HostAuth(t.Context(), testOrigin, randBytes(32)); err == nil {
		t.Fatal("invalid SIGN_RESULT accepted")
	}
}

func TestTamperedTrustStoreRefusesEverything(t *testing.T) {
	e := newEnv(t, true)
	e.pin(t, "Phone", "browser")
	e.a.Stop()
	// Flip the killed flag without the key.
	p := e.dir + "/pins.json"
	b, _ := os.ReadFile(p)
	b = []byte(strings.Replace(string(b), `"killed":false`, `"killed":true`, 1))
	_ = os.WriteFile(p, b, 0o600)
	h := newFakeHost()
	h.priv = e.host.priv
	a2 := New(h, Options{NoSignaling: true, HomeDir: e.home})
	if err := a2.Start(t.Context(), Config{ServerURL: testOrigin, HostPub: b64(e.host.pub()), DataDir: e.dir, StorageKey: e.a.cfg.StorageKey}); err != nil {
		t.Fatal(err)
	}
	defer a2.Stop()
	waitFor(t, "tamper state", 2*time.Second, func() bool {
		return h.lastState().ServerError == "trust-store-tampered" && h.hasEvent("trust-store-tampered")
	})
	srv := newFakeSender()
	b2, _ := json.Marshal(map[string]any{"type": "host-ready", "claimed": true})
	a2.OnReady(srv, b2)
	m, _ := json.Marshal(map[string]any{"type": "session-request", "sessionId": b64(randBytes(16)), "devicePub": b64(randBytes(32)), "clientNonce": b64(randBytes(32))})
	a2.OnMessage("session-request", m)
	a2.call(func() {})
	srv.none(t, "session-accept", 100*time.Millisecond)
	// The file was not overwritten (evidence preserved).
	after, _ := os.ReadFile(p)
	if string(after) != string(b) {
		t.Fatal("tampered store overwritten")
	}
	// log-read reports unverified.
	c, _ := json.Marshal(map[string]any{"cmd": "log-read", "limit": 10})
	a2.OnCommand(c)
	a2.call(func() {})
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.logs) != 1 || h.logs[0].Verified {
		t.Fatalf("log-read %+v", h.logs)
	}
}
