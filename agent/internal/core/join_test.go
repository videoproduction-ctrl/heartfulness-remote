package core

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
)

// Multiple Macs per account (PROTOCOL.md §10).

var (
	joinCodeRe = regexp.MustCompile(`^[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}$`)
	macIDRe    = regexp.MustCompile(`^[0-9]{9}$`)
)

var pendingJoin = map[string]any{"claimed": true, "joined": false}

// joinSecret extracts T from STATE.joinURL and checks the URL and code format.
func joinSecret(t *testing.T, st State, hostPub []byte) []byte {
	t.Helper()
	prefix := testOrigin + "/#join="
	if !strings.HasPrefix(st.JoinURL, prefix) {
		t.Fatalf("joinURL %q", st.JoinURL)
	}
	tB64, hp, ok := strings.Cut(strings.TrimPrefix(st.JoinURL, prefix), ".")
	if !ok || hp != b64(hostPub) {
		t.Fatalf("joinURL format %q", st.JoinURL)
	}
	T := unb64(t, tB64)
	if len(T) != proto.JoinSecretSize {
		t.Fatalf("join T is %d bytes", len(T))
	}
	if !joinCodeRe.MatchString(st.JoinCode) || st.JoinCode != proto.JoinCode(T) {
		t.Fatalf("joinCode %q", st.JoinCode)
	}
	if back, err := proto.ParseJoinCode(strings.ToLower(st.JoinCode)); err != nil || string(back) != string(T) {
		t.Fatal("joinCode does not parse back to T")
	}
	return T
}

func setupDevice(dev []byte, name, kind string, mac []byte) map[string]any {
	return map[string]any{"type": "setup-device", "devicePub": b64(dev), "name": name, "kind": kind, "setupMac": b64(mac)}
}

func TestJoinFlow(t *testing.T) {
	// A brand-new Mac (no devices) first assumes an unclaimed server.
	e := newEnv(t, false)
	hostPub := e.host.pub()
	st := e.host.lastState()
	if st.MacID != proto.MacID(hostPub) || !macIDRe.MatchString(st.MacID) || st.Joined {
		t.Fatalf("state %+v", st)
	}
	before := e.reconnects()

	// The server is claimed and does not know this Mac: switch to a 10-byte
	// join T and reconnect so host-auth carries its commit.
	e.connect(pendingJoin)
	if e.reconnects() != before+1 {
		t.Fatal("no reconnect to send the join commit")
	}
	st = e.host.lastState()
	if st.JoinURL != "" || st.JoinCode != "" || st.SetupURL != "" {
		t.Fatalf("code shown before the server has its commit: %+v", st)
	}
	ha := e.connect(pendingJoin)
	if e.reconnects() != before+1 {
		t.Fatal("reconnected again although the commit was sent")
	}
	st = e.host.lastState()
	if !st.Claimed || st.Joined || st.SetupURL != "" || st.MacID != proto.MacID(hostPub) {
		t.Fatalf("pending join state %+v", st)
	}
	T := joinSecret(t, st, hostPub)
	kc, ka, _ := proto.SetupKeys(T)
	if ha.ClaimCommit != b64(proto.ClaimCommit(kc)) {
		t.Fatal("claimCommit != H(Kc(join T))")
	}
	// A pending join host sends neither trust-sync nor host-status.
	for {
		select {
		case m := <-e.srv.ch:
			if m["type"] == "trust-sync" || m["type"] == "host-status" {
				t.Fatalf("%v sent while not in the account", m["type"])
			}
			continue
		default:
		}
		break
	}

	dev, _, _ := ed25519.GenerateKey(nil)
	// The server only knows Kc: a MAC made with it is refused.
	e.msg(setupDevice(dev, "My iPhone", "browser", proto.SetupMAC(kc, hostPub, dev, "My iPhone", "browser")))
	e.srv.none(t, "device-approved", 100*time.Millisecond)
	// Messages routed to another Mac are ignored, even with a valid MAC.
	other, _, _ := ed25519.GenerateKey(nil)
	good := setupDevice(dev, "My iPhone", "browser", proto.SetupMAC(ka, hostPub, dev, "My iPhone", "browser"))
	wrong := map[string]any{"hostPub": b64(other)}
	for k, v := range good {
		wrong[k] = v
	}
	e.msg(wrong)
	e.srv.none(t, "device-approved", 100*time.Millisecond)

	// The real MAC (with our hostPub, as the HR1.1 server routes it).
	good["hostPub"] = b64(hostPub)
	e.msg(good)
	da := e.srv.next(t, "device-approved", time.Second)
	cert, _ := jsonRoundTrip[proto.Cert](da["cert"])
	if err := cert.Verify(hostPub); err != nil || cert.DevicePub != b64(dev) || cert.Name != "My iPhone" {
		t.Fatalf("cert: %v", err)
	}
	if !proto.CheckHostConfirmMAC(ka, hostPub, dev, unb64(t, da["hostMac"])) {
		t.Fatal("hostMac does not verify with Ka")
	}
	// Now in the account: trust-sync and host-status follow; codes are gone.
	e.srv.next(t, "trust-sync", time.Second)
	e.srv.next(t, "host-status", time.Second)
	st = e.host.lastState()
	if !st.Joined || !st.Claimed || st.JoinURL != "" || st.JoinCode != "" || len(st.Devices) != 1 {
		t.Fatalf("state after join %+v", st)
	}
	if !e.host.hasEvent("joined-account") || !e.host.hasEvent("device-added") {
		t.Fatal("join events missing")
	}
	// T is forgotten: a replay does nothing and host-auth has no commit.
	dev2, _, _ := ed25519.GenerateKey(nil)
	e.msg(setupDevice(dev2, "x", "browser", proto.SetupMAC(ka, hostPub, dev2, "x", "browser")))
	e.srv.none(t, "device-approved", 100*time.Millisecond)
	if ha := e.connect(map[string]any{"claimed": true, "joined": true}); ha.ClaimCommit != "" {
		t.Fatal("claimCommit still sent after joining")
	}
	if e.reconnects() != before+1 {
		t.Fatal("unexpected reconnect after joining")
	}

	// The access log records the join.
	e.cmd(map[string]any{"cmd": "log-read", "limit": 50})
	e.host.mu.Lock()
	raw, _ := json.Marshal(e.host.logs[len(e.host.logs)-1])
	e.host.mu.Unlock()
	if !strings.Contains(string(raw), `"event":"joined-account"`) {
		t.Fatalf("log: %s", raw)
	}
	if strings.Contains(string(raw), b64(T)) {
		t.Fatal("join secret written to the access log")
	}
}

// The host confirmation matches the cross-language vectors (testdata/vectors.json "join").
func TestJoinMatchesVectors(t *testing.T) {
	b, err := os.ReadFile("../../../testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v proto.VectorSet
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(v.HostSeed)
	host := newFakeHost()
	host.priv = ed25519.NewKeyFromSeed(seed)
	if b64(host.pub()) != v.HostPub {
		t.Fatal("vector host key")
	}
	e := newEnvHost(t, host, true)
	T := unb64(t, v.Join.T)
	if len(T) != proto.JoinSecretSize {
		t.Fatal("vector T size")
	}
	// Put the vector's T in place of a random one (same as newSecret).
	e.a.call(func() {
		kc, ka, _ := proto.SetupKeys(T)
		e.a.setupT, e.a.setupKa, e.a.setupCommit = append([]byte(nil), T...), ka, b64(proto.ClaimCommit(kc))
	})
	ha := e.connect(pendingJoin)
	if ha.ClaimCommit != v.Join.ClaimCommit {
		t.Fatalf("claimCommit %s, vector %s", ha.ClaimCommit, v.Join.ClaimCommit)
	}
	st := e.host.lastState()
	if st.MacID != v.Join.MacID || st.JoinCode != v.Join.Code || st.JoinURL != testOrigin+"/#join="+v.Join.T+"."+v.HostPub {
		t.Fatalf("state %+v vs vectors %+v", st, v.Join)
	}
	dev := unb64(t, v.DevicePub)
	e.msg(map[string]any{"type": "setup-device", "hostPub": v.HostPub, "devicePub": v.DevicePub,
		"name": v.Setup.Name, "kind": v.Setup.Kind, "setupMac": v.Join.SetupMAC})
	da := e.srv.next(t, "device-approved", time.Second)
	if da["hostMac"] != v.Join.HostMAC {
		t.Fatalf("hostMac %v, vector %s", da["hostMac"], v.Join.HostMAC)
	}
	if !proto.CheckHostConfirmMAC(unb64(t, v.Join.Ka), host.pub(), dev, unb64(t, da["hostMac"])) {
		t.Fatal("hostMac does not verify with the vector Ka")
	}
}

func TestRemovedFromAccountShowsNewCode(t *testing.T) {
	e := newEnv(t, true)
	e.pin(t, "Phone", "browser")
	hostPub := e.host.pub()
	if st := e.host.lastState(); !st.Joined || st.JoinCode != "" {
		t.Fatalf("joined state %+v", st)
	}
	var codes []string
	for round := range 2 {
		before := e.reconnects()
		e.msg(map[string]any{"type": "error", "code": "removed"})
		if e.reconnects() != before+1 {
			t.Fatal("no reconnect after removal")
		}
		st := e.host.lastState()
		if st.Joined || !st.Claimed || len(st.Devices) == 0 {
			t.Fatalf("round %d: state after removal %+v", round, st)
		}
		// The server closes the socket; on reconnect the Mac is a pending join host.
		ha := e.connect(pendingJoin)
		if e.reconnects() != before+1 {
			t.Fatal("extra reconnect")
		}
		st = e.host.lastState()
		T := joinSecret(t, st, hostPub)
		kc, ka, _ := proto.SetupKeys(T)
		if ha.ClaimCommit != b64(proto.ClaimCommit(kc)) {
			t.Fatal("claimCommit is not for the new join code")
		}
		for _, c := range codes {
			if c == st.JoinCode {
				t.Fatal("join code reused after removal")
			}
		}
		codes = append(codes, st.JoinCode)
		// Join again from an approved device.
		dev, _, _ := ed25519.GenerateKey(nil)
		e.msg(setupDevice(dev, "Laptop", "tauri", proto.SetupMAC(ka, hostPub, dev, "Laptop", "tauri")))
		da := e.srv.next(t, "device-approved", time.Second)
		if !proto.CheckHostConfirmMAC(ka, hostPub, dev, unb64(t, da["hostMac"])) {
			t.Fatal("hostMac")
		}
		if st := e.host.lastState(); !st.Joined || st.JoinCode != "" {
			t.Fatalf("state after re-join %+v", st)
		}
	}
	if !e.host.hasEvent("removed-from-account") {
		t.Fatal("no removed-from-account event")
	}
}

func TestClaimFlowStillUses32ByteSecret(t *testing.T) {
	e := newEnv(t, false)
	hostPub := e.host.pub()
	if e.reconnects() != 0 {
		t.Fatal("reconnect on a normal first claim")
	}
	st := e.host.lastState()
	if st.JoinURL != "" || st.JoinCode != "" || st.Claimed || st.Joined {
		t.Fatalf("unclaimed state %+v", st)
	}
	tB64, _, _ := strings.Cut(strings.TrimPrefix(st.SetupURL, testOrigin+"/#setup="), ".")
	T := unb64(t, tB64)
	if len(T) != 32 {
		t.Fatalf("setup T is %d bytes", len(T))
	}
	_, ka, _ := proto.SetupKeys(T)
	// The server reports the claim (in band, before setup-device, §4) — the
	// pre-HR1.1 form without "joined", then the HR1.1 form. T must survive.
	e.msg(map[string]any{"type": "host-ready", "claimed": true})
	e.srv.next(t, "trust-sync", time.Second)
	e.srv.next(t, "host-status", time.Second)
	e.msg(map[string]any{"type": "host-ready", "claimed": true, "joined": true, "macId": proto.MacID(hostPub)})
	if st := e.host.lastState(); st.SetupURL != "" || st.JoinURL != "" || !st.Joined {
		t.Fatalf("state after claim %+v", st)
	}
	dev, _, _ := ed25519.GenerateKey(nil)
	e.msg(setupDevice(dev, "My iPhone", "browser", proto.SetupMAC(ka, hostPub, dev, "My iPhone", "browser")))
	da := e.srv.next(t, "device-approved", time.Second)
	if !proto.CheckHostConfirmMAC(ka, hostPub, dev, unb64(t, da["hostMac"])) {
		t.Fatal("claim device-approved without a valid hostMac")
	}
	if e.host.hasEvent("joined-account") {
		t.Fatal("a first claim is not a join")
	}
	if e.reconnects() != 0 {
		t.Fatal("unexpected reconnect")
	}
}

func TestUnclaimedServerAfterResetGetsSetupCode(t *testing.T) {
	// A Mac with devices (no T) meets an unclaimed server (e.g. after
	// "heartfulness-server reset"): it makes a setup code by itself.
	e := newEnv(t, true)
	e.pin(t, "Phone", "browser")
	e.a.call(e.a.forgetSetupSecret)
	before := e.reconnects()
	e.connect(map[string]any{"claimed": false})
	if e.reconnects() != before+1 {
		t.Fatal("no reconnect for the new setup commit")
	}
	e.connect(map[string]any{"claimed": false})
	st := e.host.lastState()
	if !strings.HasPrefix(st.SetupURL, testOrigin+"/#setup=") || st.JoinURL != "" || st.Joined {
		t.Fatalf("state %+v", st)
	}
}

func TestNewSetupCodeWhilePendingJoin(t *testing.T) {
	e := newEnv(t, true)
	e.connect(pendingJoin)
	e.connect(pendingJoin)
	first := e.host.lastState().JoinCode
	if first == "" {
		t.Fatal("no join code")
	}
	before := e.reconnects()
	e.cmd(map[string]any{"cmd": "new-setup-code"})
	if e.reconnects() != before+1 {
		t.Fatal("new-setup-code did not reconnect")
	}
	if st := e.host.lastState(); st.JoinCode != "" {
		t.Fatal("new code shown before the server has its commit")
	}
	e.connect(pendingJoin)
	st := e.host.lastState()
	joinSecret(t, st, e.host.pub())
	if st.JoinCode == first {
		t.Fatal("same join code")
	}
}

func TestHostsChangedJoined(t *testing.T) {
	e := newEnv(t, true)
	e.connect(pendingJoin)
	e.connect(pendingJoin)
	if e.host.lastState().JoinCode == "" {
		t.Fatal("no join code")
	}
	e.msg(map[string]any{"type": "hosts-changed"}) // no membership info: ignored
	if e.host.lastState().JoinCode == "" {
		t.Fatal("hosts-changed without joined cleared the code")
	}
	e.msg(map[string]any{"type": "hosts-changed", "joined": true})
	st := e.host.lastState()
	if !st.Joined || st.JoinCode != "" || st.JoinURL != "" {
		t.Fatalf("state %+v", st)
	}
	e.srv.next(t, "trust-sync", time.Second)
}

func TestRoutedMessagesForAnotherMacIgnored(t *testing.T) {
	e := newEnv(t, true)
	other, _, _ := ed25519.GenerateKey(nil)
	id, _, _, commit := newReq(t)
	req := map[string]any{"type": "pair-request", "requestId": b64(id), "name": "Laptop", "kind": "tauri", "commit": b64(commit)}
	req["hostPub"] = b64(other)
	e.msg(req)
	e.srv.none(t, "pair-challenge", 100*time.Millisecond)
	req["hostPub"] = b64(e.host.pub())
	e.msg(req)
	if pc := e.srv.next(t, "pair-challenge", time.Second); pc["hostPub"] != b64(e.host.pub()) {
		t.Fatalf("pair-challenge %v", pc["_raw"])
	}
	// Without hostPub (pre-HR1.1 server) messages are still accepted.
	id2, _, _, commit2 := newReq(t)
	e.msg(map[string]any{"type": "pair-request", "requestId": b64(id2), "name": "Phone", "kind": "browser", "commit": b64(commit2)})
	e.srv.next(t, "pair-challenge", time.Second)
}
