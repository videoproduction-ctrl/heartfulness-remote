package core

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/videoproduction-ctrl/heartfulness-remote/agent/internal/trust"
	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
)

func TestDecideSession(t *testing.T) {
	browser := trust.Device{Pub: "A", Kind: "browser"}
	tauri := trust.Device{Pub: "B", Kind: "tauri"}
	activeA := &Session{dev: browser, state: sessConnected}
	cases := []struct {
		name         string
		killed       bool
		known        bool
		dev          trust.Device
		allowBrowser bool
		active       *Session
		reject       string
		replace      bool
	}{
		{"unpinned", false, false, browser, true, nil, RejectNotTrusted, false},
		{"killed", true, true, browser, true, nil, RejectBlocked, false},
		{"killed wins over unknown", true, false, browser, true, nil, RejectBlocked, false},
		{"browser disabled", false, true, browser, false, nil, RejectBrowserDisabled, false},
		{"native allowed when browsers disabled", false, true, tauri, false, nil, "", false},
		{"unknown kind treated as browser", false, true, trust.Device{Pub: "C", Kind: "phone"}, false, nil, RejectBrowserDisabled, false},
		{"busy", false, true, tauri, true, activeA, RejectBusy, false},
		{"same device replaces", false, true, browser, true, activeA, "", true},
		{"closed session ignored", false, true, tauri, true, &Session{dev: browser, state: sessClosed}, "", false},
	}
	for _, c := range cases {
		r, rep := decideSession(c.killed, c.known, c.dev, c.allowBrowser, c.active)
		if r != c.reject || rep != c.replace {
			t.Errorf("%s: got (%q,%v) want (%q,%v)", c.name, r, rep, c.reject, c.replace)
		}
	}
}

const sdpOne = "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=fingerprint:sha-256 AA:BB:CC\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=fingerprint:sha-256 aa:bb:cc\r\n"

func signedSession(t *testing.T) (*Session, ed25519.PrivateKey, []byte) {
	t.Helper()
	hostPub, _, _ := ed25519.GenerateKey(nil)
	dpub, dpriv, _ := ed25519.GenerateKey(nil)
	s := &Session{id: randBytes(16), devPub: dpub, clientNonce: randBytes(32), hostNonce: randBytes(32),
		acceptedAt: time.Now(), state: sessAccepted}
	return s, dpriv, hostPub
}

func signOffer(priv ed25519.PrivateKey, s *Session, hostPub []byte, sdp string) []byte {
	return proto.Sign(priv, proto.LabelOffer, s.id, hostPub, s.devPub, s.clientNonce, s.hostNonce, proto.Hash([]byte(sdp)))
}

func TestVerifyOffer(t *testing.T) {
	s, dpriv, hostPub := signedSession(t)
	now := time.Now()
	good := signOffer(dpriv, s, hostPub, sdpOne)
	if err := verifyOffer(s, s.devPub, hostPub, sdpOne, good, now); err != nil {
		t.Fatalf("valid offer: %v", err)
	}
	// Bad signature bytes.
	bad := append([]byte{}, good...)
	bad[10] ^= 1
	if err := verifyOffer(s, s.devPub, hostPub, sdpOne, bad, now); !errIs(err, errOfferSig) {
		t.Errorf("bad sig: %v", err)
	}
	// Signed by another device key (not the pinned one).
	_, other, _ := ed25519.GenerateKey(nil)
	if err := verifyOffer(s, s.devPub, hostPub, sdpOne, signOffer(other, s, hostPub, sdpOne), now); !errIs(err, errOfferSig) {
		t.Errorf("foreign key: %v", err)
	}
	// Signature bound to another session id / nonces / SDP / host.
	for name, mut := range map[string]func(c *Session) []byte{
		"session id":   func(c *Session) []byte { c.id = randBytes(16); return nil },
		"client nonce": func(c *Session) []byte { c.clientNonce = randBytes(32); return nil },
		"host nonce":   func(c *Session) []byte { c.hostNonce = randBytes(32); return nil },
		"host key":     func(c *Session) []byte { h, _, _ := ed25519.GenerateKey(nil); return h },
	} {
		c := &Session{id: s.id, devPub: s.devPub, clientNonce: s.clientNonce, hostNonce: s.hostNonce}
		hp := hostPub
		if h := mut(c); h != nil {
			hp = h
		}
		if err := verifyOffer(s, s.devPub, hostPub, sdpOne, signOffer(dpriv, c, hp, sdpOne), now); !errIs(err, errOfferSig) {
			t.Errorf("wrong %s: %v", name, err)
		}
	}
	other2 := strings.Replace(sdpOne, "s=-", "s=x", 1)
	if err := verifyOffer(s, s.devPub, hostPub, other2, good, now); !errIs(err, errOfferSig) {
		t.Errorf("modified SDP: %v", err)
	}
	// Stale.
	if err := verifyOffer(s, s.devPub, hostPub, sdpOne, good, s.acceptedAt.Add(OfferTimeout+time.Second)); !errIs(err, errOfferStale) {
		t.Errorf("stale: %v", err)
	}
	// Fingerprint rules.
	none := strings.ReplaceAll(sdpOne, "a=fingerprint:sha-256 AA:BB:CC\r\n", "")
	none = strings.ReplaceAll(none, "a=fingerprint:sha-256 aa:bb:cc\r\n", "")
	if err := verifyOffer(s, s.devPub, hostPub, none, signOffer(dpriv, s, hostPub, none), now); !errIs(err, errOfferFingerprint) {
		t.Errorf("no fingerprint: %v", err)
	}
	two := sdpOne + "a=fingerprint:sha-256 DD:EE:FF\r\n"
	if err := verifyOffer(s, s.devPub, hostPub, two, signOffer(dpriv, s, hostPub, two), now); !errIs(err, errOfferFingerprint) {
		t.Errorf("two fingerprints: %v", err)
	}
	sha1 := strings.Replace(sdpOne, "a=fingerprint:sha-256 AA:BB:CC", "a=fingerprint:sha-1 AA:BB:CC", 1)
	if err := verifyOffer(s, s.devPub, hostPub, sha1, signOffer(dpriv, s, hostPub, sha1), now); !errIs(err, errOfferFingerprint) {
		t.Errorf("sha-1 fingerprint: %v", err)
	}
	// Device revoked between accept and offer.
	if err := verifyOffer(s, nil, hostPub, sdpOne, good, now); !errIs(err, errOfferUntrusted) {
		t.Errorf("untrusted: %v", err)
	}
	// Replay.
	s.offerUsed = true
	if err := verifyOffer(s, s.devPub, hostPub, sdpOne, good, now); !errIs(err, errOfferReplay) {
		t.Errorf("replay: %v", err)
	}
}

func sessionRequest(e *testEnv, dev ed25519.PrivateKey) (sid, cn []byte) {
	sid, cn = randBytes(16), randBytes(32)
	e.msg(map[string]any{"type": "session-request", "sessionId": b64(sid), "devicePub": b64(pubOf(dev)), "clientNonce": b64(cn)})
	return
}

func TestSessionAcceptanceAgent(t *testing.T) {
	e := newEnv(t, true)
	a := e.pin(t, "Phone A", "browser")
	b := e.pin(t, "Laptop B", "tauri")
	_, unpinned, _ := ed25519.GenerateKey(nil)

	expectReject := func(dev ed25519.PrivateKey, reason string) {
		t.Helper()
		sid, _ := sessionRequest(e, dev)
		m := e.srv.next(t, "session-reject", time.Second)
		if m["reason"] != reason || m["sessionId"] != b64(sid) {
			t.Fatalf("want reject %q, got %v", reason, m["_raw"])
		}
	}
	expectReject(unpinned, RejectNotTrusted)

	// Browser clients disabled.
	e.cmd(map[string]any{"cmd": "settings", "settings": map[string]any{"allowBrowserClients": false}})
	expectReject(a, RejectBrowserDisabled)
	e.cmd(map[string]any{"cmd": "settings", "allowBrowserClients": true})

	// Killed.
	e.cmd(map[string]any{"cmd": "kill"})
	if !e.host.lastState().Killed || !e.host.hasEvent("killed") {
		t.Fatal("kill state")
	}
	expectReject(a, RejectBlocked)
	e.cmd(map[string]any{"cmd": "resume"})

	// Accepted.
	sid1, _ := sessionRequest(e, a)
	acc := e.srv.next(t, "session-accept", time.Second)
	if acc["sessionId"] != b64(sid1) || len(unb64(t, acc["hostNonce"])) != 32 {
		t.Fatalf("accept %v", acc["_raw"])
	}
	// Another device while A's session is pending → busy.
	expectReject(b, RejectBusy)
	// Same device again → old session replaced.
	sid2, _ := sessionRequest(e, a)
	end := e.srv.next(t, "session-end", time.Second)
	if end["sessionId"] != b64(sid1) || end["reason"] != "replaced" {
		t.Fatalf("replace %v", end["_raw"])
	}
	acc2 := e.srv.next(t, "session-accept", time.Second)
	if acc2["sessionId"] != b64(sid2) || acc2["hostNonce"] == acc["hostNonce"] {
		t.Fatal("second accept")
	}
	// Revoked device.
	e.cmd(map[string]any{"cmd": "revoke", "devicePub": b64(pubOf(a))})
	if m := e.srv.next(t, "session-end", time.Second); m["sessionId"] != b64(sid2) || m["reason"] != "revoked" {
		t.Fatalf("revoke should end the session: %v", m["_raw"])
	}
	expectReject(a, RejectNotTrusted)

	// Offer timeout: an accepted session without offer ends after 60 s.
	sid3, _ := sessionRequest(e, b)
	e.srv.next(t, "session-accept", time.Second)
	e.clock.add(OfferTimeout + time.Second)
	if m := e.srv.next(t, "session-end", 3*time.Second); m["sessionId"] != b64(sid3) || m["reason"] != "offer-timeout" {
		t.Fatalf("offer timeout %v", m["_raw"])
	}
}

func TestOfferRejectedAgent(t *testing.T) {
	e := newEnv(t, true)
	dev := e.pin(t, "Phone", "browser")
	_, other, _ := ed25519.GenerateKey(nil)
	hostPub := e.host.pub()

	sid, cn := sessionRequest(e, dev)
	hn := unb64(t, e.srv.next(t, "session-accept", time.Second)["hostNonce"])
	// Offer signed by a different key.
	sig := proto.Sign(other, proto.LabelOffer, sid, hostPub, pubOf(dev), cn, hn, proto.Hash([]byte(sdpOne)))
	e.msg(map[string]any{"type": "offer", "sessionId": b64(sid), "sdp": sdpOne, "sig": b64(sig)})
	if m := e.srv.next(t, "session-end", time.Second); m["reason"] != "offer-rejected" {
		t.Fatalf("got %v", m["_raw"])
	}
	e.srv.none(t, "answer", 100*time.Millisecond)

	// Offer for an unknown session id: ignored.
	e.msg(map[string]any{"type": "offer", "sessionId": b64(randBytes(16)), "sdp": sdpOne, "sig": b64(sig)})
	e.srv.none(t, "answer", 100*time.Millisecond)

	// Stale offer.
	sid, cn = sessionRequest(e, dev)
	hn = unb64(t, e.srv.next(t, "session-accept", time.Second)["hostNonce"])
	sig = proto.Sign(dev, proto.LabelOffer, sid, hostPub, pubOf(dev), cn, hn, proto.Hash([]byte(sdpOne)))
	e.a.call(func() { e.a.sess.acceptedAt = e.a.sess.acceptedAt.Add(-OfferTimeout - time.Second) })
	e.msg(map[string]any{"type": "offer", "sessionId": b64(sid), "sdp": sdpOne, "sig": b64(sig)})
	if m := e.srv.next(t, "session-end", time.Second); m["reason"] != "offer-rejected" {
		t.Fatalf("got %v", m["_raw"])
	}
	var entries int
	e.cmd(map[string]any{"cmd": "log-read", "limit": 0})
	e.host.mu.Lock()
	if l := e.host.logs[len(e.host.logs)-1]; l.Verified {
		if b, err := jsonRoundTrip[[]map[string]any](l.Entries); err == nil {
			entries = len(b)
		}
	} else {
		t.Errorf("log not verified: %s", l.Error)
	}
	e.host.mu.Unlock()
	if entries < 2 {
		t.Fatalf("offer rejections not logged (%d entries)", entries)
	}
}

func TestKillAndRevokeRequestsSigned(t *testing.T) {
	e := newEnv(t, true)
	phone := e.pin(t, "Phone", "browser")
	laptop := e.pin(t, "Laptop", "tauri")
	hostPub := e.host.pub()
	now := e.clock.now().Unix()

	killSig := func(k ed25519.PrivateKey, action string, ts int64) []byte {
		return proto.Sign(k, proto.LabelKillRequest, hostPub, proto.Str(action), proto.Int(ts))
	}
	// Stale timestamp: ignored.
	e.msg(map[string]any{"type": "kill-request", "action": "kill", "ts": now - 400, "approverPub": b64(pubOf(phone)), "sig": b64(killSig(phone, "kill", now-400))})
	if e.host.lastState().Killed {
		t.Fatal("stale kill accepted")
	}
	// Unpinned approver: ignored.
	_, rogue, _ := ed25519.GenerateKey(nil)
	e.msg(map[string]any{"type": "kill-request", "action": "kill", "ts": now, "approverPub": b64(pubOf(rogue)), "sig": b64(killSig(rogue, "kill", now))})
	if e.host.lastState().Killed {
		t.Fatal("unpinned kill accepted")
	}
	// Valid kill.
	e.msg(map[string]any{"type": "kill-request", "action": "kill", "ts": now, "approverPub": b64(pubOf(phone)), "sig": b64(killSig(phone, "kill", now))})
	if !e.host.lastState().Killed {
		t.Fatal("kill not applied")
	}
	for m := e.srv.next(t, "host-status", time.Second); m["state"] != "blocked"; m = e.srv.next(t, "host-status", time.Second) {
	}
	// Resume (string ts accepted too), then a replay of the kill is refused.
	e.msg(map[string]any{"type": "kill-request", "action": "resume", "ts": now + 1, "approverPub": b64(pubOf(laptop)), "sig": b64(killSig(laptop, "resume", now+1))})
	if e.host.lastState().Killed {
		t.Fatal("resume not applied")
	}
	e.msg(map[string]any{"type": "kill-request", "action": "kill", "ts": now, "approverPub": b64(pubOf(phone)), "sig": b64(killSig(phone, "kill", now))})
	if e.host.lastState().Killed {
		t.Fatal("replayed kill accepted")
	}
	// Revoke-request by a pinned device.
	revSig := proto.Sign(phone, proto.LabelRevokeRequest, hostPub, pubOf(laptop), proto.Int(now))
	e.msg(map[string]any{"type": "revoke-request", "targetPub": b64(pubOf(laptop)), "ts": now, "approverPub": b64(pubOf(phone)), "sig": b64(revSig)})
	m := e.srv.next(t, "device-revoked", time.Second)
	rev, _ := jsonRoundTrip[proto.Revocation](m["revocation"])
	if err := rev.Verify(hostPub); err != nil || rev.DevicePub != b64(pubOf(laptop)) {
		t.Fatalf("revocation: %v", err)
	}
	ts := e.srv.next(t, "trust-sync", time.Second)
	if revs, _ := ts["revocations"].([]any); len(revs) != 1 {
		t.Fatalf("trust-sync %v", ts["_raw"])
	}
	// The revoked device can no longer issue requests.
	sig := proto.Sign(laptop, proto.LabelRevokeRequest, hostPub, pubOf(phone), proto.Int(now))
	e.msg(map[string]any{"type": "revoke-request", "targetPub": b64(pubOf(phone)), "ts": now, "approverPub": b64(pubOf(laptop)), "sig": b64(sig)})
	e.srv.none(t, "device-revoked", 100*time.Millisecond)
	if len(e.host.lastState().Devices) != 1 {
		t.Fatal("device list")
	}
}
