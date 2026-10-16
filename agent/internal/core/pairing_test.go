package core

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/videoproduction-ctrl/heartfulness-remote/agent/internal/trust"
	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
)

func newReq(t *testing.T) (id, devPub, nd, commit []byte) {
	t.Helper()
	id = randBytes(16)
	devPub, _, _ = ed25519.GenerateKey(nil)
	nd = randBytes(32)
	return id, devPub, nd, proto.PairCommit(devPub, nd)
}

func TestPairingCommitAndSAS(t *testing.T) {
	hostPub, _, _ := ed25519.GenerateKey(nil)
	p := NewPairing(nil, 0)
	now := time.Now()
	id, dp, nd, commit := newReq(t)
	r, reason := p.Request(id, "Owner's iPhone", "browser", commit, now)
	if r == nil {
		t.Fatal(reason)
	}
	if len(r.NA) != 32 {
		t.Fatal("na")
	}
	// A second request gets an independent na.
	id2, _, _, commit2 := newReq(t)
	r2, _ := p.Request(id2, "Laptop", "tauri", commit2, now)
	if string(r2.NA) == string(r.NA) {
		t.Fatal("na reused")
	}
	// Reveal with the wrong nd = commitment mismatch, request removed.
	if _, reason := p.Reveal(r2.IDB64, dp, nd, hostPub, now); reason != ReasonCommitMismatch {
		t.Fatalf("mismatch: %q", reason)
	}
	if _, ok := p.Pending(r2.IDB64); ok {
		t.Fatal("mismatched request kept")
	}
	// Correct reveal.
	r, reason = p.Reveal(r.IDB64, dp, nd, hostPub, now)
	if reason != "" {
		t.Fatal(reason)
	}
	if r.SAS != proto.SAS(hostPub, dp, nd, r.NA) || len(r.SAS) != 6 {
		t.Fatalf("SAS %q", r.SAS)
	}
	// Duplicate reveal is ignored (request stays).
	if _, reason := p.Reveal(r.IDB64, dp, nd, hostPub, now); reason != ReasonInvalid {
		t.Fatal("duplicate reveal")
	}
	if _, ok := p.Pending(r.IDB64); !ok {
		t.Fatal("request dropped by duplicate reveal")
	}
}

func TestPairingValidation(t *testing.T) {
	p := NewPairing(nil, 0)
	now := time.Now()
	id, _, _, commit := newReq(t)
	for name, f := range map[string]func() (*PairReq, string){
		"short id":     func() (*PairReq, string) { return p.Request(id[:8], "n", "browser", commit, now) },
		"short commit": func() (*PairReq, string) { return p.Request(id, "n", "browser", commit[:31], now) },
		"empty name":   func() (*PairReq, string) { return p.Request(id, "", "browser", commit, now) },
		"ctl name":     func() (*PairReq, string) { return p.Request(id, "a\nb", "browser", commit, now) },
		"bidi name":    func() (*PairReq, string) { return p.Request(id, "abc‮def", "browser", commit, now) },
		"bad kind":     func() (*PairReq, string) { return p.Request(id, "n", "Browser!", commit, now) },
		"long name": func() (*PairReq, string) {
			return p.Request(id, "0123456789012345678901234567890123456789012345678901234567890123x", "browser", commit, now)
		},
	} {
		if r, reason := f(); r != nil || reason != ReasonInvalid {
			t.Errorf("%s: accepted (%q)", name, reason)
		}
	}
	if r, _ := p.Request(id, "n", "browser", commit, now); r == nil {
		t.Fatal("valid request refused")
	}
	if r, reason := p.Request(id, "n", "browser", commit, now); r != nil || reason != ReasonInvalid {
		t.Fatal("duplicate id accepted")
	}
}

func TestPairingExpiry(t *testing.T) {
	hostPub, _, _ := ed25519.GenerateKey(nil)
	p := NewPairing(nil, 0)
	t0 := time.Now()
	id, dp, nd, commit := newReq(t)
	r, _ := p.Request(id, "Phone", "browser", commit, t0)
	if _, reason := p.Reveal(r.IDB64, dp, nd, hostPub, t0.Add(PairTTL)); reason != ReasonExpired {
		t.Fatalf("expired reveal: %q", reason)
	}
	// Expire() reports revealed-but-unapproved requests too.
	id2, dp2, nd2, commit2 := newReq(t)
	r2, _ := p.Request(id2, "Phone", "browser", commit2, t0)
	_, _ = p.Reveal(r2.IDB64, dp2, nd2, hostPub, t0.Add(time.Minute))
	if got := p.Expire(t0.Add(PairTTL - time.Second)); len(got) != 0 {
		t.Fatal("expired early")
	}
	if got := p.Expire(t0.Add(PairTTL)); len(got) != 1 || got[0].IDB64 != r2.IDB64 {
		t.Fatalf("expire: %v", got)
	}
}

func TestPairingLimits(t *testing.T) {
	p := NewPairing(nil, 0)
	now := time.Now()
	for i := range MaxPendingPairs {
		id, _, _, c := newReq(t)
		if r, reason := p.Request(id, "D", "browser", c, now); r == nil {
			t.Fatalf("request %d: %s", i, reason)
		}
	}
	id, _, _, c := newReq(t)
	if _, reason := p.Request(id, "D", "browser", c, now); reason != ReasonTooMany {
		t.Fatalf("4th pending: %q", reason)
	}
	// Once they expire there is room again.
	if r, _ := p.Request(id, "D", "browser", c, now.Add(PairTTL)); r == nil {
		t.Fatal("room after expiry")
	}

	// 5 denials within an hour → auto-deny for 1 hour.
	q := NewPairing(nil, 0)
	t0 := time.Now()
	for i := range DenyLimit - 1 {
		if q.RecordDenial(t0.Add(time.Duration(i) * time.Minute)) {
			t.Fatal("triggered early")
		}
	}
	if !q.RecordDenial(t0.Add(10 * time.Minute)) {
		t.Fatal("5th denial did not trigger auto-deny")
	}
	id, _, _, c = newReq(t)
	if _, reason := q.Request(id, "D", "browser", c, t0.Add(30*time.Minute)); reason != ReasonRateLimited {
		t.Fatalf("auto-deny: %q", reason)
	}
	if r, _ := q.Request(id, "D", "browser", c, t0.Add(10*time.Minute+AutoDenyFor)); r == nil {
		t.Fatal("auto-deny did not lift after 1 h")
	}
	// Denials spread over more than an hour do not trigger.
	w := NewPairing(nil, 0)
	for i := range 10 {
		if w.RecordDenial(t0.Add(time.Duration(i) * 20 * time.Minute)) {
			t.Fatal("slow denials triggered auto-deny")
		}
	}
}

func TestVerifyApproval(t *testing.T) {
	hostPub, _, _ := ed25519.GenerateKey(nil)
	apPub, apPriv, _ := ed25519.GenerateKey(nil)
	p := NewPairing(nil, 0)
	now := time.Now()
	id, dp, nd, commit := newReq(t)
	r, _ := p.Request(id, "Phone", "browser", commit, now)
	if r.VerifyApproval(hostPub, apPub, make([]byte, 64)) {
		t.Fatal("approval before reveal")
	}
	r, _ = p.Reveal(r.IDB64, dp, nd, hostPub, now)
	sign := func(name string) []byte {
		return proto.Sign(apPriv, proto.LabelPairApprove, r.ID, hostPub, dp, nd, r.NA, proto.Str(name), proto.Str("browser"))
	}
	if !r.VerifyApproval(hostPub, apPub, sign("Phone")) {
		t.Fatal("valid approval rejected")
	}
	if r.VerifyApproval(hostPub, apPub, sign("Other name")) {
		t.Fatal("approval for a different name accepted")
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if r.VerifyApproval(hostPub, other, sign("Phone")) {
		t.Fatal("approval verified with the wrong key")
	}
}

// Full pairing over the (fake) signaling path.
func TestPairingFlowAgent(t *testing.T) {
	e := newEnv(t, true)
	approver := e.pin(t, "Owner's iPhone", "browser")
	hostPub := e.host.pub()

	devPub, _, _ := ed25519.GenerateKey(nil)
	nd := randBytes(32)
	reqID := randBytes(16)
	e.msg(map[string]any{"type": "pair-request", "requestId": b64(reqID), "devicePub": "", "name": "Studio PC", "kind": "tauri", "commit": b64(proto.PairCommit(devPub, nd))})
	ch := e.srv.next(t, "pair-challenge", 2*time.Second)
	na := unb64(t, ch["na"])
	if ch["hostPub"] != b64(hostPub) || !proto.Verify(hostPub, unb64(t, ch["sig"]), proto.LabelPairChallenge, reqID, proto.PairCommit(devPub, nd), na, hostPub) {
		t.Fatal("pair-challenge signature invalid")
	}
	e.msg(map[string]any{"type": "pair-reveal", "requestId": b64(reqID), "devicePub": b64(devPub), "nd": b64(nd)})
	st := e.host.lastState()
	if len(st.Pending) != 1 || st.Pending[0].SAS != proto.FormatSAS(proto.SAS(hostPub, devPub, nd, na)) {
		t.Fatalf("pending %+v", st.Pending)
	}
	if !e.host.hasEvent("pair-request") {
		t.Fatal("no pair-request event")
	}

	// Approval signed by an unpinned key is ignored.
	_, rogue, _ := ed25519.GenerateKey(nil)
	sig := proto.Sign(rogue, proto.LabelPairApprove, reqID, hostPub, devPub, nd, na, proto.Str("Studio PC"), proto.Str("tauri"))
	e.msg(map[string]any{"type": "pair-approve", "requestId": b64(reqID), "approverPub": b64(pubOf(rogue)), "sig": b64(sig)})
	e.srv.none(t, "pair-result", 100*time.Millisecond)
	// Approval by the pinned key but over a different name is ignored.
	sig = proto.Sign(approver, proto.LabelPairApprove, reqID, hostPub, devPub, nd, na, proto.Str("Other"), proto.Str("tauri"))
	e.msg(map[string]any{"type": "pair-approve", "requestId": b64(reqID), "approverPub": b64(pubOf(approver)), "sig": b64(sig)})
	e.srv.none(t, "pair-result", 100*time.Millisecond)

	// Valid approval by the pinned device.
	sig = proto.Sign(approver, proto.LabelPairApprove, reqID, hostPub, devPub, nd, na, proto.Str("Studio PC"), proto.Str("tauri"))
	e.msg(map[string]any{"type": "pair-approve", "requestId": b64(reqID), "approverPub": b64(pubOf(approver)), "sig": b64(sig)})
	res := e.srv.next(t, "pair-result", 2*time.Second)
	if res["approved"] != true {
		t.Fatalf("pair-result %v", res["_raw"])
	}
	cb, _ := jsonRoundTrip[proto.Cert](res["cert"])
	if err := cb.Verify(hostPub); err != nil || cb.DevicePub != b64(devPub) || cb.Name != "Studio PC" || cb.Kind != "tauri" {
		t.Fatalf("cert %+v %v", cb, err)
	}
	ts := e.srv.next(t, "trust-sync", time.Second)
	if certs, _ := ts["certs"].([]any); len(certs) != 2 {
		t.Fatalf("trust-sync certs %v", ts["_raw"])
	}
	var d trust.Device
	var ok bool
	e.a.call(func() { d, ok = e.a.store.Device(b64(devPub)) })
	if !ok || d.Kind != "tauri" {
		t.Fatal("device not pinned")
	}
	if len(e.host.lastState().Pending) != 0 || len(e.host.lastState().Devices) != 2 {
		t.Fatal("state not updated")
	}
}

func TestPairingRevokedApproverAndLocalApproveDeny(t *testing.T) {
	e := newEnv(t, true)
	approver := e.pin(t, "Old phone", "browser")
	hostPub := e.host.pub()
	e.cmd(map[string]any{"cmd": "revoke", "devicePub": b64(pubOf(approver))})
	e.srv.next(t, "device-revoked", time.Second)

	start := func(name string) (reqID, devPub, nd, na []byte) {
		devPub, _, _ = ed25519.GenerateKey(nil)
		nd, reqID = randBytes(32), randBytes(16)
		e.msg(map[string]any{"type": "pair-request", "requestId": b64(reqID), "name": name, "kind": "browser", "commit": b64(proto.PairCommit(devPub, nd))})
		na = unb64(t, e.srv.next(t, "pair-challenge", time.Second)["na"])
		e.msg(map[string]any{"type": "pair-reveal", "requestId": b64(reqID), "devicePub": b64(devPub), "nd": b64(nd)})
		return
	}
	reqID, devPub, nd, na := start("New phone")
	sig := proto.Sign(approver, proto.LabelPairApprove, reqID, hostPub, devPub, nd, na, proto.Str("New phone"), proto.Str("browser"))
	e.msg(map[string]any{"type": "pair-approve", "requestId": b64(reqID), "approverPub": b64(pubOf(approver)), "sig": b64(sig)})
	e.srv.none(t, "pair-result", 100*time.Millisecond)

	// The owner approves on the Mac instead.
	e.cmd(map[string]any{"cmd": "approve", "requestId": b64(reqID)})
	if r := e.srv.next(t, "pair-result", time.Second); r["approved"] != true {
		t.Fatal("local approve failed")
	}
	// Deny path + denial counter persisted.
	reqID2, _, _, _ := start("Intruder")
	e.cmd(map[string]any{"cmd": "deny", "requestId": b64(reqID2)})
	r := e.srv.next(t, "pair-result", time.Second)
	if r["approved"] != false || r["reason"] != ReasonDenied {
		t.Fatalf("deny: %v", r["_raw"])
	}
	var denials int
	e.a.call(func() { denials = len(e.a.store.Snapshot().Denials) })
	if denials != 1 {
		t.Fatalf("denials persisted: %d", denials)
	}
	// A revoked key cannot re-pair.
	e.msg(map[string]any{"type": "pair-request", "requestId": b64(randBytes(16)), "name": "Old", "kind": "browser", "commit": b64(proto.PairCommit(pubOf(approver), nd))})
	ch := e.srv.next(t, "pair-challenge", time.Second)
	e.msg(map[string]any{"type": "pair-reveal", "requestId": ch["requestId"], "devicePub": b64(pubOf(approver)), "nd": b64(nd)})
	if r := e.srv.next(t, "pair-result", time.Second); r["reason"] != ReasonRevoked {
		t.Fatalf("revoked re-pair: %v", r["_raw"])
	}
}

func TestPairingCommitMismatchAgentAndExpiry(t *testing.T) {
	e := newEnv(t, true)
	devPub, _, _ := ed25519.GenerateKey(nil)
	nd := randBytes(32)
	reqID := randBytes(16)
	e.msg(map[string]any{"type": "pair-request", "requestId": b64(reqID), "name": "X", "kind": "browser", "commit": b64(proto.PairCommit(devPub, nd))})
	e.srv.next(t, "pair-challenge", time.Second)
	// Server substitutes a different key at reveal time.
	evil, _, _ := ed25519.GenerateKey(nil)
	e.msg(map[string]any{"type": "pair-reveal", "requestId": b64(reqID), "devicePub": b64(evil), "nd": b64(nd)})
	if r := e.srv.next(t, "pair-result", time.Second); r["reason"] != ReasonCommitMismatch {
		t.Fatalf("got %v", r["_raw"])
	}
	// Expiry is reported by the loop tick.
	reqID2 := randBytes(16)
	e.msg(map[string]any{"type": "pair-request", "requestId": b64(reqID2), "name": "Y", "kind": "browser", "commit": b64(proto.PairCommit(devPub, nd))})
	e.srv.next(t, "pair-challenge", time.Second)
	e.clock.add(PairTTL + time.Second)
	if r := e.srv.next(t, "pair-result", 3*time.Second); r["reason"] != ReasonExpired || r["requestId"] != b64(reqID2) {
		t.Fatalf("got %v", r["_raw"])
	}
	// Killed host refuses pairing.
	e.cmd(map[string]any{"cmd": "kill"})
	e.msg(map[string]any{"type": "pair-request", "requestId": b64(randBytes(16)), "name": "Z", "kind": "browser", "commit": b64(proto.PairCommit(devPub, nd))})
	if r := e.srv.next(t, "pair-result", time.Second); r["reason"] != ReasonUnavailable {
		t.Fatalf("got %v", r["_raw"])
	}
}
