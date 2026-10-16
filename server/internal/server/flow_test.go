package server

import (
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
	"github.com/videoproduction-ctrl/heartfulness-remote/server/internal/config"
	"github.com/videoproduction-ctrl/heartfulness-remote/server/internal/store"
)

// status is a device's approval status on one Mac.
func (e *testEnv) status(pub, hostPub string) string {
	var s string
	e.st.View(func(st *store.State) { s = st.ApprovalStatus(pub, hostPub) })
	return s
}

func (e *testEnv) failures(ip string) int {
	return e.srv.lim.failures(ip, e.srv.now())
}

// ---- host authentication ----

func TestHostAuth(t *testing.T) {
	e := newEnv(t, nil)

	good := newFakeHost(t)
	r := good.connect(e, "203.0.113.1", testOrigin, true)
	if r["type"] != "host-ready" || r["claimed"] != false || r["joined"] != false || r["origin"] != testOrigin || r["macId"] != proto.MacID(good.pub) {
		t.Fatalf("good host: %v", r)
	}
	// TURN credentials only go to Macs bound to the owner (any key may wait).
	if ice := r["iceServers"].([]any); len(ice) != 0 {
		t.Fatalf("unbound host got iceServers: %v", ice)
	}

	// Signature by another key.
	bad := newFakeHost(t)
	other := newFakeHost(t)
	bad.priv = other.priv
	if r := bad.connect(e, "203.0.113.2", testOrigin, true); r["type"] != "error" || r["code"] != "bad-signature" {
		t.Fatalf("bad sig: %v", r)
	}
	bad.expectClosed()

	// Valid key, but the transcript names a different origin.
	wrongOrigin := newFakeHost(t)
	if r := wrongOrigin.connect(e, "203.0.113.3", "https://evil.example", true); r["type"] != "error" || r["code"] != "bad-signature" {
		t.Fatalf("wrong origin: %v", r)
	}
	wrongOrigin.expectClosed()
	if e.failures("203.0.113.2") != 1 || e.failures("203.0.113.3") != 1 {
		t.Fatal("bad host signatures must count as auth failures")
	}

	// Unclaimed hosts: at most 2 pending per IP and 5 in total.
	if r := newFakeHost(t).connect(e, "203.0.113.1", testOrigin, true); r["type"] != "host-ready" {
		t.Fatalf("second pending host from one IP: %v", r)
	}
	if r := newFakeHost(t).connect(e, "203.0.113.1", testOrigin, true); r["code"] != "too-many-pending" {
		t.Fatalf("third pending host from one IP: %v", r)
	}
	for i := 0; i < 3; i++ {
		if r := newFakeHost(t).connect(e, "203.0.113.2"+string(rune('0'+i)), testOrigin, true); r["type"] != "host-ready" {
			t.Fatalf("pending host %d: %v", i, r)
		}
	}
	if r := newFakeHost(t).connect(e, "203.0.113.99", testOrigin, true); r["code"] != "too-many-pending" {
		t.Fatalf("sixth pending host: %v", r)
	}
	// The same key reconnecting replaces its old pending connection.
	if r := good.connect(e, "203.0.113.1", testOrigin, true); r["type"] != "host-ready" {
		t.Fatalf("pending host reconnect: %v", r)
	}

	// Browsers from foreign origins cannot even open the socket.
	if _, res, err := e.dial("/ws/host", http.Header{"Origin": {"https://evil.example"}, "X-Forwarded-For": {"203.0.113.4"}}); err == nil || res.StatusCode != http.StatusForbidden {
		t.Fatal("foreign-origin host socket accepted")
	}
}

func TestHostAuthPinnedKey(t *testing.T) {
	pinned := newFakeHost(t)
	e := newEnv(t, map[string]string{"HR_HOST_PUBKEY": pinned.pubB64})
	intruder := newFakeHost(t)
	if r := intruder.connect(e, "203.0.113.9", testOrigin, true); r["code"] != "host-not-allowed" {
		t.Fatalf("unpinned host: %v", r)
	}
	if r := pinned.connect(e, "203.0.113.1", testOrigin, true); r["type"] != "host-ready" {
		t.Fatalf("pinned host: %v", r)
	}
	// setup/begin also refuses other host keys.
	r := e.client("198.51.100.1").post("/api/setup/begin", map[string]any{"hostPub": intruder.pubB64, "claim": proto.B64(intruder.kc)})
	if r.code != http.StatusForbidden {
		t.Fatalf("setup for unpinned key: %d", r.code)
	}

	// HR_HOST_PUBKEY is a comma-separated allow-list (§10.2).
	second := newFakeHost(t)
	e2 := newEnv(t, map[string]string{"HR_HOST_PUBKEY": pinned.pubB64 + "," + second.pubB64})
	for i, h := range []*fakeHost{pinned, second} {
		if r := h.again().connect(e2, "203.0.113.1"+strconv.Itoa(i), testOrigin, true); r["type"] != "host-ready" {
			t.Fatalf("allowed host %d: %v", i, r)
		}
	}
	if r := intruder.connect(e2, "203.0.113.19", testOrigin, true); r["code"] != "host-not-allowed" {
		t.Fatalf("host outside the allow-list: %v", r)
	}
}

func TestHostAuthAfterClaim(t *testing.T) {
	e := newEnv(t, nil)
	h, phone, _, phoneDev := e.claim()

	// Another Mac on a claimed server waits to join (§10.2) instead of being refused.
	second := newJoinHost(t, "Edit Mac")
	if r := second.connect(e, "203.0.113.50", testOrigin, true); r["type"] != "host-ready" || r["claimed"] != true || r["joined"] != false || r["macId"] != second.macID() {
		t.Fatalf("second host after claim: %v", r)
	}
	// It is not bound: host messages other than claim-commit / a join answer are refused.
	second.send(map[string]any{"type": "host-status", "state": "available"})
	second.expectError("not-bound")
	second.send(map[string]any{"type": "device-approved", "cert": second.cert(phoneDev.pub, "Phone", "phone"), "hostMac": proto.B64(randBytes(32))})
	second.expectError("not-bound")
	if _, ok := e.srv.hub.hostInfo(second.pubB64); ok {
		t.Fatal("waiting Mac listed as bound")
	}
	if hosts := phone.get("/api/me").json(t)["hosts"].([]any); len(hosts) != 1 {
		t.Fatalf("waiting Mac in /api/me: %v", hosts)
	}

	if r := newJoinHost(t, "x").connect(e, "203.0.113.51", testOrigin, true); len(r["iceServers"].([]any)) != 0 {
		t.Fatalf("waiting Mac got TURN credentials: %v", r)
	}

	// The bound Mac reconnecting replaces its old connection (and gets TURN).
	again := h.again()
	if r := again.connect(e, "203.0.113.1", testOrigin, false); r["type"] != "host-ready" || r["claimed"] != true || r["joined"] != true || len(r["iceServers"].([]any)) != 2 {
		t.Fatalf("reconnect: %v", r)
	}
	h.expectError("replaced")
	h.expectClosed()
	if info, ok := e.srv.hub.hostInfo(h.pubB64); !ok || !info.Online || info.Name != "Studio Mac" || info.MacID != h.macID() {
		t.Fatalf("host info: %+v", info)
	}
}

func TestHostIdleProtocol(t *testing.T) {
	e := newEnv(t, nil, func(s *Server) { s.t.authTimeout = 200 * time.Millisecond })
	p, _, err := e.dial("/ws/host", http.Header{"X-Forwarded-For": {"203.0.113.1"}})
	if err != nil {
		t.Fatal(err)
	}
	p.expect("challenge")
	p.expectError("auth-timeout")
	p.expectClosed()
}

// ---- claim ----

func TestClaimChecks(t *testing.T) {
	e := newEnv(t, nil)
	c := e.client("198.51.100.1")
	h := newFakeHost(t)

	r := c.post("/api/setup/begin", map[string]any{"hostPub": h.pubB64, "claim": proto.B64(h.kc)})
	if r.code != http.StatusNotFound || r.json(t)["error"] != "host-not-connected" {
		t.Fatalf("no pending host: %d %s", r.code, r.body)
	}
	if r := c.post("/api/setup/begin", map[string]any{"hostPub": "short", "claim": "x"}); r.code != http.StatusBadRequest {
		t.Fatalf("malformed: %d", r.code)
	}

	// A pending host that did not send a commit cannot be claimed.
	h.connect(e, "203.0.113.1", testOrigin, false)
	if r := c.post("/api/setup/begin", map[string]any{"hostPub": h.pubB64, "claim": proto.B64(h.kc)}); r.code != http.StatusForbidden {
		t.Fatalf("claim without commit: %d", r.code)
	}
	// It may send one later (e.g. "new setup code" on the Mac).
	h.send(map[string]any{"type": "claim-commit", "claimCommit": proto.B64(h.commit)})
	time.Sleep(50 * time.Millisecond)

	// Ka (the setup-auth key) must not work as a claim; only Kc does.
	if r := c.post("/api/setup/begin", map[string]any{"hostPub": h.pubB64, "claim": proto.B64(h.ka)}); r.code != http.StatusForbidden || r.json(t)["error"] != "bad-claim" {
		t.Fatalf("Ka as claim: %d %s", r.code, r.body)
	}
	if e.failures(c.ip) != 2 {
		t.Fatalf("bad claims counted: %d", e.failures(c.ip))
	}
	r = c.post("/api/setup/begin", map[string]any{"hostPub": h.pubB64, "claim": proto.B64(h.kc)})
	if r.code != 200 {
		t.Fatalf("good claim: %d %s", r.code, r.body)
	}
	opts := r.json(t)["options"].(map[string]any)["publicKey"].(map[string]any)
	sel := opts["authenticatorSelection"].(map[string]any)
	if sel["residentKey"] != "required" || sel["userVerification"] != "required" || opts["attestation"] != "none" {
		t.Fatalf("creation options: %v", opts)
	}
	if opts["rp"].(map[string]any)["id"] != "localhost" {
		t.Fatalf("rp: %v", opts["rp"])
	}
}

func TestClaimFlowAndAfter(t *testing.T) {
	e := newEnv(t, nil)
	h, phone, authn, phoneDev := e.claim()

	// Already claimed: setup is closed.
	if r := e.client("198.51.100.2").post("/api/setup/begin", map[string]any{"hostPub": h.pubB64, "claim": proto.B64(h.kc)}); r.code != http.StatusConflict {
		t.Fatalf("setup after claim: %d", r.code)
	}
	if e.client("198.51.100.2").get("/api/status").json(t)["claimed"] != true {
		t.Fatal("status not claimed")
	}
	// /api/me shows the Mac, the approved phone and the passkey (§10.4).
	me := phone.get("/api/me").json(t)
	hosts := me["hosts"].([]any)
	if len(hosts) != 1 {
		t.Fatalf("me.hosts: %v", hosts)
	}
	host := hosts[0].(map[string]any)
	if host["pub"] != h.pubB64 || host["macId"] != h.macID() || host["online"] != true || host["state"] != "available" ||
		host["name"] != "Studio Mac" || host["sessionDeviceName"] != "" || host["claimedAt"].(float64) == 0 || host["lastSeen"].(float64) == 0 {
		t.Fatalf("me.hosts[0]: %v", host)
	}
	devs := me["devices"].([]any)
	if len(devs) != 1 || devs[0].(map[string]any)["pub"] != phoneDev.pubB64() || devs[0].(map[string]any)["name"] != "Phone" || devs[0].(map[string]any)["kind"] != "phone" {
		t.Fatalf("me.devices: %v", devs)
	}
	if ap := devs[0].(map[string]any)["approvals"].([]any); len(ap) != 1 || ap[0].(map[string]any)["hostPub"] != h.pubB64 || ap[0].(map[string]any)["status"] != "approved" {
		t.Fatalf("me.devices[0].approvals: %v", ap)
	}
	if pk := me["passkeys"].([]any); len(pk) != 1 || pk[0].(map[string]any)["id"] != b64u.EncodeToString(authn.credID) {
		t.Fatalf("me.passkeys: %v", pk)
	}
	if r := e.client("198.51.100.3").get("/api/me"); r.code != http.StatusUnauthorized {
		t.Fatalf("anonymous /api/me: %d", r.code)
	}
	// The cookie is HttpOnly, SameSite=Strict, Path=/.
	r := e.login(authn, "198.51.100.4")
	_ = r
	// Nothing secret is in the state file.
	b, _ := os.ReadFile(e.st.Path())
	for _, secret := range [][]byte{h.kc, h.ka, h.setupT} {
		if strings.Contains(string(b), proto.B64(secret)) || strings.Contains(string(b), b64u.EncodeToString(secret)) {
			t.Fatal("setup secrets persisted")
		}
	}
	if strings.Contains(string(b), phone.cookie) {
		t.Fatal("raw session token persisted")
	}
}

func TestSessionCookieAttributes(t *testing.T) {
	for _, origin := range []string{testOrigin, "https://remote.example.org"} {
		e := newEnv(t, map[string]string{"HR_ORIGIN": origin})
		h := newFakeHost(t)
		h.connect(e, "203.0.113.1", e.cfg.Origin, true)
		c := e.client("198.51.100.1")
		begin := c.post("/api/setup/begin", map[string]any{"hostPub": h.pubB64, "claim": proto.B64(h.kc)}).json(t)
		opts, _ := json.Marshal(begin["options"])
		dev := newDevice("Phone")
		res := c.post("/api/setup/finish", map[string]any{
			"flowId": begin["flowId"], "credential": json.RawMessage(newSoftAuthn(t).create(t, opts, e.cfg.Origin)),
			"device":   map[string]any{"pub": dev.pubB64(), "name": "Phone", "kind": "phone"},
			"setupMac": proto.B64(proto.SetupMAC(h.ka, h.pub, dev.pub, "Phone", "phone")),
		})
		if res.code != 200 {
			t.Fatalf("%s: setup/finish %d %s", origin, res.code, res.body)
		}
		sc := res.hdr.Get("Set-Cookie")
		for _, want := range []string{"HttpOnly", "SameSite=Strict", "Path=/"} {
			if !strings.Contains(sc, want) {
				t.Errorf("%s: cookie %q lacks %s", origin, sc, want)
			}
		}
		secure := strings.HasPrefix(origin, "https")
		if strings.Contains(sc, "Secure") != secure || strings.HasPrefix(sc, "__Host-hr_session=") != secure || (!secure && !strings.HasPrefix(sc, "hr_session=")) {
			t.Errorf("%s: cookie %q", origin, sc)
		}
	}
}

// ---- login ----

func TestLoginWrongSignatureCountsAsFailure(t *testing.T) {
	e := newEnv(t, nil)
	_, _, authn, _ := e.claim()
	c := e.client("198.51.100.60")
	b := c.post("/api/login/begin", nil).json(t)
	opts, _ := json.Marshal(b["options"])
	pk := b["options"].(map[string]any)["publicKey"].(map[string]any)
	if pk["userVerification"] != "required" || pk["allowCredentials"] != nil {
		t.Fatalf("login options must be discoverable + UV required: %v", pk)
	}
	r := c.post("/api/login/finish", map[string]any{"flowId": b["flowId"], "credential": json.RawMessage(authn.get(t, opts, e.cfg.Origin, true))})
	if r.code != http.StatusUnauthorized || c.cookie != "" {
		t.Fatalf("bad assertion: %d %s", r.code, r.body)
	}
	if e.failures(c.ip) != 1 {
		t.Fatalf("failure not counted: %d", e.failures(c.ip))
	}
	// The flow is single-use, even after a failure.
	r = c.post("/api/login/finish", map[string]any{"flowId": b["flowId"], "credential": json.RawMessage(authn.get(t, opts, e.cfg.Origin, false))})
	if r.code != http.StatusBadRequest {
		t.Fatalf("replayed flow: %d", r.code)
	}
	// Wrong origin in clientDataJSON is rejected too.
	b = c.post("/api/login/begin", nil).json(t)
	opts, _ = json.Marshal(b["options"])
	if r := c.post("/api/login/finish", map[string]any{"flowId": b["flowId"], "credential": json.RawMessage(authn.get(t, opts, "https://evil.example", false))}); r.code != http.StatusUnauthorized {
		t.Fatalf("phished assertion: %d", r.code)
	}
	// A correct login works.
	ok := e.login(authn, "198.51.100.61")
	if ok.get("/api/me").code != 200 {
		t.Fatal("login session unusable")
	}
}

// A passkey whose signature counter goes backwards (a cloned or replayed
// authenticator) is refused, and the stored counter is not lowered.
func TestLoginRejectsCounterGoingBackwards(t *testing.T) {
	e := newEnv(t, nil)
	_, _, authn, _ := e.claim()
	for i := 0; i < 3; i++ {
		e.login(authn, "198.51.100.70") // counter 1, 2, 3
	}
	storedCount := func() uint32 {
		var n uint32
		e.st.View(func(st *storeState) { n = st.Owner.Passkeys[0].Credential.Authenticator.SignCount })
		return n
	}
	if storedCount() != 3 {
		t.Fatalf("stored sign count %d, want 3", storedCount())
	}
	clone := *authn
	clone.counter = 1 // next assertion carries 2 <= 3
	c := e.client("198.51.100.71")
	b := c.post("/api/login/begin", nil).json(t)
	opts, _ := json.Marshal(b["options"])
	r := c.post("/api/login/finish", map[string]any{"flowId": b["flowId"], "credential": json.RawMessage(clone.get(t, opts, e.cfg.Origin, false))})
	if r.code != http.StatusUnauthorized || c.cookie != "" || str(r.json(t), "error") != "webauthn-failed" {
		t.Fatalf("cloned authenticator accepted: %d %s", r.code, r.body)
	}
	if e.failures(c.ip) != 1 {
		t.Fatalf("clone attempt not counted as an auth failure: %d", e.failures(c.ip))
	}
	if storedCount() != 3 {
		t.Fatalf("stored sign count changed to %d", storedCount())
	}
	// The genuine authenticator (counter 4) still works.
	if e.login(authn, "198.51.100.72").get("/api/me").code != 200 {
		t.Fatal("genuine authenticator refused after clone attempt")
	}
}

func TestLogout(t *testing.T) {
	e := newEnv(t, nil)
	_, phone, _, dev := e.claim()
	r := phone.post("/api/logout", nil)
	if r.code != 200 || phone.cookie != "" {
		t.Fatalf("logout: %d cookie=%q", r.code, phone.cookie)
	}
	dev.expectError("logged-out")
	dev.expectClosed()
	var n int
	e.st.View(func(st *store.State) { n = len(st.Sessions) })
	if n != 0 {
		t.Fatalf("sessions after logout: %d", n)
	}
}

// ---- pairing, approvals, sessions, trust-sync ----

func TestPairingAndSessionRelay(t *testing.T) {
	e := newEnv(t, nil)
	h, _, authn, phone := e.claim()

	// A second browser logs in with the (synced) passkey; its device key is unknown.
	laptopClient := e.login(authn, "198.51.100.70")
	laptop := newDevice("Laptop")
	ready := laptop.connect(e, laptopClient, "")
	rh := ready["hosts"].([]any)[0].(map[string]any)
	if rh["deviceStatus"] != "unknown" || rh["online"] != true || rh["pub"] != h.pubB64 || rh["macId"] != h.macID() || rh["cert"] != nil {
		t.Fatalf("laptop ready: %v", ready)
	}

	// Unapproved devices cannot start sessions, approve, revoke or kill.
	laptop.send(map[string]any{"type": "session-request", "hostPub": h.pubB64, "sessionId": proto.B64(randBytes(16)), "devicePub": phone.pubB64(), "clientNonce": proto.B64(randBytes(32))})
	laptop.expectError("not-approved")
	laptop.send(map[string]any{"type": "pair-approve", "hostPub": h.pubB64, "requestId": "x", "approverPub": phone.pubB64(), "sig": proto.B64(randBytes(64))})
	laptop.expectError("not-approved")
	laptop.send(map[string]any{"type": "kill-request", "hostPub": h.pubB64, "action": "kill", "ts": time.Now().Unix(), "sig": proto.B64(randBytes(64))})
	laptop.expectError("not-approved")
	// Messages that target a Mac must name a bound one.
	laptop.send(map[string]any{"type": "session-request", "sessionId": proto.B64(randBytes(16)), "clientNonce": proto.B64(randBytes(32))})
	laptop.expectError("bad-request")
	laptop.send(map[string]any{"type": "pair-start", "hostPub": newFakeHost(t).pubB64, "name": "Laptop", "kind": "browser", "commit": proto.B64(randBytes(32))})
	laptop.expectError("unknown-host")
	h.expectNone(100 * time.Millisecond)

	// Commit-then-reveal pairing.
	nd := randBytes(32)
	commit := proto.PairCommit(laptop.pub, nd)
	laptop.send(map[string]any{"type": "pair-start", "hostPub": h.pubB64, "name": "Laptop", "kind": "browser", "commit": proto.B64(commit)})
	pend := laptop.expect("pair-pending")
	reqID := str(pend, "requestId")
	if pend["hostPub"] != h.pubB64 {
		t.Fatalf("pair-pending: %v", pend)
	}
	pr := h.expect("pair-request")
	if str(pr, "requestId") != reqID || str(pr, "devicePub") != "" || str(pr, "commit") != proto.B64(commit) || str(pr, "name") != "Laptop" {
		t.Fatalf("pair-request: %v", pr)
	}
	// Revealing before the challenge is refused.
	laptop.send(map[string]any{"type": "pair-reveal", "requestId": reqID, "devicePub": laptop.pubB64(), "nd": proto.B64(nd)})
	laptop.expectError("bad-state")

	na := randBytes(32)
	reqRaw := mustB64(t, reqID)
	// A challenge with a bad host signature is dropped by the server.
	h.send(map[string]any{"type": "pair-challenge", "requestId": reqID, "hostPub": h.pubB64, "na": proto.B64(na), "sig": proto.B64(randBytes(64))})
	h.expectError("bad-signature")
	hostSig := proto.Sign(h.priv, proto.LabelPairChallenge, reqRaw, commit, na, h.pub)
	h.send(map[string]any{"type": "pair-challenge", "requestId": reqID, "hostPub": h.pubB64, "na": proto.B64(na), "sig": proto.B64(hostSig)})
	ch := laptop.expect("pair-challenge")
	if str(ch, "hostPub") != h.pubB64 || !proto.Verify(h.pub, mustB64(t, str(ch, "sig")), proto.LabelPairChallenge, reqRaw, commit, mustB64(t, str(ch, "na")), h.pub) {
		t.Fatalf("pair-challenge: %v", ch)
	}
	// The reveal claims a different key: the server substitutes the authenticated one.
	laptop.send(map[string]any{"type": "pair-reveal", "requestId": reqID, "devicePub": phone.pubB64(), "nd": proto.B64(nd)})
	rv := h.expect("pair-reveal")
	if str(rv, "devicePub") != laptop.pubB64() || str(rv, "nd") != proto.B64(nd) {
		t.Fatalf("pair-reveal to host: %v", rv)
	}
	an := phone.expect("approval-needed")
	if str(an, "devicePub") != laptop.pubB64() || str(an, "commit") != proto.B64(commit) || str(an, "hostSig") != proto.B64(hostSig) || str(an, "nd") != proto.B64(nd) || str(an, "na") != proto.B64(na) || an["hostPub"] != h.pubB64 {
		t.Fatalf("approval-needed: %v", an)
	}
	// Both sides compute the same SAS.
	sasPhone := proto.SAS(h.pub, mustB64(t, str(an, "devicePub")), mustB64(t, str(an, "nd")), mustB64(t, str(an, "na")))
	if sasPhone != proto.SAS(h.pub, laptop.pub, nd, na) {
		t.Fatal("SAS mismatch")
	}
	if e.status(laptop.pubB64(), h.pubB64) != store.StatusPending {
		t.Fatal("revealed device should be pending")
	}
	// The unapproved laptop never receives approval requests.
	laptop.expectNone(50 * time.Millisecond)

	// A forged approval signature is rejected by the server.
	phone.send(map[string]any{"type": "pair-approve", "hostPub": h.pubB64, "requestId": reqID, "approverPub": phone.pubB64(), "sig": proto.B64(randBytes(64))})
	phone.expectError("bad-signature")
	approveSig := proto.Sign(phone.priv, proto.LabelPairApprove, reqRaw, h.pub, laptop.pub, nd, na, proto.Str("Laptop"), proto.Str("browser"))
	phone.send(map[string]any{"type": "pair-approve", "hostPub": h.pubB64, "requestId": reqID, "approverPub": laptop.pubB64(), "sig": proto.B64(approveSig)})
	ap := h.expect("pair-approve")
	if str(ap, "approverPub") != phone.pubB64() || str(ap, "sig") != proto.B64(approveSig) {
		t.Fatalf("pair-approve to host: %v", ap)
	}

	// A cert for a different device key is rejected.
	stranger := newDevice("x")
	h.send(map[string]any{"type": "pair-result", "requestId": reqID, "approved": true, "cert": h.cert(stranger.pub, "Laptop", "browser")})
	h.expectError("bad-cert")
	if d := laptop.expect("pair-denied"); d["reason"] != "error" {
		t.Fatalf("pair-denied: %v", d)
	}
	phone.expect("approval-closed")
	if e.status(laptop.pubB64(), h.pubB64) == store.StatusApproved {
		t.Fatal("device approved with a wrong cert")
	}

	// Second attempt, approved for real.
	reqID, nd, na = pairOnce(t, h, laptop, phone)
	_ = na
	cert := h.cert(laptop.pub, "Laptop", "browser")
	h.send(map[string]any{"type": "pair-result", "requestId": reqID, "approved": true, "cert": cert})
	pa := laptop.expect("pair-approved")
	if pa["cert"].(map[string]any)["sig"] != cert.Sig || pa["hostPub"] != h.pubB64 {
		t.Fatalf("pair-approved: %v", pa)
	}
	if c := phone.expect("approval-closed"); str(c, "requestId") != reqID || c["hostPub"] != h.pubB64 {
		t.Fatalf("approval-closed: %v", c)
	}
	if e.status(laptop.pubB64(), h.pubB64) != store.StatusApproved {
		t.Fatal("laptop not approved")
	}
	_ = nd

	// Session relay: the server overwrites devicePub with the authenticated key.
	sid := proto.B64(randBytes(16))
	cn := proto.B64(randBytes(32))
	laptop.send(map[string]any{"type": "session-request", "hostPub": h.pubB64, "sessionId": sid, "devicePub": phone.pubB64(), "clientNonce": cn, "relayOnly": true})
	sr := h.expect("session-request")
	if str(sr, "devicePub") != laptop.pubB64() || str(sr, "sessionId") != sid || str(sr, "clientNonce") != cn || sr["relayOnly"] != true {
		t.Fatalf("session-request: %v", sr)
	}
	// Offer before accept is refused.
	laptop.send(map[string]any{"type": "offer", "sessionId": sid, "sdp": "v=0", "sig": proto.B64(randBytes(64))})
	laptop.expectError("bad-request")
	hn := proto.B64(randBytes(32))
	h.send(map[string]any{"type": "session-accept", "sessionId": sid, "hostNonce": hn})
	if acc := laptop.expect("session-accept"); str(acc, "hostNonce") != hn || acc["hostPub"] != h.pubB64 {
		t.Fatalf("session-accept: %v", acc)
	}
	offerSig := proto.B64(randBytes(64))
	laptop.send(map[string]any{"type": "offer", "sessionId": sid, "sdp": "v=0\r\na=fingerprint:sha-256 AA\r\n", "sig": offerSig, "devicePub": phone.pubB64(), "extra": "dropped"})
	of := h.expect("offer")
	if str(of, "sdp") != "v=0\r\na=fingerprint:sha-256 AA\r\n" || str(of, "sig") != offerSig || of["extra"] != nil || of["devicePub"] != nil {
		t.Fatalf("offer: %v", of)
	}
	// Another device cannot inject into this session.
	phone.send(map[string]any{"type": "ice", "sessionId": sid, "candidate": map[string]any{"candidate": "evil"}})
	phone.expectError("unknown-session")
	ansSig := proto.B64(randBytes(64))
	h.send(map[string]any{"type": "answer", "sessionId": sid, "sdp": "v=0 answer", "sig": ansSig})
	if an := laptop.expect("answer"); str(an, "sdp") != "v=0 answer" || str(an, "sig") != ansSig || an["hostPub"] != h.pubB64 {
		t.Fatalf("answer: %v", an)
	}
	laptop.send(map[string]any{"type": "ice", "sessionId": sid, "candidate": map[string]any{"candidate": "candidate:1 1 udp 1 192.0.2.1 5000 typ host", "sdpMid": "0"}})
	if ic := h.expect("ice"); ic["candidate"].(map[string]any)["sdpMid"] != "0" {
		t.Fatalf("ice to host: %v", ic)
	}
	h.send(map[string]any{"type": "ice", "sessionId": sid, "candidate": nil})
	if ic := laptop.expect("ice"); ic["candidate"] != nil || ic["hostPub"] != h.pubB64 {
		t.Fatalf("end-of-candidates: %v", ic)
	}
	h.send(map[string]any{"type": "host-status", "state": "in-session", "sessionDeviceName": "Laptop"})
	waitFor(t, func() bool { info, _ := e.srv.hub.hostInfo(h.pubB64); return info.State == "in-session" })
	var hs map[string]any
	for hs == nil || hs["state"] != "in-session" {
		hs = phone.expect("host-status")
	}
	if hs["sessionDeviceName"] != "Laptop" || hs["online"] != true || hs["hostPub"] != h.pubB64 {
		t.Fatalf("host-status: %v", hs)
	}
	laptop.send(map[string]any{"type": "session-end", "sessionId": sid, "hostPub": h.pubB64, "reason": "user"})
	if se := h.expect("session-end"); se["reason"] != "user" {
		t.Fatalf("session-end: %v", se)
	}
	h.send(map[string]any{"type": "answer", "sessionId": sid, "sdp": "late", "sig": ansSig})
	h.expectError("unknown-session")

	// Kill/revoke requests from an approved device are verified and relayed.
	ts := time.Now().Unix()
	killSig := proto.Sign(phone.priv, proto.LabelKillRequest, h.pub, proto.Str("kill"), proto.Int(ts))
	phone.send(map[string]any{"type": "kill-request", "hostPub": h.pubB64, "action": "kill", "ts": ts, "approverPub": laptop.pubB64(), "sig": proto.B64(killSig)})
	if kr := h.expect("kill-request"); str(kr, "approverPub") != phone.pubB64() || kr["action"] != "kill" {
		t.Fatalf("kill-request: %v", kr)
	}
	stale := time.Now().Add(-time.Hour).Unix()
	phone.send(map[string]any{"type": "kill-request", "hostPub": h.pubB64, "action": "kill", "ts": stale, "sig": proto.B64(proto.Sign(phone.priv, proto.LabelKillRequest, h.pub, proto.Str("kill"), proto.Int(stale)))})
	phone.expectError("stale")
	revSig := proto.Sign(phone.priv, proto.LabelRevokeRequest, h.pub, laptop.pub, proto.Int(ts))
	phone.send(map[string]any{"type": "revoke-request", "hostPub": h.pubB64, "targetPub": laptop.pubB64(), "ts": ts, "sig": proto.B64(revSig)})
	if rr := h.expect("revoke-request"); str(rr, "targetPub") != laptop.pubB64() || str(rr, "approverPub") != phone.pubB64() {
		t.Fatalf("revoke-request: %v", rr)
	}

	// trust-sync: the Mac is authoritative. Only the phone is certified, so the
	// laptop (approved earlier) becomes revoked; a forged cert is ignored.
	forged := proto.SignCert(newFakeHost(t).priv, proto.Cert{HostPub: h.pubB64, DevicePub: stranger.pubB64(), Name: "x", Kind: "browser", IssuedAt: 1})
	h.send(map[string]any{"type": "trust-sync", "certs": []proto.Cert{h.certsOK[phone.pubB64()], forged}, "revocations": []proto.Revocation{}})
	waitFor(t, func() bool { return e.status(laptop.pubB64(), h.pubB64) == store.StatusRevoked })
	if e.status(phone.pubB64(), h.pubB64) != store.StatusApproved || e.status(stranger.pubB64(), h.pubB64) != store.StatusUnknown {
		t.Fatalf("trust-sync statuses: phone=%s stranger=%s", e.status(phone.pubB64(), h.pubB64), e.status(stranger.pubB64(), h.pubB64))
	}
	laptop.send(map[string]any{"type": "session-request", "hostPub": h.pubB64, "sessionId": proto.B64(randBytes(16)), "clientNonce": proto.B64(randBytes(32))})
	laptop.expectError("not-approved")
}

// pairOnce runs pair-start → challenge → reveal and returns the request id.
func pairOnce(t *testing.T, h *fakeHost, dev, approver *device) (string, []byte, []byte) {
	t.Helper()
	nd := randBytes(32)
	commit := proto.PairCommit(dev.pub, nd)
	dev.send(map[string]any{"type": "pair-start", "hostPub": h.pubB64, "name": dev.name, "kind": dev.kind, "commit": proto.B64(commit)})
	reqID := str(dev.expect("pair-pending"), "requestId")
	h.expect("pair-request")
	na := randBytes(32)
	h.send(map[string]any{"type": "pair-challenge", "requestId": reqID, "hostPub": h.pubB64, "na": proto.B64(na),
		"sig": proto.B64(proto.Sign(h.priv, proto.LabelPairChallenge, mustB64(t, reqID), commit, na, h.pub))})
	dev.expect("pair-challenge")
	dev.send(map[string]any{"type": "pair-reveal", "requestId": reqID, "devicePub": dev.pubB64(), "nd": proto.B64(nd)})
	h.expect("pair-reveal")
	if approver != nil {
		approver.expect("approval-needed")
	}
	return reqID, nd, na
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPairDenyAndHostOffline(t *testing.T) {
	e := newEnv(t, nil)
	h, _, authn, phone := e.claim()
	c := e.login(authn, "198.51.100.80")
	tablet := newDevice("Tablet")
	tablet.connect(e, c, "")
	reqID, _, _ := pairOnce(t, h, tablet, phone)
	phone.send(map[string]any{"type": "pair-deny", "hostPub": h.pubB64, "requestId": reqID})
	if d := h.expect("pair-deny"); str(d, "requestId") != reqID {
		t.Fatalf("pair-deny: %v", d)
	}
	h.send(map[string]any{"type": "pair-result", "requestId": reqID, "approved": false, "reason": "denied"})
	if d := tablet.expect("pair-denied"); d["reason"] != "denied" || d["hostPub"] != h.pubB64 {
		t.Fatalf("pair-denied: %v", d)
	}
	phone.expect("approval-closed")
	if e.status(tablet.pubB64(), h.pubB64) != store.StatusUnknown {
		t.Fatal("denied device kept")
	}

	// A mismatching reveal is forwarded to the host but never shown to approvers.
	nd := randBytes(32)
	tablet.send(map[string]any{"type": "pair-start", "hostPub": h.pubB64, "name": "Tablet", "kind": "browser", "commit": proto.B64(proto.PairCommit(tablet.pub, nd))})
	reqID = str(tablet.expect("pair-pending"), "requestId")
	h.expect("pair-request")
	na := randBytes(32)
	h.send(map[string]any{"type": "pair-challenge", "requestId": reqID, "hostPub": h.pubB64, "na": proto.B64(na),
		"sig": proto.B64(proto.Sign(h.priv, proto.LabelPairChallenge, mustB64(t, reqID), proto.PairCommit(tablet.pub, nd), na, h.pub))})
	tablet.expect("pair-challenge")
	tablet.send(map[string]any{"type": "pair-reveal", "requestId": reqID, "nd": proto.B64(randBytes(32))})
	h.expect("pair-reveal")
	phone.expectNone(100 * time.Millisecond)

	// Host goes offline: pending pairings fail and clients see it offline.
	_ = h.ws.CloseNow()
	if d := tablet.expect("pair-denied"); d["reason"] != "host-offline" {
		t.Fatalf("pair-denied on host loss: %v", d)
	}
	waitFor(t, func() bool { info, _ := e.srv.hub.hostInfo(h.pubB64); return !info.Online })
	if info, _ := e.srv.hub.hostInfo(h.pubB64); info.State != "offline" {
		t.Fatalf("offline state %q", info.State)
	}
	tablet.send(map[string]any{"type": "pair-start", "hostPub": h.pubB64, "name": "Tablet", "kind": "browser", "commit": proto.B64(randBytes(32))})
	tablet.expectError("host-offline")
}

func TestDeviceRevokedMessage(t *testing.T) {
	e := newEnv(t, nil)
	h, _, _, phone := e.claim()
	rev := proto.Revocation{HostPub: h.pubB64, DevicePub: phone.pubB64(), RevokedAt: time.Now().Unix()}
	rev.Sig = proto.B64(proto.Sign(newFakeHost(t).priv, proto.LabelRevoked, h.pub, phone.pub, proto.Int(rev.RevokedAt)))
	h.send(map[string]any{"type": "device-revoked", "revocation": rev})
	h.expectError("bad-revocation")
	rev.Sig = proto.B64(proto.Sign(h.priv, proto.LabelRevoked, h.pub, phone.pub, proto.Int(rev.RevokedAt)))
	h.send(map[string]any{"type": "device-revoked", "revocation": rev})
	waitFor(t, func() bool { return e.status(phone.pubB64(), h.pubB64) == store.StatusRevoked })
	phone.expect("devices-changed")
}

// ---- link flow (native apps) ----

func TestLinkFlow(t *testing.T) {
	e := newEnv(t, nil)
	h, phone, _, phoneDev := e.claim()
	app := e.client("198.51.100.90")
	app.origin = tauri

	r := app.post("/api/link/start", map[string]any{"name": "Windows laptop"})
	if r.code != 200 || r.hdr.Get("Access-Control-Allow-Origin") != tauri {
		t.Fatalf("link/start: %d %s %v", r.code, r.body, r.hdr)
	}
	m := r.json(t)
	code, poll := str(m, "code"), str(m, "pollToken")
	if !regexp.MustCompile(`^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{4}-[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{4}$`).MatchString(code) || m["expiresIn"] != float64(600) {
		t.Fatalf("code %q %v", code, m)
	}
	if s := app.post("/api/link/poll", map[string]any{"pollToken": poll}).json(t); s["status"] != "pending" || s["token"] != nil {
		t.Fatalf("poll pending: %v", s)
	}
	// Approving needs a session; a wrong code is an auth failure.
	if r := e.client("198.51.100.91").post("/api/link/approve", map[string]any{"code": code}); r.code != http.StatusUnauthorized {
		t.Fatalf("anonymous approve: %d", r.code)
	}
	if r := phone.post("/api/link/approve", map[string]any{"code": "ZZZZ-ZZZZ"}); r.code != http.StatusNotFound {
		t.Fatalf("bad code: %d", r.code)
	}
	if e.failures(phone.ip) != 1 {
		t.Fatal("bad link code not counted")
	}
	// Codes are case- and dash-insensitive when typed.
	if r := phone.post("/api/link/approve", map[string]any{"code": strings.ToLower(strings.ReplaceAll(code, "-", " "))}); r.code != 200 || r.json(t)["name"] != "Windows laptop" {
		t.Fatalf("approve: %d %s", r.code, r.body)
	}
	if r := phone.post("/api/link/approve", map[string]any{"code": code}); r.code != http.StatusNotFound {
		t.Fatalf("code reused: %d", r.code)
	}
	s := app.post("/api/link/poll", map[string]any{"pollToken": poll}).json(t)
	tok := str(s, "token")
	if s["status"] != "approved" || len(tok) < 40 {
		t.Fatalf("poll approved: %v", s)
	}
	if s := app.post("/api/link/poll", map[string]any{"pollToken": poll}).json(t); s["status"] != "expired" || s["token"] != nil {
		t.Fatalf("token delivered twice: %v", s)
	}
	// The bearer token works cross-origin from Tauri, without cookies.
	app.bearer = tok
	if r := app.get("/api/me"); r.code != 200 || r.hdr.Get("Access-Control-Allow-Origin") != tauri {
		t.Fatalf("bearer /api/me: %d %v", r.code, r.hdr)
	}
	if r := app.post("/api/turn", nil); r.code != 200 {
		t.Fatalf("bearer POST without X-HR: %d", r.code)
	}
	// A bearer token is not accepted as a cookie, and vice versa.
	if r := (&client{e: e, ip: "198.51.100.92", origin: testOrigin, cookie: tok}).get("/api/me"); r.code != http.StatusUnauthorized {
		t.Fatal("bearer token accepted as cookie")
	}
	if r := (&client{e: e, ip: "198.51.100.92", bearer: phone.cookie}).get("/api/me"); r.code != http.StatusUnauthorized {
		t.Fatal("cookie token accepted as bearer")
	}
	// WebSocket with the bearer token from the Tauri origin.
	tauriDev := newDevice("Windows laptop")
	ready := tauriDev.connect(e, &client{e: e, ip: app.ip, origin: tauri}, tok)
	if ready["hosts"].([]any)[0].(map[string]any)["deviceStatus"] != "unknown" {
		t.Fatalf("tauri ready: %v", ready)
	}
	// Bearer session expiry is 30 days.
	var exp time.Time
	e.st.View(func(st *store.State) {
		for _, ss := range st.Sessions {
			if ss.Kind == store.KindBearer {
				exp = ss.Expires
			}
		}
	})
	if d := time.Until(exp); d < 29*24*time.Hour || d > 31*24*time.Hour {
		t.Fatalf("bearer lifetime %v", d)
	}
	_ = h
	_ = phoneDev
	// An expired link code cannot be approved.
	r = app.post("/api/link/start", map[string]any{"name": "Other"})
	code2 := str(r.json(t), "code")
	e.clock.advance(11 * time.Minute)
	if r := phone.post("/api/link/approve", map[string]any{"code": code2}); r.code != http.StatusNotFound {
		t.Fatalf("expired code: %d", r.code)
	}
}

func TestLinkRequiresClaim(t *testing.T) {
	e := newEnv(t, nil)
	app := e.client("198.51.100.90")
	app.origin = tauri
	if r := app.post("/api/link/start", map[string]any{"name": "App"}); r.code != http.StatusConflict {
		t.Fatalf("link before claim: %d", r.code)
	}
	if r := app.post("/api/link/start", map[string]any{"name": "bad\x00name"}); r.code != http.StatusBadRequest {
		t.Fatalf("control chars in name: %d", r.code)
	}
	if code := randomCode(); len(code) != 8 || strings.ContainsAny(code, "ILO01") {
		t.Fatalf("code alphabet: %q", code)
	}
}

// ---- passkeys (session + device proof) ----

func deviceProofFor(t *testing.T, c *client, d *device) map[string]any {
	t.Helper()
	r := c.get("/api/nonce")
	if r.code != 200 {
		t.Fatalf("nonce: %d %s", r.code, r.body)
	}
	n := str(r.json(t), "nonce")
	sig := proto.Sign(d.priv, proto.LabelClientAuth, proto.Str(c.e.cfg.Origin), mustB64(t, n))
	return map[string]any{"devicePub": d.pubB64(), "nonce": n, "sig": proto.B64(sig)}
}

func TestPasskeyManagement(t *testing.T) {
	e := newEnv(t, nil)
	_, phone, authn, phoneDev := e.claim()

	// Device proof is required and checked.
	if r := phone.post("/api/passkeys/begin", map[string]any{}); r.code != http.StatusBadRequest {
		t.Fatalf("no proof: %d", r.code)
	}
	proof := deviceProofFor(t, phone, phoneDev)
	proof["sig"] = proto.B64(randBytes(64))
	if r := phone.post("/api/passkeys/begin", proof); r.code != http.StatusForbidden {
		t.Fatalf("bad proof sig: %d", r.code)
	}
	if e.failures(phone.ip) != 1 {
		t.Fatal("bad device proof not counted")
	}
	// Nonces are single-use.
	proof = deviceProofFor(t, phone, phoneDev)
	if r := phone.post("/api/passkeys/begin", proof); r.code != 200 {
		t.Fatalf("begin: %d %s", r.code, r.body)
	}
	if r := phone.post("/api/passkeys/begin", proof); r.code != http.StatusForbidden || r.json(t)["error"] != "bad-nonce" {
		t.Fatalf("nonce reuse: %d %s", r.code, r.body)
	}
	// An unapproved device cannot manage passkeys.
	stranger := newDevice("x")
	if r := phone.post("/api/passkeys/begin", deviceProofFor(t, phone, stranger)); r.code != http.StatusForbidden {
		t.Fatalf("unapproved device: %d", r.code)
	}

	b := phone.post("/api/passkeys/begin", deviceProofFor(t, phone, phoneDev)).json(t)
	opts, _ := json.Marshal(b["options"])
	pkOpts := b["options"].(map[string]any)["publicKey"].(map[string]any)
	if ex := pkOpts["excludeCredentials"].([]any); len(ex) != 1 {
		t.Fatalf("excludeCredentials: %v", ex)
	}
	second := newSoftAuthn(t)
	fin := deviceProofFor(t, phone, phoneDev)
	fin["flowId"] = b["flowId"]
	fin["name"] = "YubiKey"
	fin["credential"] = json.RawMessage(second.create(t, opts, e.cfg.Origin))
	if r := phone.post("/api/passkeys/finish", fin); r.code != 200 {
		t.Fatalf("finish: %d %s", r.code, r.body)
	}
	pks := phone.get("/api/me").json(t)["passkeys"].([]any)
	if len(pks) != 2 || pks[1].(map[string]any)["name"] != "YubiKey" {
		t.Fatalf("passkeys: %v", pks)
	}
	// The new passkey can log in.
	e.login(second, "198.51.100.95")

	del := deviceProofFor(t, phone, phoneDev)
	del["id"] = b64u.EncodeToString(authn.credID)
	if r := phone.post("/api/passkeys/delete", del); r.code != 200 {
		t.Fatalf("delete: %d %s", r.code, r.body)
	}
	del = deviceProofFor(t, phone, phoneDev)
	del["id"] = b64u.EncodeToString(second.credID)
	if r := phone.post("/api/passkeys/delete", del); r.code != http.StatusConflict || r.json(t)["error"] != "last-passkey" {
		t.Fatalf("delete last: %d %s", r.code, r.body)
	}
	// The deleted passkey no longer logs in.
	c := e.client("198.51.100.96")
	lb := c.post("/api/login/begin", nil).json(t)
	lo, _ := json.Marshal(lb["options"])
	if r := c.post("/api/login/finish", map[string]any{"flowId": lb["flowId"], "credential": json.RawMessage(authn.get(t, lo, e.cfg.Origin, false))}); r.code != http.StatusUnauthorized {
		t.Fatalf("deleted passkey login: %d", r.code)
	}
}

// ---- retention ----

func TestPurgeJob(t *testing.T) {
	e := newEnv(t, nil)
	now := e.srv.now()
	_ = e.st.Update(func(st *store.State) error {
		st.Events = []store.Event{
			{Time: now.Add(-8 * 24 * time.Hour), Type: "login", IP: "198.51.100.1"},
			{Time: now.Add(-time.Hour), Type: "login", IP: "198.51.100.2"},
		}
		st.Devices["old"] = &store.Device{Pub: "old", CreatedAt: now.Add(-25 * time.Hour),
			Approvals: map[string]*store.Approval{"h": {Status: store.StatusPending, CreatedAt: now.Add(-25 * time.Hour)}}}
		st.Sessions["x"] = &store.Session{Hash: "x", Kind: store.KindCookie, LastUsed: now.Add(-13 * time.Hour), Expires: now.Add(time.Hour)}
		return nil
	})
	e.srv.mem.mu.Lock()
	e.srv.mem.links = append(e.srv.mem.links, &linkRec{expires: now.Add(-time.Second)})
	e.srv.mem.mu.Unlock()
	e.srv.Purge()
	e.st.View(func(st *store.State) {
		if len(st.Events) != 1 || st.Events[0].IP != "198.51.100.2" {
			t.Fatalf("events after purge: %v", st.Events)
		}
		if len(st.Devices) != 0 || len(st.Sessions) != 0 {
			t.Fatal("stale devices/sessions kept")
		}
	})
	e.srv.mem.mu.Lock()
	defer e.srv.mem.mu.Unlock()
	if len(e.srv.mem.links) != 0 {
		t.Fatal("expired link codes kept")
	}
	// The file on disk reflects the purge.
	b, _ := os.ReadFile(e.st.Path())
	if strings.Contains(string(b), "198.51.100.1") {
		t.Fatal("old event still on disk")
	}
	fi, _ := os.Stat(e.st.Path())
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode %v", fi.Mode().Perm())
	}
}

func TestClientWSRequiresSession(t *testing.T) {
	e := newEnv(t, nil)
	e.claim()
	d := newDevice("x")
	p, _, err := e.dial("/ws/client", http.Header{"Origin": {testOrigin}, "X-Forwarded-For": {"198.51.100.5"}})
	if err != nil {
		t.Fatal(err)
	}
	d.peer = p
	p.send(map[string]any{"type": "auth"})
	p.expectError("unauthorized")
	p.expectClosed()
	// No Origin at all is refused for client sockets.
	if _, res, err := e.dial("/ws/client", http.Header{"X-Forwarded-For": {"198.51.100.5"}}); err == nil || res.StatusCode != http.StatusForbidden {
		t.Fatal("client socket without Origin accepted")
	}
}

// linkBearer runs the native-app link flow and returns a bearer token.
func linkBearer(t *testing.T, e *testEnv, phone *client, ip string) string {
	t.Helper()
	app := e.client(ip)
	app.origin = tauri
	m := app.post("/api/link/start", map[string]any{"name": "Native app"}).json(t)
	if r := phone.post("/api/link/approve", map[string]any{"code": str(m, "code")}); r.code != 200 {
		t.Fatalf("link approve: %d %s", r.code, r.body)
	}
	tok := str(app.post("/api/link/poll", map[string]any{"pollToken": str(m, "pollToken")}).json(t), "token")
	if tok == "" {
		t.Fatal("no bearer token")
	}
	return tok
}

// The Tauri app (macOS: tauri://localhost; Windows: http(s)://tauri.localhost)
// opens /ws/client cross-origin and authenticates with its bearer token.
func TestClientWSTauriOrigins(t *testing.T) {
	e := newEnv(t, nil)
	_, phone, _, _ := e.claim()
	tok := linkBearer(t, e, phone, "198.51.100.120")
	for i, origin := range config.TauriOrigins {
		d := newDevice("Native " + origin)
		ready := d.connect(e, &client{e: e, ip: "198.51.100." + strconv.Itoa(121+i), origin: origin}, tok)
		if ready["hosts"].([]any)[0].(map[string]any)["deviceStatus"] != store.StatusUnknown {
			t.Fatalf("%s: ready %v", origin, ready)
		}
	}
	// From a Tauri origin the browser session cookie is ignored (only the
	// bearer token authenticates there), and a cookie-kind token is not
	// accepted as a bearer token.
	for i, tc := range []struct{ cookie, token string }{{phone.cookie, ""}, {"", phone.cookie}} {
		hdr := http.Header{"Origin": {tauri}, "X-Forwarded-For": {"198.51.100." + strconv.Itoa(130+i)}}
		if tc.cookie != "" {
			hdr.Set("Cookie", e.cfg.CookieName()+"="+tc.cookie)
		}
		p, _, err := e.dial("/ws/client", hdr)
		if err != nil {
			t.Fatal(err)
		}
		auth := map[string]any{"type": "auth"}
		if tc.token != "" {
			auth["token"] = tc.token
		}
		p.send(auth)
		p.expectError("unauthorized")
		p.expectClosed()
	}
	// Look-alike origins are refused at the upgrade.
	for i, origin := range []string{"https://evil.example", "tauri://evil", "http://tauri.localhost.evil.example", "null"} {
		hdr := http.Header{"Origin": {origin}, "X-Forwarded-For": {"198.51.100." + strconv.Itoa(140+i)}}
		if _, res, err := e.dial("/ws/client", hdr); err == nil || res == nil || res.StatusCode != http.StatusForbidden {
			t.Fatalf("origin %q accepted", origin)
		}
	}
}

func TestClientWSBadDeviceSignature(t *testing.T) {
	e := newEnv(t, nil)
	_, phone, _, _ := e.claim()
	d := newDevice("x")
	other := newDevice("y")
	d.priv = other.priv
	p := d.dialAuth(e, phone, "")
	p.expectError("bad-signature")
	p.expectClosed()
	if e.failures(phone.ip) != 1 {
		t.Fatal("bad device signature not counted")
	}
}

func TestWSMessageRules(t *testing.T) {
	e := newEnv(t, nil)
	_, phone, _, dev := e.claim()
	_ = phone
	dev.send(map[string]any{"type": "no-such-thing"})
	dev.expectError("unknown-type")
	big := strings.Repeat("a", maxFrame+1)
	dev.send(map[string]any{"type": "offer", "sdp": big})
	dev.expectClosed()

	// Message rate limit: bursts beyond 200 close the connection.
	d2 := newDevice("burst")
	d2.connect(e, phone, "")
	for i := 0; i < 260; i++ {
		b, _ := json.Marshal(map[string]any{"type": "no-such-thing"})
		if err := d2.ws.Write(t.Context(), websocket.MessageText, b); err != nil {
			break
		}
	}
	d2.expectClosed()
}
