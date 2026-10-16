package server

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
	"github.com/videoproduction-ctrl/heartfulness-remote/server/internal/store"
)

// Multiple Macs per account (PROTOCOL.md §10).

// pairApproved pairs dev with Mac h, approved by approver (§5, per Mac).
func pairApproved(t *testing.T, h *fakeHost, dev, approver *device) {
	t.Helper()
	reqID, nd, na := pairOnce(t, h, dev, approver)
	sig := proto.Sign(approver.priv, proto.LabelPairApprove, mustB64(t, reqID), h.pub, dev.pub, nd, na, proto.Str(dev.name), proto.Str(dev.kind))
	approver.send(map[string]any{"type": "pair-approve", "hostPub": h.pubB64, "requestId": reqID, "sig": proto.B64(sig)})
	h.expect("pair-approve")
	h.send(map[string]any{"type": "pair-result", "requestId": reqID, "approved": true, "cert": h.cert(dev.pub, dev.name, dev.kind)})
	if pa := dev.expect("pair-approved"); pa["hostPub"] != h.pubB64 {
		t.Fatalf("pair-approved: %v", pa)
	}
	approver.expect("approval-closed")
}

// openSession runs session-request → session-accept between d and Mac h.
func openSession(t *testing.T, h *fakeHost, d *device) string {
	t.Helper()
	sid := proto.B64(randBytes(16))
	d.send(map[string]any{"type": "session-request", "hostPub": h.pubB64, "sessionId": sid, "clientNonce": proto.B64(randBytes(32))})
	if sr := h.expect("session-request"); str(sr, "sessionId") != sid || str(sr, "devicePub") != d.pubB64() {
		t.Fatalf("session-request: %v", sr)
	}
	h.send(map[string]any{"type": "session-accept", "sessionId": sid, "hostNonce": proto.B64(randBytes(32))})
	if acc := d.expect("session-accept"); acc["hostPub"] != h.pubB64 {
		t.Fatalf("session-accept: %v", acc)
	}
	return sid
}

func readyEntry(t *testing.T, ready map[string]any, hostPub string) map[string]any {
	t.Helper()
	for _, x := range ready["hosts"].([]any) {
		if m := x.(map[string]any); m["pub"] == hostPub {
			return m
		}
	}
	t.Fatalf("host %s not in ready: %v", hostPub, ready)
	return nil
}

func meApprovals(t *testing.T, c *client, d *device) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, x := range c.get("/api/me").json(t)["devices"].([]any) {
		m := x.(map[string]any)
		if m["pub"] != d.pubB64() {
			continue
		}
		for _, a := range m["approvals"].([]any) {
			am := a.(map[string]any)
			out[str(am, "hostPub")] = str(am, "status")
		}
	}
	return out
}

func TestTwoMacsOneOwner(t *testing.T) {
	e := newEnv(t, nil)
	// A Mac that is waiting while the server gets claimed by another one
	// becomes a join candidate of the claimed server.
	early := newFakeHost(t)
	if r := early.connect(e, "203.0.113.60", testOrigin, true); r["claimed"] != false {
		t.Fatalf("early host: %v", r)
	}
	hA, phone, authn, phoneDev := e.claim()
	if hr := early.expect("host-ready"); hr["claimed"] != true || hr["joined"] != false || hr["macId"] != early.macID() {
		t.Fatalf("waiting Mac after the claim: %v", hr)
	}

	hB := newJoinHost(t, "Edit Mac")
	e.join(hB, "203.0.113.2", phone.from("198.51.100.11"), phoneDev)

	// /api/me lists both Macs (claim order) and the phone's approval on each.
	me := phone.get("/api/me").json(t)
	hosts := me["hosts"].([]any)
	if len(hosts) != 2 {
		t.Fatalf("me.hosts: %v", hosts)
	}
	for i, h := range []*fakeHost{hA, hB} {
		mh := hosts[i].(map[string]any)
		if mh["pub"] != h.pubB64 || mh["macId"] != h.macID() || mh["name"] != h.name || mh["online"] != true || mh["state"] != "available" || mh["claimedAt"].(float64) == 0 {
			t.Fatalf("me.hosts[%d]: %v", i, mh)
		}
	}
	if ap := meApprovals(t, phone, phoneDev); len(ap) != 2 || ap[hA.pubB64] != "approved" || ap[hB.pubB64] != "approved" {
		t.Fatalf("phone approvals: %v", ap)
	}

	// A new connection's ready lists both Macs with this device's status and cert.
	laptopClient := e.login(authn, "198.51.100.70")
	laptop := newDevice("Laptop")
	ready := laptop.connect(e, laptopClient, "")
	if rh := readyEntry(t, ready, hB.pubB64); rh["deviceStatus"] != "unknown" || rh["online"] != true || rh["name"] != "Edit Mac" {
		t.Fatalf("laptop ready: %v", ready)
	}
	phone2 := newDevice("Phone")
	phone2.pub, phone2.priv = phoneDev.pub, phoneDev.priv
	ready = phone2.connect(e, phone, "")
	for _, h := range []*fakeHost{hA, hB} {
		rh := readyEntry(t, ready, h.pubB64)
		if rh["deviceStatus"] != "approved" || rh["cert"].(map[string]any)["hostPub"] != h.pubB64 || rh["macId"] != h.macID() {
			t.Fatalf("phone ready for %s: %v", h.name, rh)
		}
	}

	// Both Macs are online at once; host-status names the Mac.
	hB.send(map[string]any{"type": "host-status", "state": "blocked"})
	for {
		hs := laptop.expect("host-status")
		if hs["hostPub"] == hB.pubB64 && hs["state"] == "blocked" {
			break
		}
	}
	if info, _ := e.srv.hub.hostInfo(hA.pubB64); info.State != "available" || !info.Online {
		t.Fatalf("Mac A affected by Mac B's status: %+v", info)
	}

	// Sessions with both Macs at the same time, each relayed to the right Mac.
	sidA := openSession(t, hA, phone2)
	sidB := openSession(t, hB, phone2)
	phone2.send(map[string]any{"type": "ice", "sessionId": sidB, "hostPub": hB.pubB64, "candidate": map[string]any{"candidate": "x"}})
	hB.expect("ice")
	hA.expectNone(50 * time.Millisecond)
	// A Mac cannot answer for another Mac's session.
	hB.send(map[string]any{"type": "answer", "sessionId": sidA, "sdp": "v=0", "sig": proto.B64(randBytes(64))})
	hB.expectError("unknown-session")
	// A hostPub that does not match the session's Mac is refused.
	phone2.send(map[string]any{"type": "offer", "sessionId": sidA, "hostPub": hB.pubB64, "sdp": "v=0", "sig": proto.B64(randBytes(64))})
	phone2.expectError("host-mismatch")
	hA.expectNone(50 * time.Millisecond)
	hB.expectNone(50 * time.Millisecond)

	// Mac A reconnecting replaces only its own connection; B's session survives.
	a2 := hA.again()
	if r := a2.connect(e, "203.0.113.1", testOrigin, false); r["joined"] != true {
		t.Fatalf("A reconnect: %v", r)
	}
	hA.expectError("replaced")
	if se := phone2.expect("session-end"); se["sessionId"] != sidA || se["hostPub"] != hA.pubB64 || se["reason"] != "host-reconnected" {
		t.Fatalf("session-end: %v", se)
	}
	phone2.send(map[string]any{"type": "session-end", "sessionId": sidB, "reason": "user"})
	if se := hB.expect("session-end"); se["sessionId"] != sidB {
		t.Fatalf("B session-end: %v", se)
	}

	// The binding is persisted.
	var onDisk store.State
	b, _ := os.ReadFile(e.st.Path())
	if err := json.Unmarshal(b, &onDisk); err != nil || len(onDisk.Hosts) != 2 || onDisk.Hosts[1].Pub != hB.pubB64 || onDisk.Hosts[1].MacID != hB.macID() {
		t.Fatalf("state file: %v %+v", err, onDisk.Hosts)
	}
	// Nothing secret about the join is persisted.
	kc, ka, _ := proto.SetupKeys(hB.setupT)
	for _, secret := range [][]byte{hB.setupT, kc, ka} {
		if containsB64(b, secret) {
			t.Fatal("join secret persisted")
		}
	}
}

func containsB64(b, secret []byte) bool {
	return strings.Contains(string(b), proto.B64(secret)) || strings.Contains(string(b), b64u.EncodeToString(secret))
}

func TestJoinRejected(t *testing.T) {
	e := newEnv(t, nil)
	hA, phone, authn, phoneDev := e.claim()
	hB := newJoinHost(t, "Edit Mac")
	hB.connect(e, "203.0.113.2", testOrigin, true)
	kc, ka, _ := proto.SetupKeys(hB.setupT)
	c := phone.from("198.51.100.20")

	// A signed-in device that is not approved on any Mac cannot look up or join.
	strangerClient := e.login(authn, "198.51.100.21")
	stranger := newDevice("Stranger")
	stranger.connect(e, strangerClient, "")
	if r := strangerClient.get("/api/hosts/pending?macId=" + hB.macID() + "&" + proofQuery(t, strangerClient, stranger)); r.code != http.StatusForbidden || str(r.json(t), "error") != "device-not-approved" {
		t.Fatalf("pending by unapproved device: %d %s", r.code, r.body)
	}
	if r := strangerClient.post("/api/hosts/join/begin", withProof(t, strangerClient, stranger, map[string]any{"hostPub": hB.pubB64, "claim": proto.B64(kc)})); r.code != http.StatusForbidden || str(r.json(t), "error") != "device-not-approved" {
		t.Fatalf("begin by unapproved device: %d %s", r.code, r.body)
	}
	// No session, no proof.
	if r := e.client("198.51.100.22").post("/api/hosts/join/begin", map[string]any{"hostPub": hB.pubB64, "claim": proto.B64(kc)}); r.code != http.StatusUnauthorized {
		t.Fatalf("anonymous begin: %d", r.code)
	}
	if r := c.post("/api/hosts/join/begin", map[string]any{"hostPub": hB.pubB64, "claim": proto.B64(kc)}); r.code != http.StatusBadRequest {
		t.Fatalf("begin without device proof: %d", r.code)
	}
	// Cookie requests need the CSRF header like every other state change.
	if r := c.do(http.MethodPost, "/api/hosts/join/begin", withProof(t, c, phoneDev, map[string]any{"hostPub": hB.pubB64, "claim": proto.B64(kc)}), func(r *http.Request) { r.Header.Del("X-HR") }); r.code != http.StatusForbidden || str(r.json(t), "error") != "csrf" {
		t.Fatalf("begin without X-HR: %d %s", r.code, r.body)
	}

	// The claim must match the waiting Mac's commit; Ka or a guess is an auth failure.
	bad := phone.from("198.51.100.23")
	for _, guess := range [][]byte{ka, randBytes(32)} {
		r := bad.post("/api/hosts/join/begin", withProof(t, bad, phoneDev, map[string]any{"hostPub": hB.pubB64, "claim": proto.B64(guess)}))
		if r.code != http.StatusForbidden || str(r.json(t), "error") != "bad-claim" {
			t.Fatalf("bad claim: %d %s", r.code, r.body)
		}
	}
	if e.failures(bad.ip) != 2 {
		t.Fatalf("bad join claims counted: %d", e.failures(bad.ip))
	}
	// Unknown Mac, or one that is already bound.
	if r := c.post("/api/hosts/join/begin", withProof(t, c, phoneDev, map[string]any{"hostPub": newFakeHost(t).pubB64, "claim": proto.B64(kc)})); r.code != http.StatusNotFound {
		t.Fatalf("begin for unknown Mac: %d", r.code)
	}
	if r := c.post("/api/hosts/join/begin", withProof(t, c, phoneDev, map[string]any{"hostPub": hA.pubB64, "claim": proto.B64(kc)})); r.code != http.StatusConflict || str(r.json(t), "error") != "already-joined" {
		t.Fatalf("begin for bound Mac: %d %s", r.code, r.body)
	}

	// The flow is single-use and bound to the session and device that began it.
	c2 := phone.from("198.51.100.24")
	begin := func(cl *client) string {
		t.Helper()
		r := cl.post("/api/hosts/join/begin", withProof(t, cl, phoneDev, map[string]any{"hostPub": hB.pubB64, "claim": proto.B64(kc)}))
		if r.code != 200 {
			t.Fatalf("begin: %d %s", r.code, r.body)
		}
		return str(r.json(t), "flowId")
	}
	mac := proto.B64(proto.SetupMAC(ka, hB.pub, phoneDev.pub, "Phone", "phone"))
	other := e.login(authn, "198.51.100.25")
	flow := begin(c2)
	if r := other.post("/api/hosts/join/finish", withProof(t, other, phoneDev, map[string]any{"flowId": flow, "setupMac": mac})); r.code != http.StatusBadRequest || str(r.json(t), "error") != "unknown-flow" {
		t.Fatalf("finish from another session: %d %s", r.code, r.body)
	}
	if r := c2.post("/api/hosts/join/finish", withProof(t, c2, phoneDev, map[string]any{"flowId": flow, "setupMac": mac})); r.code != http.StatusBadRequest {
		t.Fatalf("finish with a consumed flow: %d %s", r.code, r.body)
	}
	hB.expectNone(50 * time.Millisecond)

	// Real join/finish: setup-device reaches the Mac with the registered name/kind.
	c3 := phone.from("198.51.100.26")
	flow = begin(c3)
	if r := c3.post("/api/hosts/join/finish", withProof(t, c3, phoneDev, map[string]any{"flowId": flow, "setupMac": mac})); r.code != 200 {
		t.Fatalf("finish: %d %s", r.code, r.body)
	}
	sd := hB.expect("setup-device")
	if str(sd, "devicePub") != phoneDev.pubB64() || str(sd, "name") != "Phone" || str(sd, "kind") != "phone" ||
		!proto.CheckSetupMAC(hB.ka, hB.pub, phoneDev.pub, "Phone", "phone", mustB64(t, str(sd, "setupMac"))) {
		t.Fatalf("setup-device: %v", sd)
	}
	hostMac := proto.B64(proto.HostConfirmMAC(hB.ka, hB.pub, phoneDev.pub))
	notBound := func(what string) {
		t.Helper()
		if _, ok := e.srv.hub.hostInfo(hB.pubB64); ok {
			t.Fatalf("%s: Mac bound", what)
		}
		var n int
		e.st.View(func(st *store.State) { n = len(st.Hosts) })
		if n != 1 || e.status(phoneDev.pubB64(), hB.pubB64) != store.StatusUnknown {
			t.Fatalf("%s: store changed", what)
		}
	}
	// A cert signed by another key (the server cannot be fed a forged binding).
	forged := proto.SignCert(newFakeHost(t).priv, proto.Cert{HostPub: hB.pubB64, DevicePub: phoneDev.pubB64(), Name: "Phone", Kind: "phone", IssuedAt: time.Now().Unix()})
	hB.send(map[string]any{"type": "device-approved", "cert": forged, "hostMac": hostMac})
	hB.expectError("bad-cert")
	notBound("forged cert")
	// A cert from this Mac for another Mac's key.
	wrongHost := proto.SignCert(hB.priv, proto.Cert{HostPub: hA.pubB64, DevicePub: phoneDev.pubB64(), Name: "Phone", Kind: "phone", IssuedAt: time.Now().Unix()})
	hB.send(map[string]any{"type": "device-approved", "cert": wrongHost, "hostMac": hostMac})
	hB.expectError("bad-cert")
	notBound("cert naming another Mac")
	// A genuine cert, but for a device that did not ask to join.
	hB.send(map[string]any{"type": "device-approved", "cert": hB.cert(stranger.pub, "Stranger", "browser"), "hostMac": hostMac})
	hB.expectError("unknown-device")
	notBound("cert for another device")
	// No host confirmation MAC.
	hB.send(map[string]any{"type": "device-approved", "cert": hB.cert(phoneDev.pub, "Phone", "phone")})
	hB.expectError("bad-request")
	notBound("missing hostMac")
	phoneDev.expectNone(50 * time.Millisecond)
	stranger.expectNone(10 * time.Millisecond)

	// The genuine answer binds the Mac.
	hB.send(map[string]any{"type": "device-approved", "cert": hB.cert(phoneDev.pub, "Phone", "phone"), "hostMac": hostMac})
	if hr := hB.expect("host-ready"); hr["joined"] != true {
		t.Fatalf("host-ready: %v", hr)
	}
	if hj := phoneDev.expect("host-joined"); hj["hostPub"] != hB.pubB64 || hj["hostMac"] != hostMac {
		t.Fatalf("host-joined: %v", hj)
	}
	if e.status(phoneDev.pubB64(), hB.pubB64) != store.StatusApproved {
		t.Fatal("phone not approved on the joined Mac")
	}
	// A bound Mac cannot be joined again.
	if r := phone.from("198.51.100.27").post("/api/hosts/join/begin", withProof(t, phone.from("198.51.100.27"), phoneDev, map[string]any{"hostPub": hB.pubB64, "claim": proto.B64(kc)})); r.code != http.StatusConflict {
		t.Fatalf("begin after join: %d", r.code)
	}
}

// A Mac that shows a new code after join/begin does not get the stale flow's
// setup-device (finish reports the Mac as not connected).
func TestJoinStaleCode(t *testing.T) {
	e := newEnv(t, nil)
	_, phone, _, phoneDev := e.claim()
	hB := newJoinHost(t, "Edit Mac")
	hB.connect(e, "203.0.113.2", testOrigin, true)
	kc, ka, _ := proto.SetupKeys(hB.setupT)
	c := phone.from("198.51.100.30")
	r := c.post("/api/hosts/join/begin", withProof(t, c, phoneDev, map[string]any{"hostPub": hB.pubB64, "claim": proto.B64(kc)}))
	if r.code != 200 {
		t.Fatalf("begin: %d %s", r.code, r.body)
	}
	hB.send(map[string]any{"type": "claim-commit", "claimCommit": proto.B64(randBytes(32))})
	time.Sleep(50 * time.Millisecond)
	r = c.post("/api/hosts/join/finish", withProof(t, c, phoneDev, map[string]any{"flowId": str(r.json(t), "flowId"), "setupMac": proto.B64(proto.SetupMAC(ka, hB.pub, phoneDev.pub, "Phone", "phone"))}))
	if r.code != http.StatusConflict || str(r.json(t), "error") != "host-not-connected" {
		t.Fatalf("finish after a new code: %d %s", r.code, r.body)
	}
	hB.expectNone(50 * time.Millisecond)

	// A join finished for the old code cannot complete once the Mac shows a new one.
	hB.send(map[string]any{"type": "claim-commit", "claimCommit": proto.B64(hB.commit)})
	time.Sleep(50 * time.Millisecond)
	c2 := phone.from("198.51.100.31")
	r = c2.post("/api/hosts/join/begin", withProof(t, c2, phoneDev, map[string]any{"hostPub": hB.pubB64, "claim": proto.B64(kc)}))
	r = c2.post("/api/hosts/join/finish", withProof(t, c2, phoneDev, map[string]any{"flowId": str(r.json(t), "flowId"), "setupMac": proto.B64(proto.SetupMAC(ka, hB.pub, phoneDev.pub, "Phone", "phone"))}))
	if r.code != 200 {
		t.Fatalf("finish: %d %s", r.code, r.body)
	}
	hB.expect("setup-device")
	hB.send(map[string]any{"type": "claim-commit", "claimCommit": proto.B64(randBytes(32))})
	hB.send(map[string]any{"type": "device-approved", "cert": hB.cert(phoneDev.pub, "Phone", "phone"), "hostMac": proto.B64(proto.HostConfirmMAC(ka, hB.pub, phoneDev.pub))})
	hB.expectError("not-bound")
	if _, ok := e.srv.hub.hostInfo(hB.pubB64); ok {
		t.Fatal("Mac bound by a join for an old code")
	}
}

func TestPendingLookupByMacID(t *testing.T) {
	e := newEnv(t, nil)
	_, phone, _, phoneDev := e.claim()
	c := phone.from("198.51.100.40")
	lookup := func(cl *client, macID string) resp {
		t.Helper()
		return cl.get("/api/hosts/pending?macId=" + url.QueryEscape(macID) + "&" + proofQuery(t, cl, phoneDev))
	}
	hB := newJoinHost(t, "Edit Mac")
	if r := lookup(c, hB.macID()); r.code != http.StatusNotFound {
		t.Fatalf("no waiting Mac: %d %s", r.code, r.body)
	}
	// A waiting Mac without a join code yet is not offered.
	hB.connect(e, "203.0.113.2", testOrigin, false)
	if r := lookup(c, hB.macID()); r.code != http.StatusNotFound {
		t.Fatalf("Mac without a code: %d %s", r.code, r.body)
	}
	hB.send(map[string]any{"type": "claim-commit", "claimCommit": proto.B64(hB.commit)})
	time.Sleep(50 * time.Millisecond)
	for _, typed := range []string{hB.macID(), proto.FormatMacID(hB.macID()), hB.macID()[:3] + "-" + hB.macID()[3:6] + "-" + hB.macID()[6:]} {
		r := lookup(c, typed)
		if r.code != 200 {
			t.Fatalf("lookup %q: %d %s", typed, r.code, r.body)
		}
		if m := r.json(t); m["hostPub"] != hB.pubB64 || m["name"] != "Edit Mac" || len(m) != 2 {
			t.Fatalf("lookup %q: %v", typed, m)
		}
	}
	c2 := phone.from("198.51.100.41")
	for _, typed := range []string{"12345", "abcdefghi", "1234567890", ""} {
		if r := lookup(c2, typed); r.code != http.StatusBadRequest {
			t.Fatalf("malformed Mac ID %q: %d", typed, r.code)
		}
	}
	// The device proof is required (a GET carries it in the query).
	if r := c2.get("/api/hosts/pending?macId=" + hB.macID()); r.code != http.StatusBadRequest {
		t.Fatalf("lookup without proof: %d", r.code)
	}
	if r := e.client("198.51.100.42").get("/api/hosts/pending?macId=" + hB.macID()); r.code != http.StatusUnauthorized {
		t.Fatalf("anonymous lookup: %d", r.code)
	}
	// Two waiting Macs with the same Mac ID (an attacker can grind one): ambiguous.
	hC := newJoinHost(t, "Look-alike")
	hC.connect(e, "203.0.113.3", testOrigin, true)
	e.srv.hub.mu.Lock()
	e.srv.hub.pendingHosts[hC.pubB64].macID = hB.macID()
	e.srv.hub.mu.Unlock()
	if r := lookup(c2, hB.macID()); r.code != http.StatusConflict || str(r.json(t), "error") != "ambiguous" {
		t.Fatalf("ambiguous Mac ID: %d %s", r.code, r.body)
	}
	// The lookup is in the auth rate-limit class (10/min per IP).
	c3 := phone.from("198.51.100.43")
	limited := false
	for i := 0; i < 12 && !limited; i++ {
		limited = c3.get("/api/hosts/pending?macId="+hB.macID()).code == http.StatusTooManyRequests
	}
	if !limited {
		t.Fatal("hosts/pending is not rate-limited like the auth endpoints")
	}
}

// A device approved on Mac A but not on Mac B cannot start a session with,
// approve pairings for, or send revoke/kill requests to B; approval requests
// for B reach only devices approved on B.
func TestPerMacAuthorization(t *testing.T) {
	e := newEnv(t, nil)
	hA, phone, authn, phoneDev := e.claim()
	hB := newJoinHost(t, "Edit Mac")
	e.join(hB, "203.0.113.2", phone.from("198.51.100.11"), phoneDev)

	laptopClient := e.login(authn, "198.51.100.70")
	laptop := newDevice("Laptop")
	laptop.connect(e, laptopClient, "")
	pairApproved(t, hA, laptop, phoneDev)
	if e.status(laptop.pubB64(), hA.pubB64) != store.StatusApproved || e.status(laptop.pubB64(), hB.pubB64) != store.StatusUnknown {
		t.Fatal("laptop should be approved on A only")
	}

	ts := time.Now().Unix()
	laptop.send(map[string]any{"type": "session-request", "hostPub": hB.pubB64, "sessionId": proto.B64(randBytes(16)), "clientNonce": proto.B64(randBytes(32))})
	if er := laptop.expectError("not-approved"); er["hostPub"] != hB.pubB64 {
		t.Fatalf("error: %v", er)
	}
	laptop.send(map[string]any{"type": "kill-request", "hostPub": hB.pubB64, "action": "kill", "ts": ts,
		"sig": proto.B64(proto.Sign(laptop.priv, proto.LabelKillRequest, hB.pub, proto.Str("kill"), proto.Int(ts)))})
	laptop.expectError("not-approved")
	laptop.send(map[string]any{"type": "revoke-request", "hostPub": hB.pubB64, "targetPub": phoneDev.pubB64(), "ts": ts,
		"sig": proto.B64(proto.Sign(laptop.priv, proto.LabelRevokeRequest, hB.pub, phoneDev.pub, proto.Int(ts)))})
	laptop.expectError("not-approved")
	hB.expectNone(50 * time.Millisecond)
	// …while the same requests to A go through.
	openSession(t, hA, laptop)
	laptop.send(map[string]any{"type": "kill-request", "hostPub": hA.pubB64, "action": "kill", "ts": ts,
		"sig": proto.B64(proto.Sign(laptop.priv, proto.LabelKillRequest, hA.pub, proto.Str("kill"), proto.Int(ts)))})
	hA.expect("kill-request")
	// A signature over A's key does not work for B (and the reverse).
	laptop.send(map[string]any{"type": "kill-request", "hostPub": hA.pubB64, "action": "kill", "ts": ts,
		"sig": proto.B64(proto.Sign(laptop.priv, proto.LabelKillRequest, hB.pub, proto.Str("kill"), proto.Int(ts)))})
	laptop.expectError("bad-signature")

	// A tablet pairs with B: only devices approved on B are asked.
	tabletClient := e.login(authn, "198.51.100.71")
	tablet := newDevice("Tablet")
	tablet.connect(e, tabletClient, "")
	reqID, nd, na := pairOnce(t, hB, tablet, phoneDev)
	laptop.expectNone(100 * time.Millisecond)
	// A reconnecting client gets pending approvals only for its Macs.
	laptop2 := newDevice("Laptop")
	laptop2.pub, laptop2.priv = laptop.pub, laptop.priv
	laptop2.connect(e, laptopClient, "")
	laptop2.expectNone(50 * time.Millisecond)
	phone2 := newDevice("Phone")
	phone2.pub, phone2.priv = phoneDev.pub, phoneDev.priv
	phone2.connect(e, phone, "")
	if an := phone2.expect("approval-needed"); an["requestId"] != reqID || an["hostPub"] != hB.pubB64 {
		t.Fatalf("approval-needed on reconnect: %v", an)
	}

	approveSig := func(d *device, hostPub []byte) string {
		return proto.B64(proto.Sign(d.priv, proto.LabelPairApprove, mustB64(t, reqID), hostPub, tablet.pub, nd, na, proto.Str(tablet.name), proto.Str(tablet.kind)))
	}
	laptop.send(map[string]any{"type": "pair-approve", "hostPub": hB.pubB64, "requestId": reqID, "sig": approveSig(laptop, hB.pub)})
	laptop.expectError("not-approved")
	laptop.send(map[string]any{"type": "pair-approve", "hostPub": hA.pubB64, "requestId": reqID, "sig": approveSig(laptop, hA.pub)})
	laptop.expectError("host-mismatch")
	laptop.send(map[string]any{"type": "pair-deny", "hostPub": hB.pubB64, "requestId": reqID})
	laptop.expectError("not-approved")
	laptop.send(map[string]any{"type": "pair-deny", "hostPub": hA.pubB64, "requestId": reqID})
	laptop.expectError("host-mismatch")
	hA.expectNone(50 * time.Millisecond)
	hB.expectNone(10 * time.Millisecond)
	// Mac A cannot answer B's pairing.
	hA.send(map[string]any{"type": "pair-result", "requestId": reqID, "approved": true, "cert": hA.cert(tablet.pub, "Tablet", "browser")})
	hA.expectError("unknown-request")
	// The phone (approved on B) approves; only B hears about it.
	phoneDev.send(map[string]any{"type": "pair-approve", "hostPub": hB.pubB64, "requestId": reqID, "sig": approveSig(phoneDev, hB.pub)})
	if ap := hB.expect("pair-approve"); ap["approverPub"] != phoneDev.pubB64() {
		t.Fatalf("pair-approve: %v", ap)
	}
	hA.expectNone(50 * time.Millisecond)
	hB.send(map[string]any{"type": "pair-result", "requestId": reqID, "approved": true, "cert": hB.cert(tablet.pub, "Tablet", "browser")})
	if pa := tablet.expect("pair-approved"); pa["hostPub"] != hB.pubB64 {
		t.Fatalf("pair-approved: %v", pa)
	}
	if ap := meApprovals(t, phone.from("198.51.100.12"), tablet); len(ap) != 1 || ap[hB.pubB64] != "approved" {
		t.Fatalf("tablet approvals: %v", ap)
	}
	// Pairing state is per (device, Mac): the tablet may now pair with A too.
	pairApproved(t, hA, tablet, laptop)
	if ap := meApprovals(t, phone.from("198.51.100.13"), tablet); len(ap) != 2 || ap[hA.pubB64] != "approved" || ap[hB.pubB64] != "approved" {
		t.Fatalf("tablet approvals after pairing with A: %v", ap)
	}
	tablet.send(map[string]any{"type": "pair-start", "hostPub": hA.pubB64, "name": "Tablet", "kind": "browser", "commit": proto.B64(randBytes(32))})
	tablet.expectError("already-approved")
}

// trust-sync, device-revoked and certs from one Mac only change approvals for
// that Mac.
func TestTrustSyncPerMac(t *testing.T) {
	e := newEnv(t, nil)
	hA, phone, _, phoneDev := e.claim()
	hB := newJoinHost(t, "Edit Mac")
	e.join(hB, "203.0.113.2", phone.from("198.51.100.11"), phoneDev)
	sidA := openSession(t, hA, phoneDev)
	sidB := openSession(t, hB, phoneDev)

	// B's pins no longer include the phone: revoked on B only, B's session ends.
	only := newDevice("Only on B")
	hB.send(map[string]any{"type": "trust-sync", "certs": []proto.Cert{hB.cert(only.pub, "Only on B", "browser")}, "revocations": []proto.Revocation{}})
	if se := phoneDev.expect("session-end"); se["sessionId"] != sidB || se["hostPub"] != hB.pubB64 || se["reason"] != "revoked" {
		t.Fatalf("session-end: %v", se)
	}
	if se := hB.expect("session-end"); se["sessionId"] != sidB {
		t.Fatalf("B session-end: %v", se)
	}
	hA.expectNone(50 * time.Millisecond)
	if e.status(phoneDev.pubB64(), hB.pubB64) != store.StatusRevoked || e.status(phoneDev.pubB64(), hA.pubB64) != store.StatusApproved {
		t.Fatal("trust-sync from B changed approvals outside B")
	}
	if e.status(only.pubB64(), hB.pubB64) != store.StatusApproved || e.status(only.pubB64(), hA.pubB64) != store.StatusUnknown {
		t.Fatal("device certified by B only")
	}
	// The session with A is untouched.
	phoneDev.send(map[string]any{"type": "ice", "sessionId": sidA, "hostPub": hA.pubB64, "candidate": nil})
	hA.expect("ice")

	// A's trust-sync never touches B's approvals (a device unknown to A stays approved on B).
	hA.send(map[string]any{"type": "trust-sync", "certs": []proto.Cert{hA.certsOK[phoneDev.pubB64()]}, "revocations": []proto.Revocation{}})
	time.Sleep(50 * time.Millisecond)
	if e.status(only.pubB64(), hB.pubB64) != store.StatusApproved || e.status(phoneDev.pubB64(), hA.pubB64) != store.StatusApproved {
		t.Fatal("trust-sync from A changed B's approvals")
	}

	// B re-certifies the phone.
	hB.send(map[string]any{"type": "trust-sync", "certs": []proto.Cert{hB.cert(phoneDev.pub, "Phone", "phone"), hB.certsOK[only.pubB64()]}, "revocations": []proto.Revocation{}})
	waitFor(t, func() bool { return e.status(phoneDev.pubB64(), hB.pubB64) == store.StatusApproved })

	// device-revoked from A revokes on A only.
	rev := proto.Revocation{HostPub: hA.pubB64, DevicePub: phoneDev.pubB64(), RevokedAt: time.Now().Unix()}
	rev.Sig = proto.B64(proto.Sign(hA.priv, proto.LabelRevoked, hA.pub, phoneDev.pub, proto.Int(rev.RevokedAt)))
	hA.send(map[string]any{"type": "device-revoked", "revocation": rev})
	if se := phoneDev.expect("session-end"); se["sessionId"] != sidA || se["reason"] != "revoked" {
		t.Fatalf("session-end on A revocation: %v", se)
	}
	if se := hA.expect("session-end"); se["sessionId"] != sidA {
		t.Fatalf("A session-end on revocation: %v", se)
	}
	hB.expectNone(50 * time.Millisecond)
	waitFor(t, func() bool { return e.status(phoneDev.pubB64(), hA.pubB64) == store.StatusRevoked })
	if e.status(phoneDev.pubB64(), hB.pubB64) != store.StatusApproved {
		t.Fatal("revocation by A changed B")
	}
	// A revocation signed by B for A's key is refused by A's connection.
	rev.Sig = proto.B64(proto.Sign(hB.priv, proto.LabelRevoked, hA.pub, phoneDev.pub, proto.Int(rev.RevokedAt)))
	hA.send(map[string]any{"type": "device-revoked", "revocation": rev})
	hA.expectError("bad-revocation")
	// The phone, still approved on B, can manage things (device proof works).
	if r := phone.from("198.51.100.14").get("/api/hosts/pending?macId=000000000&" + proofQuery(t, phone.from("198.51.100.14"), phoneDev)); r.code != http.StatusNotFound {
		t.Fatalf("device proof by a device approved on B only: %d %s", r.code, r.body)
	}
}

func TestRemoveMac(t *testing.T) {
	e := newEnv(t, nil)
	hA, phone, _, phoneDev := e.claim()
	hB := newJoinHost(t, "Edit Mac")
	e.join(hB, "203.0.113.2", phone.from("198.51.100.11"), phoneDev)
	only := newDevice("Only on B")
	hB.send(map[string]any{"type": "trust-sync", "certs": []proto.Cert{hB.certsOK[phoneDev.pubB64()], hB.cert(only.pub, "Only on B", "browser")}, "revocations": []proto.Revocation{}})
	waitFor(t, func() bool { return e.status(only.pubB64(), hB.pubB64) == store.StatusApproved })
	sid := openSession(t, hB, phoneDev)

	c := phone.from("198.51.100.50")
	if r := c.post("/api/hosts/remove", map[string]any{"hostPub": hB.pubB64}); r.code != http.StatusBadRequest {
		t.Fatalf("remove without proof: %d", r.code)
	}
	if r := c.post("/api/hosts/remove", withProof(t, c, phoneDev, map[string]any{"hostPub": hB.pubB64})); r.code != 200 {
		t.Fatalf("remove: %d %s", r.code, r.body)
	}
	hB.expectError("removed")
	hB.expectClosed()
	if se := phoneDev.expect("session-end"); se["sessionId"] != sid || se["hostPub"] != hB.pubB64 || se["reason"] != "host-removed" {
		t.Fatalf("session-end: %v", se)
	}
	me := phone.get("/api/me").json(t)
	if hosts := me["hosts"].([]any); len(hosts) != 1 || hosts[0].(map[string]any)["pub"] != hA.pubB64 {
		t.Fatalf("hosts after removal: %v", hosts)
	}
	if ap := meApprovals(t, phone, phoneDev); len(ap) != 1 || ap[hA.pubB64] != "approved" {
		t.Fatalf("phone approvals after removal: %v", ap)
	}
	for _, d := range me["devices"].([]any) {
		if d.(map[string]any)["pub"] == only.pubB64() {
			t.Fatal("device approved only on the removed Mac is still listed")
		}
	}
	var events int
	e.st.View(func(st *store.State) {
		for _, ev := range st.Events {
			if ev.Type == "mac-removed" {
				events++
			}
		}
	})
	if events != 1 {
		t.Fatalf("mac-removed events: %d", events)
	}
	// Removed is gone; the last Mac cannot be removed.
	c2 := phone.from("198.51.100.51")
	if r := c2.post("/api/hosts/remove", withProof(t, c2, phoneDev, map[string]any{"hostPub": hB.pubB64})); r.code != http.StatusNotFound {
		t.Fatalf("remove twice: %d", r.code)
	}
	if r := c2.post("/api/hosts/remove", withProof(t, c2, phoneDev, map[string]any{"hostPub": hA.pubB64})); r.code != http.StatusConflict || str(r.json(t), "error") != "last-host" {
		t.Fatalf("remove last Mac: %d %s", r.code, r.body)
	}
	// Messages to the removed Mac are refused; the remaining one works.
	phoneDev.send(map[string]any{"type": "session-request", "hostPub": hB.pubB64, "sessionId": proto.B64(randBytes(16)), "clientNonce": proto.B64(randBytes(32))})
	phoneDev.expectError("unknown-host")
	openSession(t, hA, phoneDev)
	// The removed Mac reconnecting waits to join again.
	b2 := hB.again()
	if r := b2.connect(e, "203.0.113.2", testOrigin, true); r["type"] != "host-ready" || r["claimed"] != true || r["joined"] != false {
		t.Fatalf("removed Mac reconnect: %v", r)
	}
}

func TestMaxMacs(t *testing.T) {
	e := newEnv(t, nil)
	_, phone, _, phoneDev := e.claim()
	fill := func(n int) {
		t.Helper()
		if err := e.st.Update(func(st *store.State) error {
			for len(st.Hosts) < n {
				pub, _, _ := ed25519.GenerateKey(nil)
				if err := st.AddHost(store.HostBinding{Pub: proto.B64(pub), Name: "Mac", ClaimedAt: time.Now()}); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	// 19 Macs: one more may join (begin + finish), but if the account fills up
	// before the Mac answers, the binding is refused.
	fill(store.MaxHosts - 1)
	hB := newJoinHost(t, "Edit Mac")
	hB.connect(e, "203.0.113.2", testOrigin, true)
	kc, ka, _ := proto.SetupKeys(hB.setupT)
	c := phone.from("198.51.100.60")
	r := c.post("/api/hosts/join/begin", withProof(t, c, phoneDev, map[string]any{"hostPub": hB.pubB64, "claim": proto.B64(kc)}))
	if r.code != 200 {
		t.Fatalf("begin at 19 Macs: %d %s", r.code, r.body)
	}
	r = c.post("/api/hosts/join/finish", withProof(t, c, phoneDev, map[string]any{"flowId": str(r.json(t), "flowId"), "setupMac": proto.B64(proto.SetupMAC(ka, hB.pub, phoneDev.pub, "Phone", "phone"))}))
	if r.code != 200 {
		t.Fatalf("finish at 19 Macs: %d %s", r.code, r.body)
	}
	fill(store.MaxHosts)
	hB.answerSetup(t)
	hB.expectError("too-many-hosts")
	if er := phoneDev.expectError("too-many-hosts"); er["hostPub"] != hB.pubB64 {
		t.Fatalf("device error: %v", er)
	}
	if _, ok := e.srv.hub.hostInfo(hB.pubB64); ok {
		t.Fatal("21st Mac bound")
	}
	// At 20 Macs, join/begin is refused up front.
	c2 := phone.from("198.51.100.61")
	if r := c2.post("/api/hosts/join/begin", withProof(t, c2, phoneDev, map[string]any{"hostPub": hB.pubB64, "claim": proto.B64(kc)})); r.code != http.StatusConflict || str(r.json(t), "error") != "too-many-hosts" {
		t.Fatalf("begin at 20 Macs: %d %s", r.code, r.body)
	}
	if n := len(phone.get("/api/me").json(t)["hosts"].([]any)); n != store.MaxHosts {
		t.Fatalf("hosts: %d", n)
	}
}

func TestWaitingMacLimits(t *testing.T) {
	e := newEnv(t, nil)
	e.claim()
	// At most 5 waiting Macs (2 per IP).
	var waiting []*fakeHost
	for i := 0; i < 5; i++ {
		h := newJoinHost(t, "Mac")
		if r := h.connect(e, "203.0.113."+string(rune('2'+i/2)), testOrigin, true); r["type"] != "host-ready" {
			t.Fatalf("waiting Mac %d: %v", i, r)
		}
		waiting = append(waiting, h)
	}
	if r := newJoinHost(t, "Mac").connect(e, "203.0.113.9", testOrigin, true); r["code"] != "too-many-pending" {
		t.Fatalf("sixth waiting Mac: %v", r)
	}
	// They are dropped after 30 minutes.
	e.clock.advance(29 * time.Minute)
	e.srv.housekeeping()
	waiting[0].expectNone(50 * time.Millisecond)
	e.clock.advance(2 * time.Minute)
	e.srv.housekeeping()
	for _, h := range waiting {
		h.expectError("join-expired")
		h.expectClosed()
	}
	if r := newJoinHost(t, "Mac").connect(e, "203.0.113.9", testOrigin, true); r["type"] != "host-ready" {
		t.Fatalf("waiting Mac after expiry: %v", r)
	}
}

// A single-Mac (HR1) state.json keeps working after the upgrade: the Mac is
// still bound and the phone still approved on it.
func TestServeMigratedSingleMacState(t *testing.T) {
	e := newEnv(t, nil)
	h, _, authn, phoneDev := e.claim()
	var st map[string]any
	b, _ := os.ReadFile(e.st.Path())
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	host := st["hosts"].([]any)[0].(map[string]any)
	delete(host, "macId")
	delete(host, "lastSeen")
	st["host"], st["version"] = host, 1
	delete(st, "hosts")
	for _, d := range st["devices"].(map[string]any) {
		dm := d.(map[string]any)
		ap := dm["approvals"].(map[string]any)[h.pubB64].(map[string]any)
		dm["status"] = ap["status"]
		if ct := ap["cert"]; ct != nil {
			dm["cert"] = ct
		}
		delete(dm, "approvals")
	}
	v1, _ := json.MarshalIndent(st, "", " ")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "state.json"), v1, 0o600); err != nil {
		t.Fatal(err)
	}
	e2 := newEnv(t, map[string]string{"HR_DATA_DIR": dir})
	if r := h.again().connect(e2, "203.0.113.1", testOrigin, false); r["type"] != "host-ready" || r["claimed"] != true || r["joined"] != true || r["macId"] != h.macID() {
		t.Fatalf("Mac after migration: %v", r)
	}
	phone := e2.login(authn, "198.51.100.80")
	d := newDevice("Phone")
	d.pub, d.priv = phoneDev.pub, phoneDev.priv
	ready := d.connect(e2, phone, "")
	if rh := readyEntry(t, ready, h.pubB64); rh["deviceStatus"] != "approved" || rh["cert"] == nil || rh["name"] != "Studio Mac" {
		t.Fatalf("ready after migration: %v", ready)
	}
	if ap := meApprovals(t, phone, d); len(ap) != 1 || ap[h.pubB64] != "approved" {
		t.Fatalf("approvals after migration: %v", ap)
	}
}
