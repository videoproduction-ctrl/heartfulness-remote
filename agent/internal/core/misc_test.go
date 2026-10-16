package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIdleTimeout(t *testing.T) {
	e := newEnv(t, true, func(c *Config, _ *Options) { c.Settings.IdleTimeoutMin = 2 })
	dev := e.pin(t, "Phone", "browser")
	sid, _ := sessionRequest(e, dev)
	e.srv.next(t, "session-accept", time.Second)
	// Pretend the peer connection came up (no pion needed for the timer).
	e.a.call(func() {
		s := e.a.sess
		s.state, s.connectedAt = sessConnected, e.clock.now()
		s.lastInput.Store(e.clock.now().UnixNano())
		s.live.Store(true)
	})
	tick := func(d time.Duration) {
		e.clock.add(d)
		time.Sleep(700 * time.Millisecond) // > one loop tick
		e.sync()
	}
	tick(30 * time.Second)
	if e.host.hasEvent("idle-warning") {
		t.Fatal("warned too early")
	}
	tick(31 * time.Second) // idle 61 s of 120 s → T-60 warning
	if !e.host.hasEvent("idle-warning") {
		t.Fatal("no idle warning at T-60s")
	}
	// Input resets the timer.
	e.a.call(func() { e.a.sess.lastInput.Store(e.clock.now().UnixNano()) })
	tick(70 * time.Second)
	e.srv.none(t, "session-end", 50*time.Millisecond)
	tick(51 * time.Second)
	m := e.srv.next(t, "session-end", 2*time.Second)
	if m["sessionId"] != b64(sid) || m["reason"] != "idle" {
		t.Fatalf("got %v", m["_raw"])
	}
	if !e.host.hasEvent("session-end") || len(e.host.encoderCmds("stop")) != 1 {
		t.Fatal("session-end event / ENCODER stop missing")
	}
}

func TestBitrateModes(t *testing.T) {
	h := newFakeHost()
	s := &Session{a: &Agent{io: h}, settingMax: 40000, mode: "auto"}
	check := func(bps int, wantK, wantF int) {
		t.Helper()
		s.bmu.Lock()
		s.targetBps = bps
		s.bmu.Unlock()
		s.updateBitrate()
		k, f := s.desiredEncoder()
		if k != wantK || f != wantF {
			t.Fatalf("target %d: got %d kbps @%d, want %d @%d", bps, k, f, wantK, wantF)
		}
	}
	check(0, initialKbps, 60)
	check(3_000_000, 3000, 30)
	check(5_000_000, 5000, 30) // hysteresis band keeps 30
	check(7_000_000, 7000, 60)
	check(5_000_000, 5000, 60) // …and keeps 60 on the way down
	check(100_000, MinKbps, 30)
	check(100_000_000, 40000, 60)
	s.mode = "smooth"
	check(2_000_000, 2000, 60)
	s.mode = "sharp"
	check(20_000_000, 20000, 30)
	s.clientMax = 5000
	check(20_000_000, 5000, 30)
	s.setMaxKbps(3000)
	check(20_000_000, 3000, 30)
	// Small changes are not re-sent.
	n := len(h.encoderCmds("bitrate"))
	check(2_990_000, 2990, 30)
	if len(h.encoderCmds("bitrate")) != n {
		t.Fatal("tiny change emitted")
	}
}

func TestResetAfterTamper(t *testing.T) {
	e := newEnv(t, true)
	e.pin(t, "Phone", "browser")
	// reset on a healthy store is refused.
	e.cmd(map[string]any{"cmd": "reset-trust-store"})
	if len(e.host.lastState().Devices) != 1 {
		t.Fatal("healthy store reset")
	}
	e.a.Stop()
	p := filepath.Join(e.dir, "pins.json")
	b, _ := os.ReadFile(p)
	_ = os.WriteFile(p, []byte(strings.Replace(string(b), "Phone", "Phony", 1)), 0o600)

	h := newFakeHost()
	h.priv = e.host.priv
	a2 := New(h, Options{NoSignaling: true, HomeDir: e.home})
	if err := a2.Start(t.Context(), Config{ServerURL: testOrigin, HostPub: b64(e.host.pub()), DataDir: e.dir, StorageKey: e.a.cfg.StorageKey}); err != nil {
		t.Fatal(err)
	}
	defer a2.Stop()
	a2.call(a2.flushState)
	if h.lastState().ServerError != "trust-store-tampered" {
		t.Fatalf("state %+v", h.lastState())
	}
	a2.OnCommand([]byte(`{"cmd":"reset-trust-store"}`))
	a2.call(a2.flushState)
	st := h.lastState()
	if st.ServerError != "" || len(st.Devices) != 0 {
		t.Fatalf("after reset %+v", st)
	}
	var quarantined int
	ents, _ := os.ReadDir(e.dir)
	for _, en := range ents {
		if strings.Contains(en.Name(), ".quarantined-") {
			quarantined++
		}
	}
	if quarantined != 2 {
		t.Fatalf("evidence not kept: %v", ents)
	}
	// Fresh setup code exists again.
	msg, _ := a2.HostAuth(t.Context(), testOrigin, randBytes(32))
	if msg.(hostAuthMsg).ClaimCommit == "" {
		t.Fatal("no setup code after reset")
	}
	// The new log verifies.
	a2.OnCommand([]byte(`{"cmd":"log-read"}`))
	a2.call(func() {})
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.logs[len(h.logs)-1].Verified {
		t.Fatalf("log after reset: %s", h.logs[len(h.logs)-1].Error)
	}
}
