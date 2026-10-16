package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func checkSecurityHeaders(t *testing.T, r resp, hsts bool) {
	t.Helper()
	want := map[string]string{
		"Content-Security-Policy":      ContentSecurityPolicy,
		"X-Content-Type-Options":       "nosniff",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
	}
	for k, v := range want {
		if got := r.hdr.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	csp := r.hdr.Get("Content-Security-Policy")
	for _, d := range []string{"require-trusted-types-for 'script'", "trusted-types 'none'", "default-src 'none'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, d) {
			t.Errorf("CSP missing %q", d)
		}
	}
	pp := r.hdr.Get("Permissions-Policy")
	for _, d := range []string{"camera=()", "microphone=()", "geolocation=()", "payment=()", "usb=()", "fullscreen=(self)", "clipboard-read=(self)", "clipboard-write=(self)", "keyboard-map=(self)"} {
		if !strings.Contains(pp, d) {
			t.Errorf("Permissions-Policy missing %q", d)
		}
	}
	if got := r.hdr.Get("Strict-Transport-Security"); (got != "") != hsts {
		t.Errorf("HSTS = %q, want present=%v", got, hsts)
	}
}

func TestSecurityHeadersEverywhere(t *testing.T) {
	e := newEnv(t, nil)
	c := e.client("198.51.100.1")
	for _, p := range []string{"/healthz", "/api/status", "/", "/missing.js", "/api/nope", "/devices"} {
		checkSecurityHeaders(t, c.get(p), false)
	}
	checkSecurityHeaders(t, c.post("/api/logout", nil), false) // 401
	checkSecurityHeaders(t, c.do(http.MethodPost, "/api/logout", nil, func(r *http.Request) { r.Header.Del("X-HR") }), false)

	https := newEnv(t, map[string]string{"HR_ORIGIN": "https://remote.example.org"})
	r := https.client("198.51.100.1").get("/healthz")
	checkSecurityHeaders(t, r, true)
	if !strings.Contains(r.hdr.Get("Strict-Transport-Security"), "max-age=") {
		t.Fatal("HSTS max-age")
	}
}

func TestHealthAndStatus(t *testing.T) {
	e := newEnv(t, nil)
	c := e.client("198.51.100.1")
	if r := c.get("/healthz"); r.code != 200 || r.json(t)["ok"] != true {
		t.Fatalf("healthz: %d %s", r.code, r.body)
	}
	m := c.get("/api/status").json(t)
	if m["claimed"] != false || m["rpId"] != "localhost" || m["origin"] != testOrigin {
		t.Fatalf("status: %v", m)
	}
	if r := c.get("/api/status"); r.hdr.Get("Cache-Control") != "no-store" {
		t.Fatal("API responses must not be cached")
	}
}

func TestStaticFiles(t *testing.T) {
	e := newEnv(t, nil)
	c := e.client("198.51.100.1")
	cases := []struct {
		path, ctype, cache string
		code               int
	}{
		{"/", "text/html; charset=utf-8", "no-cache", 200},
		{"/index.html", "text/html; charset=utf-8", "no-cache", 200},
		{"/app-3F2A9C1B.js", "text/javascript; charset=utf-8", "public, max-age=31536000, immutable", 200},
		{"/style.css", "text/css; charset=utf-8", "no-cache", 200},
		{"/manifest.webmanifest", "application/manifest+json", "no-cache", 200},
		{"/icons/icon.svg", "image/svg+xml", "no-cache", 200},
		{"/devices", "text/html; charset=utf-8", "no-cache", 200},        // SPA fallback
		{"/session/abc", "text/html; charset=utf-8", "no-cache", 200},    // SPA fallback
		{"/missing.js", "", "", 404},                                     // has an extension: no fallback
		{"/.env", "", "", 404},                                           // dotfiles never served
		{"/api/unknown", "application/json; charset=utf-8", "no-store", 404}, // no fallback for /api
		{"/ws/unknown", "application/json; charset=utf-8", "", 404},
	}
	for _, tc := range cases {
		r := c.get(tc.path)
		if r.code != tc.code {
			t.Errorf("%s: code %d want %d", tc.path, r.code, tc.code)
			continue
		}
		if tc.ctype != "" && r.hdr.Get("Content-Type") != tc.ctype {
			t.Errorf("%s: content-type %q", tc.path, r.hdr.Get("Content-Type"))
		}
		if tc.cache != "" && r.hdr.Get("Cache-Control") != tc.cache {
			t.Errorf("%s: cache-control %q", tc.path, r.hdr.Get("Cache-Control"))
		}
	}
	if r := c.post("/index.html", nil); r.code != http.StatusMethodNotAllowed {
		t.Errorf("POST static: %d", r.code)
	}
	etag := c.get("/style.css").hdr.Get("ETag")
	if r := c.do(http.MethodGet, "/style.css", nil, func(r *http.Request) { r.Header.Set("If-None-Match", etag) }); r.code != http.StatusNotModified {
		t.Errorf("conditional GET: %d", r.code)
	}
	if isHashedAsset("app-settings.js") || !isHashedAsset("chunk-AB12CD34.css") {
		t.Error("hashed asset detection")
	}
}

func TestCSRF(t *testing.T) {
	e := newEnv(t, nil)
	_, phone, _, _ := e.claim()
	noXHR := func(r *http.Request) { r.Header.Del("X-HR") }
	if r := phone.do(http.MethodPost, "/api/turn", nil, noXHR); r.code != http.StatusForbidden || r.json(t)["error"] != "csrf" {
		t.Fatalf("missing X-HR: %d %s", r.code, r.body)
	}
	evil := func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }
	if r := phone.do(http.MethodPost, "/api/turn", nil, evil); r.code != http.StatusForbidden {
		t.Fatalf("foreign origin: %d", r.code)
	}
	noOrigin := func(r *http.Request) { r.Header.Del("Origin") }
	if r := phone.do(http.MethodPost, "/api/turn", nil, noOrigin); r.code != http.StatusForbidden {
		t.Fatalf("missing origin: %d", r.code)
	}
	if r := phone.post("/api/turn", nil); r.code != 200 {
		t.Fatalf("legit request: %d %s", r.code, r.body)
	}
	// Unauthenticated browser endpoints are protected the same way.
	if r := e.client("198.51.100.77").do(http.MethodPost, "/api/login/begin", nil, noXHR); r.code != http.StatusForbidden {
		t.Fatalf("login/begin without X-HR: %d", r.code)
	}
	// Cookies are never honoured for requests from another origin, even GETs.
	if r := phone.do(http.MethodGet, "/api/me", nil, func(r *http.Request) { r.Header.Set("Origin", tauri) }); r.code != http.StatusUnauthorized {
		t.Fatalf("cookie from Tauri origin: %d", r.code)
	}
}

func TestCORS(t *testing.T) {
	e := newEnv(t, nil)
	c := e.client("198.51.100.1")
	for _, o := range []string{"tauri://localhost", "http://tauri.localhost", "https://tauri.localhost"} {
		r := c.do(http.MethodOptions, "/api/me", nil, func(r *http.Request) {
			r.Header.Set("Origin", o)
			r.Header.Set("Access-Control-Request-Method", "GET")
			r.Header.Set("Access-Control-Request-Headers", "authorization")
		})
		if r.code != http.StatusNoContent || r.hdr.Get("Access-Control-Allow-Origin") != o {
			t.Fatalf("preflight %s: %d %v", o, r.code, r.hdr)
		}
		if r.hdr.Get("Access-Control-Allow-Credentials") != "" {
			t.Fatal("credentials must never be allowed")
		}
		if !strings.Contains(r.hdr.Get("Access-Control-Allow-Headers"), "Authorization") {
			t.Fatal("Authorization header not allowed")
		}
	}
	r := c.do(http.MethodOptions, "/api/me", nil, func(r *http.Request) {
		r.Header.Set("Origin", "https://evil.example")
		r.Header.Set("Access-Control-Request-Method", "GET")
	})
	if r.code != http.StatusForbidden || r.hdr.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("foreign preflight: %d %v", r.code, r.hdr)
	}
	r = c.do(http.MethodGet, "/api/status", nil, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") })
	if r.hdr.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("ACAO for foreign origin")
	}
	r = c.do(http.MethodGet, "/api/status", nil, func(r *http.Request) { r.Header.Set("Origin", testOrigin) })
	if r.hdr.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("same-origin requests need no CORS")
	}
	r = c.do(http.MethodGet, "/api/status", nil, func(r *http.Request) { r.Header.Set("Origin", tauri) })
	if r.hdr.Get("Access-Control-Allow-Origin") != tauri || !strings.Contains(strings.Join(r.hdr.Values("Vary"), ","), "Origin") {
		t.Fatalf("Tauri GET: %v", r.hdr)
	}
}

func TestBodyLimit(t *testing.T) {
	e := newEnv(t, nil)
	big := []byte(`{"name":"` + strings.Repeat("a", MaxBodyBytes+10) + `"}`)
	r := e.client("198.51.100.1").post("/api/link/start", big)
	if r.code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: %d", r.code)
	}
}

func TestRateLimitAuthEndpoints(t *testing.T) {
	e := newEnv(t, nil)
	c := e.client("198.51.100.20")
	for i := 0; i < 10; i++ {
		if r := c.post("/api/login/begin", nil); r.code == http.StatusTooManyRequests {
			t.Fatalf("request %d limited too early", i)
		}
	}
	r := c.post("/api/login/begin", nil)
	if r.code != http.StatusTooManyRequests {
		t.Fatalf("11th auth request: %d", r.code)
	}
	if ra, err := strconv.Atoi(r.hdr.Get("Retry-After")); err != nil || ra < 1 || ra > 60 {
		t.Fatalf("Retry-After %q", r.hdr.Get("Retry-After"))
	}
	// Other IPs and non-auth endpoints are unaffected.
	if r := e.client("198.51.100.21").post("/api/login/begin", nil); r.code == http.StatusTooManyRequests {
		t.Fatal("other IP limited")
	}
	if r := c.get("/api/status"); r.code != 200 {
		t.Fatalf("general API limited by the auth bucket: %d", r.code)
	}
	// Polling has its own bucket so a waiting app cannot starve login.
	p := e.client("198.51.100.22")
	for i := 0; i < 10; i++ {
		p.do(http.MethodPost, "/api/link/poll", map[string]string{"pollToken": "x"})
	}
	if r := p.post("/api/login/begin", nil); r.code == http.StatusTooManyRequests {
		t.Fatal("poll bucket starved login")
	}
}

func TestRateLimitGeneralAPI(t *testing.T) {
	e := newEnv(t, nil)
	c := e.client("198.51.100.30")
	limited := false
	for i := 0; i < 40; i++ {
		if c.get("/api/status").code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("general API limit (5/s burst 20) not enforced")
	}
}

func TestRateLimitWSUpgrades(t *testing.T) {
	e := newEnv(t, nil)
	hdr := http.Header{"X-Forwarded-For": {"198.51.100.40"}, "Origin": {testOrigin}}
	for i := 0; i < 10; i++ {
		p, _, err := e.dial("/ws/client", hdr)
		if err != nil {
			t.Fatalf("upgrade %d: %v", i, err)
		}
		_ = p.ws.CloseNow()
	}
	_, res, err := e.dial("/ws/client", hdr)
	if err == nil || res == nil || res.StatusCode != http.StatusTooManyRequests || res.Header.Get("Retry-After") == "" {
		t.Fatalf("11th upgrade: err=%v res=%v", err, res)
	}
}

func TestLockoutAfterFailures(t *testing.T) {
	e := newEnv(t, nil)
	h := newFakeHost(t)
	h.connect(e, "203.0.113.1", testOrigin, true)
	attacker := e.client("198.51.100.50")
	wrong := randBytes(32)
	for i := 0; i < 5; i++ {
		r := attacker.post("/api/setup/begin", map[string]any{"hostPub": h.pubB64, "claim": b64u.EncodeToString(wrong)})
		if r.code != http.StatusForbidden || r.json(t)["error"] != "bad-claim" {
			t.Fatalf("attempt %d: %d %s", i, r.code, r.body)
		}
	}
	// The correct claim is now refused too: the IP is locked for 15 minutes.
	r := attacker.post("/api/setup/begin", map[string]any{"hostPub": h.pubB64, "claim": b64u.EncodeToString(h.kc)})
	if r.code != http.StatusTooManyRequests {
		t.Fatalf("locked IP: %d %s", r.code, r.body)
	}
	ra, _ := strconv.Atoi(r.hdr.Get("Retry-After"))
	if ra < 890 || ra > 900 {
		t.Fatalf("Retry-After %d, want ~900", ra)
	}
	if r := attacker.get("/api/status"); r.code != http.StatusTooManyRequests {
		t.Fatalf("locked IP can still use the API: %d", r.code)
	}
	if _, res, err := e.dial("/ws/client", http.Header{"X-Forwarded-For": {attacker.ip}, "Origin": {testOrigin}}); err == nil || res.StatusCode != http.StatusTooManyRequests {
		t.Fatal("locked IP can open WebSockets")
	}
	// Static files still load (so the page can explain the lockout).
	if r := attacker.get("/"); r.code != 200 {
		t.Fatalf("static: %d", r.code)
	}
	// Someone else can still claim.
	phone := e.client("198.51.100.51")
	if r := phone.post("/api/setup/begin", map[string]any{"hostPub": h.pubB64, "claim": b64u.EncodeToString(h.kc)}); r.code != 200 {
		t.Fatalf("other IP: %d %s", r.code, r.body)
	}
	// After 15 minutes the lock expires.
	e.clock.advance(16 * time.Minute)
	if r := attacker.get("/api/status"); r.code != 200 {
		t.Fatalf("lock did not expire: %d", r.code)
	}
	var lockouts int
	e.st.View(func(st *storeState) {
		for _, ev := range st.Events {
			if ev.Type == "lockout" {
				lockouts++
			}
		}
	})
	if lockouts != 1 {
		t.Fatalf("lockout events: %d", lockouts)
	}
}

func TestGlobalThrottle(t *testing.T) {
	e := newEnv(t, nil)
	h := newFakeHost(t)
	h.connect(e, "203.0.113.1", testOrigin, true)
	wrong := b64u.EncodeToString(randBytes(32))
	n := 0
	for ip := 1; n <= globalFailLimit; ip++ {
		c := e.client(fmt.Sprintf("192.0.2.%d", ip))
		for k := 0; k < 4 && n <= globalFailLimit; k++ {
			if r := c.post("/api/setup/begin", map[string]any{"hostPub": h.pubB64, "claim": wrong}); r.code != http.StatusForbidden {
				t.Fatalf("failure %d: %d %s", n, r.code, r.body)
			}
			n++
		}
	}
	fresh := e.client("198.51.100.99")
	if r := fresh.post("/api/login/begin", nil); r.code == http.StatusTooManyRequests {
		t.Fatalf("first request under global throttle should pass: %d", r.code)
	}
	r := fresh.post("/api/login/begin", nil)
	if r.code != http.StatusTooManyRequests || r.hdr.Get("Retry-After") == "" {
		t.Fatalf("global throttle not engaged: %d", r.code)
	}
	// Non-auth endpoints are not globally throttled.
	if r := fresh.get("/api/status"); r.code != 200 {
		t.Fatalf("status under global throttle: %d", r.code)
	}
}

func TestClientIPFromTrustedProxyOnly(t *testing.T) {
	e := newEnv(t, nil)
	mk := func(remote string, xff ...string) *http.Request {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		for _, v := range xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		return r
	}
	cases := []struct {
		r    *http.Request
		want string
	}{
		{mk("203.0.113.5:1234", "1.2.3.4"), "203.0.113.5"},                          // untrusted peer: XFF ignored
		{mk("127.0.0.1:1234", "1.2.3.4"), "1.2.3.4"},                                // trusted proxy
		{mk("127.0.0.1:1234", "6.6.6.6, 1.2.3.4"), "1.2.3.4"},                       // right-most untrusted
		{mk("127.0.0.1:1234", "6.6.6.6", "1.2.3.4, 127.0.0.1"), "1.2.3.4"},          // skip trusted hops
		{mk("127.0.0.1:1234"), "127.0.0.1"},                                         // no header
		{mk("127.0.0.1:1234", "garbage"), "127.0.0.1"},                              // unparseable
		{mk("[::1]:1234", "2001:db8::1"), "2001:db8::1"},                            // IPv6
		{mk("127.0.0.1:1234", "[2001:db8::2]:443"), "2001:db8::2"},                  // with port
	}
	for i, tc := range cases {
		if got := e.srv.clientIP(tc.r).String(); got != tc.want {
			t.Errorf("case %d: got %s want %s", i, got, tc.want)
		}
	}
	if limitKey(e.srv.clientIP(mk("[::1]:1", "2001:db8::1"))) != limitKey(e.srv.clientIP(mk("[::1]:1", "2001:db8::ffff"))) {
		t.Error("IPv6 clients in one /64 must share a limit key")
	}
}

func TestTURNCredentials(t *testing.T) {
	e := newEnv(t, nil)
	_, phone, _, _ := e.claim()
	if r := e.client("198.51.100.2").post("/api/turn", nil); r.code != http.StatusUnauthorized {
		t.Fatalf("anonymous turn: %d", r.code)
	}
	r := phone.post("/api/turn", nil)
	if r.code != 200 {
		t.Fatalf("turn: %d %s", r.code, r.body)
	}
	m := r.json(t)
	if m["ttl"] != float64(86400) {
		t.Fatalf("ttl %v", m["ttl"])
	}
	servers := m["iceServers"].([]any)
	if len(servers) != 2 {
		t.Fatalf("iceServers: %v", servers)
	}
	stun := servers[0].(map[string]any)
	if fmt.Sprint(stun["urls"]) != "[stun:turn.example.org:3478]" || stun["username"] != nil {
		t.Fatalf("stun: %v", stun)
	}
	turn := servers[1].(map[string]any)
	if fmt.Sprint(turn["urls"]) != "[turn:turn.example.org:3478?transport=udp turn:turn.example.org:3478?transport=tcp]" {
		t.Fatalf("turn urls: %v", turn["urls"])
	}
	user, cred := turn["username"].(string), turn["credential"].(string)
	exp, err := strconv.ParseInt(strings.TrimSuffix(user, ":hr"), 10, 64)
	if err != nil || !strings.HasSuffix(user, ":hr") {
		t.Fatalf("username %q", user)
	}
	if d := time.Until(time.Unix(exp, 0)); d < 23*time.Hour+59*time.Minute || d > 24*time.Hour+time.Minute {
		t.Fatalf("expiry in %v", d)
	}
	mac := hmac.New(sha1.New, []byte(testSecret))
	mac.Write([]byte(user))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if cred != want {
		t.Fatalf("credential %q want %q", cred, want)
	}
	if !bytes.Equal([]byte(cred), []byte(want)) {
		t.Fatal("unreachable")
	}
}

func TestTURNDevWithoutSecret(t *testing.T) {
	e := newEnv(t, map[string]string{"HR_TURN_SECRET": "", "HR_DEV": "1"})
	if got := e.srv.iceServers(); len(got) != 0 {
		t.Fatalf("dev without secret: %v", got)
	}
}
