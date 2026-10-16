package server

import (
	"context"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/videoproduction-ctrl/heartfulness-remote/server/internal/config"
)

// ContentSecurityPolicy is the strict CSP from PROTOCOL.md §6.
const ContentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; " +
	"img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; font-src 'self'; " +
	"manifest-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'; " +
	"frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'"

// PermissionsPolicy disables powerful features except the ones the remote
// desktop client needs on its own origin (passkeys, autoplay of the remote
// screen, fullscreen, clipboard sync, keyboard layout, and the screen wake
// lock that keeps the display on during a session). Only feature names that
// current Chromium recognises are listed: unknown names (for example
// ambient-light-sensor, bluetooth) only produce console errors.
const PermissionsPolicy = "accelerometer=(), autoplay=(self), browsing-topics=(), camera=(), " +
	"display-capture=(), encrypted-media=(), geolocation=(), gyroscope=(), hid=(), " +
	"identity-credentials-get=(), idle-detection=(), local-fonts=(), magnetometer=(), " +
	"microphone=(), midi=(), otp-credentials=(), payment=(), " +
	"publickey-credentials-create=(self), publickey-credentials-get=(self), " +
	"screen-wake-lock=(self), serial=(), usb=(), xr-spatial-tracking=(), " +
	"fullscreen=(self), clipboard-read=(self), clipboard-write=(self), keyboard-map=(self)"

func (s *Server) setSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", ContentSecurityPolicy)
	if s.cfg.Secure() {
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", PermissionsPolicy)
	h.Set("X-Frame-Options", "DENY")
}

// cors handles CORS for /api/*: only the Tauri origins are allowed, never
// with credentials. It returns false when the request was fully answered.
func (s *Server) cors(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	w.Header().Add("Vary", "Origin")
	preflight := r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != ""
	if config.IsTauriOrigin(origin) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		if preflight {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-HR")
			w.Header().Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return false
		}
		return true
	}
	if r.Method == http.MethodOptions {
		writeError(w, http.StatusForbidden, "cors")
		return false
	}
	return true
}

// checkCSRF enforces PROTOCOL.md §6 for state-changing requests: without a
// bearer token they must come from our own origin and carry X-HR: 1. The
// Tauri app may call the unauthenticated link endpoints cross-origin.
func (s *Server) checkCSRF(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	if bearerToken(r) != "" {
		return true
	}
	origin := r.Header.Get("Origin")
	if origin == s.cfg.Origin && r.Header.Get("X-HR") == "1" {
		return true
	}
	if config.IsTauriOrigin(origin) && (r.URL.Path == "/api/link/start" || r.URL.Path == "/api/link/poll") {
		return true
	}
	return false
}

func bearerToken(r *http.Request) string {
	a := r.Header.Get("Authorization")
	if len(a) > 7 && strings.EqualFold(a[:7], "bearer ") {
		return strings.TrimSpace(a[7:])
	}
	return ""
}

// ---- client IP ----

type ctxKey int

const ipKey ctxKey = 1

func withIP(ctx context.Context, ip netip.Addr) context.Context {
	return context.WithValue(ctx, ipKey, ip)
}

func ipFrom(r *http.Request) netip.Addr {
	ip, _ := r.Context().Value(ipKey).(netip.Addr)
	return ip
}

// clientIP returns the peer address, or — only when the peer is a trusted
// proxy — the right-most untrusted address in X-Forwarded-For.
func (s *Server) clientIP(r *http.Request) netip.Addr {
	peer := parseHostAddr(r.RemoteAddr)
	if !peer.IsValid() || !s.trusted(peer) {
		return peer
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				hops = append(hops, p)
			}
		}
	}
	client := peer
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(hops[i])
		if err != nil {
			a = parseHostAddr(hops[i])
			if !a.IsValid() {
				break
			}
		}
		a = a.Unmap()
		client = a
		if !s.trusted(a) {
			break
		}
	}
	return client
}

func (s *Server) trusted(a netip.Addr) bool {
	for _, p := range s.cfg.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func parseHostAddr(hp string) netip.Addr {
	if ap, err := netip.ParseAddrPort(hp); err == nil {
		return ap.Addr().Unmap()
	}
	host, _, err := net.SplitHostPort(hp)
	if err != nil {
		host = hp
	}
	a, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

// limitKey groups IPv6 clients by /64 (one subscriber usually owns a /64).
func limitKey(a netip.Addr) string {
	if !a.IsValid() {
		return "invalid"
	}
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

// ---- admission: rate limits, lockout, global throttle ----

func isAuthPath(p string) bool {
	return strings.HasPrefix(p, "/api/setup/") || strings.HasPrefix(p, "/api/login/") ||
		strings.HasPrefix(p, "/api/link/") || strings.HasPrefix(p, "/api/hosts/")
}

func (s *Server) admit(w http.ResponseWriter, r *http.Request, ip netip.Addr, path string, isAPI, isWS bool) bool {
	key := limitKey(ip)
	now := s.now()
	if !isAPI && !isWS {
		if ok, retry := s.lim.allow(key, bucketStatic, now); !ok {
			tooMany(w, retry)
			return false
		}
		return true
	}
	if locked, retry := s.lim.locked(key, now); locked {
		tooMany(w, retry)
		return false
	}
	if isWS {
		if ok, retry := s.lim.allow(key, bucketWS, now); !ok {
			tooMany(w, retry)
			return false
		}
		return true
	}
	if ok, retry := s.lim.allow(key, bucketAPI, now); !ok {
		tooMany(w, retry)
		return false
	}
	if isAuthPath(path) {
		b := bucketAuth
		if path == "/api/link/poll" {
			b = bucketPoll
		}
		if ok, retry := s.lim.allow(key, b, now); !ok {
			tooMany(w, retry)
			return false
		}
		if ok, retry := s.lim.globalAllow(now); !ok {
			tooMany(w, retry)
			return false
		}
	}
	return true
}

func tooMany(w http.ResponseWriter, retry time.Duration) {
	secs := int(math.Ceil(retry.Seconds()))
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeError(w, http.StatusTooManyRequests, "rate-limited")
}

// authFailure records a failed authentication attempt from r's client IP.
func (s *Server) authFailure(r *http.Request, what string) {
	s.authFailureIP(ipFrom(r), what)
}

func (s *Server) authFailureIP(ip netip.Addr, what string) {
	lockedNow, globalNow := s.lim.fail(limitKey(ip), s.now())
	s.log.Warn("auth failure", "what", what)
	if lockedNow {
		s.log.Warn("client locked out after repeated failures")
		s.event("lockout", "", ip.String())
	}
	if globalNow {
		s.log.Warn("global auth throttle engaged: too many failures server-wide")
		s.event("global-throttle", "", "")
	}
}
