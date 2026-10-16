// Package server implements the Heartfulness Remote signaling and
// authentication server (docs/PROTOCOL.md §4–§7): passkey login, the claim
// (bootstrap) flow, device pairing relay, session signaling relay, TURN
// credentials, rate limiting and lockout. It never sees screen data and
// cannot impersonate the Mac or an approved device: every trust decision it
// mirrors is backed by an Ed25519 signature it verifies.
package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
	"github.com/videoproduction-ctrl/heartfulness-remote/server/internal/config"
	"github.com/videoproduction-ctrl/heartfulness-remote/server/internal/store"
)

// MaxBodyBytes limits JSON request bodies.
const MaxBodyBytes = 64 << 10

// Timing knobs (variables so tests can shorten them).
type timing struct {
	pingInterval time.Duration // WebSocket ping period
	idleTimeout  time.Duration // drop connections with no traffic/pong for this long
	authTimeout  time.Duration // unauthenticated WebSocket lifetime
	turnRefresh  time.Duration // host TURN credential refresh
	housekeeping time.Duration // in-memory expiry sweep
	purge        time.Duration // persistent purge job
}

var defaultTiming = timing{
	pingInterval: 20 * time.Second,
	idleTimeout:  60 * time.Second,
	authTimeout:  15 * time.Second,
	turnRefresh:  12 * time.Hour,
	housekeeping: 30 * time.Second,
	purge:        time.Hour,
}

// Server is the HTTP + WebSocket server.
type Server struct {
	cfg    *config.Config
	st     *store.Store
	log    *slog.Logger
	wa     *webauthn.WebAuthn
	now    func() time.Time
	t      timing
	lim    *limiter
	hub    *hub
	mem    *memory
	static http.Handler
	mux    *http.ServeMux
}

// Options configures New.
type Options struct {
	Logger *slog.Logger
	WebFS  fs.FS            // embedded web client (used when cfg.WebDir is empty)
	Now    func() time.Time // clock (tests)
}

// New builds a server around an opened store.
func New(cfg *config.Config, st *store.Store, opts Options) (*Server, error) {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:                  cfg.RPID,
		RPDisplayName:         "Heartfulness Remote",
		RPOrigins:             []string{cfg.Origin},
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: flowTTL, TimeoutUVD: flowTTL},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: flowTTL, TimeoutUVD: flowTTL},
		},
	})
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg: cfg,
		st:  st,
		log: opts.Logger,
		wa:  wa,
		now: opts.Now,
		t:   defaultTiming,
	}
	s.lim = newLimiter(s.now)
	s.mem = newMemory()
	s.hub = newHub(s)
	webFS := opts.WebFS
	if cfg.WebDir != "" {
		webFS = dirFS(cfg.WebDir)
	}
	s.static = newStaticHandler(webFS, cfg.WebDir == "")
	s.routes()
	return s, nil
}

func (s *Server) routes() {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", s.handleHealthz)
	m.HandleFunc("GET /api/status", s.handleStatus)
	m.HandleFunc("POST /api/setup/begin", s.handleSetupBegin)
	m.HandleFunc("POST /api/setup/finish", s.handleSetupFinish)
	m.HandleFunc("POST /api/login/begin", s.handleLoginBegin)
	m.HandleFunc("POST /api/login/finish", s.handleLoginFinish)
	m.HandleFunc("POST /api/logout", s.handleLogout)
	m.HandleFunc("GET /api/me", s.handleMe)
	m.HandleFunc("POST /api/turn", s.handleTurn)
	m.HandleFunc("GET /api/nonce", s.handleNonce)
	m.HandleFunc("POST /api/passkeys/begin", s.handlePasskeyBegin)
	m.HandleFunc("POST /api/passkeys/finish", s.handlePasskeyFinish)
	m.HandleFunc("POST /api/passkeys/delete", s.handlePasskeyDelete)
	m.HandleFunc("POST /api/link/start", s.handleLinkStart)
	m.HandleFunc("POST /api/link/approve", s.handleLinkApprove)
	m.HandleFunc("POST /api/link/poll", s.handleLinkPoll)
	m.HandleFunc("GET /ws/host", s.handleWSHost)
	m.HandleFunc("GET /ws/client", s.handleWSClient)
	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { writeError(w, http.StatusNotFound, "not-found") })
	m.HandleFunc("/ws/", func(w http.ResponseWriter, r *http.Request) { writeError(w, http.StatusNotFound, "not-found") })
	m.Handle("/", s.static)
	s.mux = m
}

// Handler returns the root HTTP handler with all middleware applied.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.setSecurityHeaders(w)
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		}
		path := r.URL.Path
		isAPI := strings.HasPrefix(path, "/api/")
		isWS := strings.HasPrefix(path, "/ws/")
		if isAPI {
			w.Header().Set("Cache-Control", "no-store")
			if !s.cors(w, r) {
				return
			}
		}
		ip := s.clientIP(r)
		if !s.admit(w, r, ip, path, isAPI, isWS) {
			return
		}
		if isAPI && !s.checkCSRF(r) {
			writeError(w, http.StatusForbidden, "csrf")
			return
		}
		s.mux.ServeHTTP(w, r.WithContext(withIP(r.Context(), ip)))
	})
}

// Run serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
	}
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	bg, stop := context.WithCancel(ctx)
	defer stop()
	go s.background(bg)
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	s.log.Info("listening", "addr", ln.Addr().String(), "origin", s.cfg.Origin, "rpId", s.cfg.RPID, "claimed", s.claimed())
	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s.hub.closeAll()
	err = srv.Shutdown(sctx)
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	s.log.Info("stopped")
	return err
}

// background runs the housekeeping sweep and the hourly purge job.
func (s *Server) background(ctx context.Context) {
	hk := time.NewTicker(s.t.housekeeping)
	defer hk.Stop()
	pg := time.NewTicker(s.t.purge)
	defer pg.Stop()
	s.Purge()
	for {
		select {
		case <-ctx.Done():
			return
		case <-hk.C:
			s.housekeeping()
		case <-pg.C:
			s.Purge()
		}
	}
}

// housekeeping expires in-memory state (flows, nonces, link codes, pairing
// requests, unanswered session requests, idle limiter entries).
func (s *Server) housekeeping() {
	now := s.now()
	s.mem.expire(now)
	s.lim.cleanup(now)
	s.hub.expire(now)
}

// Purge runs the retention job: events older than 7 days, expired sessions,
// pending devices older than 24 h, old revocations, and expired in-memory
// flows and link codes.
func (s *Server) Purge() {
	now := s.now()
	var res store.PurgeResult
	err := s.st.Update(func(st *store.State) error {
		res = st.Purge(now)
		if res == (store.PurgeResult{}) {
			return store.ErrNoChange
		}
		return nil
	})
	if err != nil {
		s.log.Error("purge failed", "err", err)
	}
	s.mem.expire(now)
	if res != (store.PurgeResult{}) {
		s.log.Info("purged", "events", res.Events, "sessions", res.Sessions, "pendingDevices", res.PendingDevices, "revokedDevices", res.RevokedDevices)
	}
}

func (s *Server) claimed() bool {
	var c bool
	s.st.View(func(st *store.State) { c = st.Claimed() })
	return c
}

func (s *Server) event(typ, device, ip string) {
	now := s.now()
	if err := s.st.Update(func(st *store.State) error {
		st.AddEvent(store.Event{Time: now, Type: typ, Device: device, IP: ip})
		return nil
	}); err != nil {
		s.log.Error("event write failed", "err", err)
	}
}

// ---- small helpers ----

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return b
}

func tokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

type errorBody struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, errorBody{Error: code})
}

// readJSON decodes a JSON body (size-limited by the middleware).
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "too-large")
		} else {
			writeError(w, http.StatusBadRequest, "bad-json")
		}
		return false
	}
	return true
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"claimed": s.claimed(), "rpId": s.cfg.RPID, "origin": s.cfg.Origin})
}

// b64Key decodes a b64 Ed25519 public key.
func b64Key(s string) ([]byte, bool) {
	b, err := proto.UnB64Len(s, proto.PubKeySize)
	return b, err == nil
}
