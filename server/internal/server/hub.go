package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/time/rate"

	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
	"github.com/videoproduction-ctrl/heartfulness-remote/server/internal/config"
	"github.com/videoproduction-ctrl/heartfulness-remote/server/internal/store"
)

// WebSocket limits (PROTOCOL.md §7).
const (
	maxFrame           = 256 << 10
	msgRate            = 50
	msgBurst           = 200
	sendQueueLen       = 256
	writeTimeout       = 10 * time.Second
	maxPendingHosts    = 5
	maxClientConns     = 20
	maxPreAuthConns    = 64
	maxPairings        = 3
	pairingTTL         = 5 * time.Minute
	sessionRequestTTL  = 60 * time.Second
	maxSessionsPerConn = 4
	maxSessions        = 32
	maxSDP             = 128 << 10
	maxCandidate       = 4 << 10
	setupResendTTL     = 10 * time.Minute
	lastSeenEvery      = 5 * time.Minute
)

// Host states (host-status). "offline" is server-generated.
const (
	hostAvailable = "available"
	hostInSession = "in-session"
	hostBlocked   = "blocked"
	hostOffline   = "offline"
)

var reasonRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

func cleanReason(r, def string) string {
	if reasonRE.MatchString(r) {
		return r
	}
	return def
}

// inMsg is the union of all inbound message fields. The server copies only
// validated fields into outbound messages; nothing is forwarded verbatim.
type inMsg struct {
	Type string `json:"type"`

	Token       string `json:"token"`
	HostPub     string `json:"hostPub"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Sig         string `json:"sig"`
	ClaimCommit string `json:"claimCommit"`
	DevicePub   string `json:"devicePub"`

	Certs       []proto.Cert       `json:"certs"`
	Revocations []proto.Revocation `json:"revocations"`

	State             string `json:"state"`
	SessionDeviceName string `json:"sessionDeviceName"`

	Kind        string            `json:"kind"`
	Commit      string            `json:"commit"`
	RequestID   string            `json:"requestId"`
	Na          string            `json:"na"`
	Nd          string            `json:"nd"`
	Approved    *bool             `json:"approved"`
	Cert        *proto.Cert       `json:"cert"`
	Reason      string            `json:"reason"`
	ApproverPub string            `json:"approverPub"`
	TargetPub   string            `json:"targetPub"`
	Ts          int64             `json:"ts"`
	Action      string            `json:"action"`
	Revocation  *proto.Revocation `json:"revocation"`

	SessionID   string          `json:"sessionId"`
	ClientNonce string          `json:"clientNonce"`
	HostNonce   string          `json:"hostNonce"`
	RelayOnly   bool            `json:"relayOnly"`
	Sdp         string          `json:"sdp"`
	Candidate   json.RawMessage `json:"candidate"`
}

type msg = map[string]any

// conn is one WebSocket connection (host or client).
type conn struct {
	h      *hub
	ws     *websocket.Conn
	isHost bool
	ip     netip.Addr

	ctx       context.Context
	cancel    context.CancelFunc
	send      chan []byte
	closeReq  chan struct{}
	closeOnce sync.Once
	closeCode websocket.StatusCode
	closeWhy  string
	lim       *rate.Limiter
	lastSeen  atomic.Int64 // unix nanos of last inbound frame or pong

	// Read-goroutine state.
	stage int
	nonce []byte

	// Set under hub.mu once authenticated.
	authed      bool
	hostPub     string // b64
	hostName    string
	claimCommit []byte
	bound       bool
	cookieTok   string
	sessionHash string
	devicePub   string // b64
}

func (c *conn) touch() { c.lastSeen.Store(time.Now().UnixNano()) }

// sendMsg queues a JSON message; a full queue aborts the connection.
func (c *conn) sendMsg(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	select {
	case <-c.ctx.Done():
	case c.send <- b:
	default:
		c.abort()
	}
}

func (c *conn) sendErr(code string, extra ...any) {
	m := msg{"type": "error", "code": code}
	for i := 0; i+1 < len(extra); i += 2 {
		if k, ok := extra[i].(string); ok {
			m[k] = extra[i+1]
		}
	}
	c.sendMsg(m)
}

// closeWith flushes queued messages and then closes with code/reason.
func (c *conn) closeWith(code websocket.StatusCode, why string) {
	c.closeOnce.Do(func() {
		c.closeCode, c.closeWhy = code, why
		close(c.closeReq)
	})
}

// fail sends an error message and closes the connection.
func (c *conn) fail(code string) {
	c.sendErr(code)
	c.closeWith(websocket.StatusPolicyViolation, code)
}

func (c *conn) abort() {
	c.cancel()
	_ = c.ws.CloseNow()
}

func (c *conn) closing() bool {
	select {
	case <-c.closeReq:
		return true
	default:
		return false
	}
}

func (c *conn) write(b []byte) bool {
	ctx, cancel := context.WithTimeout(c.ctx, writeTimeout)
	defer cancel()
	return c.ws.Write(ctx, websocket.MessageText, b) == nil
}

func (c *conn) writer() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case b := <-c.send:
			if !c.write(b) {
				c.abort()
				return
			}
		case <-c.closeReq:
			for drained := false; !drained; {
				select {
				case b := <-c.send:
					if !c.write(b) {
						c.abort()
						return
					}
				default:
					drained = true
				}
			}
			_ = c.ws.Close(c.closeCode, c.closeWhy)
			c.cancel()
			return
		}
	}
}

func (c *conn) pinger(interval, idle time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(c.ctx, interval)
			if c.ws.Ping(ctx) == nil {
				c.touch()
			}
			cancel()
			if time.Since(time.Unix(0, c.lastSeen.Load())) > idle {
				c.abort()
				return
			}
		}
	}
}

// serve runs the read loop; handle returns false to stop reading.
func (c *conn) serve(handle func(*conn, *inMsg) bool) {
	t := c.h.s.t
	go c.writer()
	go c.pinger(t.pingInterval, t.idleTimeout)
	authTimer := time.AfterFunc(t.authTimeout, func() {
		c.h.mu.Lock()
		authed := c.authed
		c.h.mu.Unlock()
		if !authed {
			c.fail("auth-timeout")
		}
	})
	defer authTimer.Stop()
	defer func() {
		c.h.remove(c)
		if !c.closing() {
			c.abort()
		}
	}()
	for {
		typ, data, err := c.ws.Read(c.ctx)
		if err != nil {
			return
		}
		c.touch()
		if c.closing() {
			continue // drain until the close handshake completes
		}
		if typ != websocket.MessageText {
			c.fail("text-only")
			continue
		}
		if !c.lim.Allow() {
			c.fail("rate-limited")
			continue
		}
		var m inMsg
		if err := json.Unmarshal(data, &m); err != nil || m.Type == "" {
			c.fail("bad-message")
			continue
		}
		if !handle(c, &m) {
			continue
		}
	}
}

// ---- hub ----

type setupDevice struct {
	DevicePub string
	Name      string
	Kind      string
	SetupMac  string
	expires   time.Time
}

type pairing struct {
	id         string
	idRaw      []byte
	conn       *conn  // requesting device connection (nil if it went away)
	devicePub  string // b64, from the authenticated connection
	name, kind string
	commit     []byte
	na, hostSg []byte
	nd         []byte
	challenged bool
	revealed   bool
	bad        bool // reveal did not match the commit
	created    time.Time
}

type rtcSession struct {
	id        string
	client    *conn
	devicePub string
	accepted  bool
	created   time.Time
}

type hub struct {
	s  *Server
	mu sync.Mutex

	all          map[*conn]struct{}
	preAuth      int
	host         *conn
	hostState    string
	hostSessDev  string
	pendingHosts map[string]*conn
	clients      map[*conn]struct{}
	pairings     map[string]*pairing
	sessions     map[string]*rtcSession
	setup        *setupDevice
}

func newHub(s *Server) *hub {
	return &hub{
		s:            s,
		all:          map[*conn]struct{}{},
		pendingHosts: map[string]*conn{},
		clients:      map[*conn]struct{}{},
		pairings:     map[string]*pairing{},
		sessions:     map[string]*rtcSession{},
	}
}

// checkWSOrigin allows our origin and the Tauri origins. The host agent is a
// native program and may omit Origin; browsers always send it.
func (s *Server) checkWSOrigin(r *http.Request, allowMissing bool) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return allowMissing
	}
	return o == s.cfg.Origin || config.IsTauriOrigin(o)
}

func (h *hub) accept(w http.ResponseWriter, r *http.Request, isHost bool) *conn {
	h.mu.Lock()
	if h.preAuth >= maxPreAuthConns {
		h.mu.Unlock()
		writeError(w, http.StatusServiceUnavailable, "busy")
		return nil
	}
	h.preAuth++
	h.mu.Unlock()
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // origin already checked by checkWSOrigin
		CompressionMode:    websocket.CompressionDisabled,
	})
	if err != nil {
		h.mu.Lock()
		h.preAuth--
		h.mu.Unlock()
		return nil
	}
	ws.SetReadLimit(maxFrame)
	ctx, cancel := context.WithCancel(context.Background())
	c := &conn{
		h:        h,
		ws:       ws,
		isHost:   isHost,
		ip:       ipFrom(r),
		ctx:      ctx,
		cancel:   cancel,
		send:     make(chan []byte, sendQueueLen),
		closeReq: make(chan struct{}),
		lim:      rate.NewLimiter(msgRate, msgBurst),
	}
	c.touch()
	h.mu.Lock()
	h.all[c] = struct{}{}
	h.mu.Unlock()
	return c
}

func (s *Server) handleWSHost(w http.ResponseWriter, r *http.Request) {
	if !s.checkWSOrigin(r, true) {
		writeError(w, http.StatusForbidden, "bad-origin")
		return
	}
	c := s.hub.accept(w, r, true)
	if c == nil {
		return
	}
	c.nonce = randBytes(proto.NonceSize)
	c.sendMsg(msg{"type": "challenge", "nonce": proto.B64(c.nonce), "claimed": s.claimed()})
	go s.hub.turnRefresher(c)
	c.serve(s.hub.onHost)
}

func (h *hub) turnRefresher(c *conn) {
	t := time.NewTicker(h.s.t.turnRefresh)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			h.mu.Lock()
			bound := c.bound && h.host == c
			h.mu.Unlock()
			if bound {
				c.sendMsg(msg{"type": "turn", "iceServers": h.s.iceServers()})
			}
		}
	}
}

func (h *hub) remove(c *conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.all[c]; !ok {
		return
	}
	delete(h.all, c)
	if !c.authed {
		h.preAuth--
		return
	}
	if c.isHost {
		if h.host == c {
			h.host = nil
			h.hostGoneLocked("host-offline")
			h.s.log.Info("host disconnected")
		}
		if h.pendingHosts[c.hostPub] == c {
			delete(h.pendingHosts, c.hostPub)
		}
		return
	}
	delete(h.clients, c)
	for id, rs := range h.sessions {
		if rs.client == c {
			if h.host != nil {
				h.host.sendMsg(msg{"type": "session-end", "sessionId": id, "reason": "client-disconnected"})
			}
			delete(h.sessions, id)
		}
	}
	for _, p := range h.pairings {
		if p.conn == c {
			p.conn = nil
		}
	}
	h.s.touchDevice(c.devicePub, true)
}

// hostGoneLocked ends sessions and pairings after the host connection went away.
func (h *hub) hostGoneLocked(reason string) {
	h.hostState, h.hostSessDev = "", ""
	for id, rs := range h.sessions {
		rs.client.sendMsg(msg{"type": "session-end", "sessionId": id, "reason": reason})
		delete(h.sessions, id)
	}
	for id, p := range h.pairings {
		if p.conn != nil {
			p.conn.sendMsg(msg{"type": "pair-denied", "requestId": id, "reason": reason})
		}
		if p.revealed {
			h.toApproversLocked(msg{"type": "approval-closed", "requestId": id})
		}
		delete(h.pairings, id)
	}
	h.broadcastHostStatusLocked()
}

func (h *hub) closeAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.all {
		c.closeWith(websocket.StatusGoingAway, "shutdown")
	}
}

// dropSession closes client connections that used a revoked session.
func (h *hub) dropSession(hash string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients {
		if c.sessionHash == hash {
			c.fail("logged-out")
		}
	}
}

// hostInfoLocked describes the host for /api/me and client messages.
func (h *hub) hostInfoLocked() meHost {
	var info meHost
	h.s.st.View(func(st *store.State) {
		if st.Host != nil {
			info.Pub, info.Name = st.Host.Pub, st.Host.Name
		}
	})
	info.Online = h.host != nil
	info.State = hostOffline
	if info.Online {
		info.State = h.hostState
		info.SessionDeviceName = h.hostSessDev
	}
	return info
}

func (h *hub) hostInfo() meHost {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hostInfoLocked()
}

func (h *hub) broadcastHostStatusLocked() {
	info := h.hostInfoLocked()
	m := msg{"type": "host-status", "online": info.Online, "state": info.State, "sessionDeviceName": info.SessionDeviceName}
	for c := range h.clients {
		c.sendMsg(m)
	}
}

func (h *hub) broadcastDevicesChanged() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.broadcastDevicesChangedLocked()
}

func (h *hub) broadcastDevicesChangedLocked() {
	for c := range h.clients {
		c.sendMsg(msg{"type": "devices-changed"})
	}
}

// approvedSet returns the set of approved device keys.
func (h *hub) approvedSet() map[string]bool {
	out := map[string]bool{}
	h.s.st.View(func(st *store.State) {
		for k, d := range st.Devices {
			if d.Status == store.StatusApproved {
				out[k] = true
			}
		}
	})
	return out
}

func (h *hub) toApproversLocked(m msg) {
	approved := h.approvedSet()
	for c := range h.clients {
		if approved[c.devicePub] {
			c.sendMsg(m)
		}
	}
}

func (h *hub) toDeviceLocked(devicePub string, m msg) {
	for c := range h.clients {
		if c.devicePub == devicePub {
			c.sendMsg(m)
		}
	}
}

func (s *Server) deviceStatus(pub string) string {
	status := store.StatusUnknown
	s.st.View(func(st *store.State) { status = st.DeviceStatus(pub) })
	return status
}

// touchDevice updates lastSeen (throttled unless force).
func (s *Server) touchDevice(pub string, force bool) {
	now := s.now()
	_ = s.st.Update(func(st *store.State) error {
		d, ok := st.Devices[pub]
		if !ok || (!force && now.Sub(d.LastSeen) < lastSeenEvery) {
			return store.ErrNoChange
		}
		d.LastSeen = now
		return nil
	})
}

// pendingCommit returns the claim commit of a connected, unclaimed host.
func (h *hub) pendingCommit(hostPub string) ([]byte, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	c := h.pendingHosts[hostPub]
	if c == nil || c.closing() {
		return nil, false
	}
	return append([]byte(nil), c.claimCommit...), true
}

// completeClaim binds the pending host atomically with the store mutation,
// promotes its connection and forwards setup-device to it.
func (h *hub) completeClaim(hostPub string, sd setupDevice, mutate func(st *store.State, hostName string) error) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	c := h.pendingHosts[hostPub]
	if c == nil || c.closing() {
		return errHostGone
	}
	if err := h.s.st.Update(func(st *store.State) error { return mutate(st, c.hostName) }); err != nil {
		return err
	}
	delete(h.pendingHosts, hostPub)
	for _, other := range h.pendingHosts {
		other.fail("already-claimed")
	}
	h.pendingHosts = map[string]*conn{}
	c.bound, c.claimCommit = true, nil
	h.host = c
	h.hostState = hostAvailable
	c.sendMsg(msg{"type": "host-ready", "claimed": true, "origin": h.s.cfg.Origin, "iceServers": h.s.iceServers()})
	sd.expires = h.s.now().Add(setupResendTTL)
	h.setup = &sd
	h.sendSetupLocked()
	h.broadcastHostStatusLocked()
	return nil
}

func (h *hub) sendSetupLocked() {
	sd := h.setup
	if sd == nil || h.host == nil {
		return
	}
	if !h.s.now().Before(sd.expires) || h.s.deviceStatus(sd.DevicePub) != store.StatusPending {
		h.setup = nil
		return
	}
	h.host.sendMsg(msg{"type": "setup-device", "devicePub": sd.DevicePub, "name": sd.Name, "kind": sd.Kind, "setupMac": sd.SetupMac})
}

// expire runs the in-memory expiry sweep.
func (h *hub) expire(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, p := range h.pairings {
		if now.Sub(p.created) >= pairingTTL {
			if p.conn != nil {
				p.conn.sendMsg(msg{"type": "pair-denied", "requestId": id, "reason": "expired"})
			}
			if p.revealed {
				h.toApproversLocked(msg{"type": "approval-closed", "requestId": id})
			}
			delete(h.pairings, id)
		}
	}
	for id, rs := range h.sessions {
		if !rs.accepted && now.Sub(rs.created) >= sessionRequestTTL {
			rs.client.sendMsg(msg{"type": "session-end", "sessionId": id, "reason": "timeout"})
			if h.host != nil {
				h.host.sendMsg(msg{"type": "session-end", "sessionId": id, "reason": "timeout"})
			}
			delete(h.sessions, id)
		}
	}
	if h.setup != nil && !now.Before(h.setup.expires) {
		h.setup = nil
	}
	for c := range h.clients {
		if !h.s.sessionValid(c.sessionHash) {
			c.fail("session-expired")
			continue
		}
		h.s.touchSession(c.sessionHash)
	}
}

// ---- host messages ----

func (h *hub) onHost(c *conn, m *inMsg) bool {
	if c.stage == 0 {
		if m.Type != "host-auth" {
			c.fail("auth-required")
			return false
		}
		return h.hostAuth(c, m)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !c.bound || h.host != c {
		if m.Type == "claim-commit" && h.pendingHosts[c.hostPub] == c {
			if b, err := proto.UnB64Len(m.ClaimCommit, 32); err == nil {
				c.claimCommit = b
			} else {
				c.sendErr("bad-request", "for", m.Type)
			}
			return true
		}
		c.sendErr("not-bound", "for", m.Type)
		return true
	}
	switch m.Type {
	case "trust-sync":
		h.trustSyncLocked(c, m)
	case "host-status":
		h.hostStatusLocked(c, m)
	case "pair-challenge":
		h.pairChallengeLocked(c, m)
	case "pair-result":
		h.pairResultLocked(c, m)
	case "device-approved":
		h.deviceApprovedLocked(c, m)
	case "device-revoked":
		h.deviceRevokedLocked(c, m)
	case "session-accept", "session-reject", "answer", "ice", "session-end":
		h.hostSessionLocked(c, m)
	case "claim-commit":
		// Already claimed: nothing to do.
	default:
		c.sendErr("unknown-type", "for", m.Type)
	}
	return true
}

func (h *hub) hostAuth(c *conn, m *inMsg) bool {
	s := h.s
	pub, ok := b64Key(m.HostPub)
	sig, err := proto.UnB64Len(m.Sig, proto.SignatureSize)
	if !ok || err != nil {
		c.fail("bad-request")
		return false
	}
	if !proto.Verify(pub, sig, proto.LabelHostAuth, proto.Str(s.cfg.Origin), c.nonce) {
		s.authFailureIP(c.ip, "host signature")
		c.fail("bad-signature")
		return false
	}
	if s.cfg.HostPubPin != nil && string(pub) != string(s.cfg.HostPubPin) {
		s.authFailureIP(c.ip, "host key not pinned")
		c.fail("host-not-allowed")
		return false
	}
	var commit []byte
	if m.ClaimCommit != "" {
		if commit, err = proto.UnB64Len(m.ClaimCommit, 32); err != nil {
			c.fail("bad-request")
			return false
		}
	}
	name, ok := cleanName(m.Name)
	if !ok {
		name = "Mac"
	}
	pubB64 := proto.B64(pub)

	h.mu.Lock()
	defer h.mu.Unlock()
	var claimed bool
	var boundPub, boundName string
	s.st.View(func(st *store.State) {
		claimed = st.Claimed()
		if st.Host != nil {
			boundPub, boundName = st.Host.Pub, st.Host.Name
		}
	})
	c.stage = 1
	c.hostPub, c.hostName = pubB64, name
	if claimed {
		if boundPub != pubB64 {
			c.fail("already-claimed")
			return false
		}
		if old := h.host; old != nil {
			h.host = nil
			old.fail("replaced")
			h.hostGoneLocked("host-reconnected")
		}
		c.authed, c.bound = true, true
		h.preAuth--
		h.host = c
		h.hostState = hostAvailable
		if name != boundName {
			_ = s.st.Update(func(st *store.State) error {
				if st.Host == nil {
					return store.ErrNoChange
				}
				st.Host.Name = name
				return nil
			})
		}
		c.sendMsg(msg{"type": "host-ready", "claimed": true, "origin": s.cfg.Origin, "iceServers": s.iceServers()})
		h.sendSetupLocked()
		h.broadcastHostStatusLocked()
		s.log.Info("host connected", "host", proto.Fingerprint(pub))
		return true
	}
	if old := h.pendingHosts[pubB64]; old != nil {
		delete(h.pendingHosts, pubB64)
		old.fail("replaced")
	} else if len(h.pendingHosts) >= maxPendingHosts {
		c.fail("too-many-pending")
		return false
	}
	c.authed = true
	c.claimCommit = commit
	h.preAuth--
	h.pendingHosts[pubB64] = c
	c.sendMsg(msg{"type": "host-ready", "claimed": false, "origin": s.cfg.Origin, "iceServers": s.iceServers()})
	s.log.Info("unclaimed host connected", "host", proto.Fingerprint(pub))
	return true
}

func (h *hub) hostPubBytes(c *conn) []byte {
	b, _ := proto.UnB64Len(c.hostPub, proto.PubKeySize)
	return b
}

const maxTrustEntries = 1000

func (h *hub) trustSyncLocked(c *conn, m *inMsg) {
	s := h.s
	if len(m.Certs) > maxTrustEntries || len(m.Revocations) > maxTrustEntries {
		c.sendErr("too-large", "for", m.Type)
		return
	}
	hostPub := h.hostPubBytes(c)
	certs := map[string]proto.Cert{}
	for _, ct := range m.Certs {
		if err := ct.Verify(hostPub); err != nil {
			s.log.Warn("trust-sync: ignoring invalid cert")
			continue
		}
		certs[ct.DevicePub] = ct
	}
	revs := map[string]bool{}
	for _, rv := range m.Revocations {
		if err := rv.Verify(hostPub); err != nil {
			s.log.Warn("trust-sync: ignoring invalid revocation")
			continue
		}
		revs[rv.DevicePub] = true
	}
	now := s.now()
	var revokedNow []string
	changed := false
	_ = s.st.Update(func(st *store.State) error {
		for pub, d := range st.Devices {
			ct, isCert := certs[pub]
			switch {
			case revs[pub]:
				if d.Status != store.StatusRevoked {
					d.Status, d.RevokedAt, d.Cert = store.StatusRevoked, now, nil
					revokedNow = append(revokedNow, pub)
					changed = true
				}
			case isCert:
				nc := ct
				name, kind := certNameKind(ct, d.Name, d.Kind)
				if d.Status != store.StatusApproved || d.Cert == nil || *d.Cert != nc || d.Name != name || d.Kind != kind {
					d.Status, d.Cert, d.Name, d.Kind, d.RevokedAt = store.StatusApproved, &nc, name, kind, time.Time{}
					changed = true
				}
			case d.Status == store.StatusApproved:
				d.Status, d.RevokedAt, d.Cert = store.StatusRevoked, now, nil
				revokedNow = append(revokedNow, pub)
				changed = true
			}
		}
		for pub, ct := range certs {
			if _, ok := st.Devices[pub]; ok || revs[pub] {
				continue
			}
			nc := ct
			name, kind := certNameKind(ct, "Device", "unknown")
			st.Devices[pub] = &store.Device{Pub: pub, Name: name, Kind: kind, Status: store.StatusApproved, Cert: &nc, CreatedAt: now}
			changed = true
		}
		for pub := range revs {
			if _, ok := st.Devices[pub]; ok {
				continue
			}
			st.Devices[pub] = &store.Device{Pub: pub, Name: "Removed device", Kind: "unknown", Status: store.StatusRevoked, CreatedAt: now, RevokedAt: now}
			changed = true
		}
		if !changed {
			return store.ErrNoChange
		}
		st.AddEvent(store.Event{Time: now, Type: "trust-sync"})
		return nil
	})
	for _, pub := range revokedNow {
		h.endDeviceSessionsLocked(pub, "revoked")
	}
	if changed {
		h.broadcastDevicesChangedLocked()
	}
}

func certNameKind(ct proto.Cert, defName, defKind string) (string, string) {
	name, ok := cleanName(ct.Name)
	if !ok {
		name = defName
	}
	kind := ct.Kind
	if !validKind(kind) {
		kind = defKind
	}
	return name, kind
}

// endDeviceSessionsLocked stops relaying for a device that lost trust.
func (h *hub) endDeviceSessionsLocked(devicePub, reason string) {
	for id, rs := range h.sessions {
		if rs.devicePub != devicePub {
			continue
		}
		rs.client.sendMsg(msg{"type": "session-end", "sessionId": id, "reason": reason})
		if h.host != nil {
			h.host.sendMsg(msg{"type": "session-end", "sessionId": id, "reason": reason})
		}
		delete(h.sessions, id)
	}
}

func (h *hub) hostStatusLocked(c *conn, m *inMsg) {
	switch m.State {
	case hostAvailable, hostInSession, hostBlocked:
	default:
		c.sendErr("bad-request", "for", m.Type)
		return
	}
	dev := ""
	if m.SessionDeviceName != "" {
		if n, ok := cleanName(m.SessionDeviceName); ok {
			dev = n
		}
	}
	h.hostState, h.hostSessDev = m.State, dev
	h.broadcastHostStatusLocked()
}

func (h *hub) deviceApprovedLocked(c *conn, m *inMsg) {
	s := h.s
	if m.Cert == nil || m.Cert.Verify(h.hostPubBytes(c)) != nil {
		c.sendErr("bad-cert", "for", m.Type)
		return
	}
	ct := *m.Cert
	now := s.now()
	var name string
	err := s.st.Update(func(st *store.State) error {
		d, ok := st.Devices[ct.DevicePub]
		if !ok || d.Status == store.StatusRevoked {
			return errNotFound
		}
		name, d.Kind = certNameKind(ct, d.Name, d.Kind)
		d.Name, d.Status, d.Cert = name, store.StatusApproved, &ct
		st.AddEvent(store.Event{Time: now, Type: "device-approved", Device: name})
		return nil
	})
	if err != nil {
		c.sendErr("unknown-device", "for", m.Type)
		return
	}
	if h.setup != nil && h.setup.DevicePub == ct.DevicePub {
		h.setup = nil
	}
	h.toDeviceLocked(ct.DevicePub, msg{"type": "pair-approved", "cert": ct})
	h.broadcastDevicesChangedLocked()
}

func (h *hub) deviceRevokedLocked(c *conn, m *inMsg) {
	s := h.s
	if m.Revocation == nil || m.Revocation.Verify(h.hostPubBytes(c)) != nil {
		c.sendErr("bad-revocation", "for", m.Type)
		return
	}
	pub := m.Revocation.DevicePub
	now := s.now()
	_ = s.st.Update(func(st *store.State) error {
		d, ok := st.Devices[pub]
		if !ok {
			d = &store.Device{Pub: pub, Name: "Removed device", Kind: "unknown", CreatedAt: now}
			st.Devices[pub] = d
		}
		d.Status, d.RevokedAt, d.Cert = store.StatusRevoked, now, nil
		st.AddEvent(store.Event{Time: now, Type: "device-revoked", Device: d.Name})
		return nil
	})
	h.endDeviceSessionsLocked(pub, "revoked")
	h.broadcastDevicesChangedLocked()
}

func (h *hub) hostSessionLocked(c *conn, m *inMsg) {
	rs := h.sessions[m.SessionID]
	if rs == nil {
		c.sendErr("unknown-session", "sessionId", m.SessionID)
		return
	}
	out := msg{"type": m.Type, "sessionId": rs.id}
	switch m.Type {
	case "session-accept":
		if rs.accepted {
			c.sendErr("bad-state", "sessionId", rs.id)
			return
		}
		if _, err := proto.UnB64Len(m.HostNonce, proto.NonceSize); err != nil {
			c.sendErr("bad-request", "sessionId", rs.id)
			return
		}
		rs.accepted = true
		out["hostNonce"] = m.HostNonce
	case "session-reject":
		out["reason"] = cleanReason(m.Reason, "error")
		delete(h.sessions, rs.id)
	case "answer":
		if !rs.accepted || len(m.Sdp) == 0 || len(m.Sdp) > maxSDP {
			c.sendErr("bad-request", "sessionId", rs.id)
			return
		}
		if _, err := proto.UnB64Len(m.Sig, proto.SignatureSize); err != nil {
			c.sendErr("bad-request", "sessionId", rs.id)
			return
		}
		out["sdp"], out["sig"] = m.Sdp, m.Sig
	case "ice":
		cand, ok := cleanCandidate(m.Candidate)
		if !ok {
			c.sendErr("bad-request", "sessionId", rs.id)
			return
		}
		out["candidate"] = cand
	case "session-end":
		out["reason"] = cleanReason(m.Reason, "ended")
		delete(h.sessions, rs.id)
	}
	rs.client.sendMsg(out)
}

// cleanCandidate accepts an RTCIceCandidateInit object (or null) of bounded size.
func cleanCandidate(raw json.RawMessage) (json.RawMessage, bool) {
	if len(raw) == 0 || len(raw) > maxCandidate {
		return nil, false
	}
	if string(raw) == "null" {
		return raw, true
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, false
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, false
	}
	return b, true
}
