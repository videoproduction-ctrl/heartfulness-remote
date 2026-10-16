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
	maxPendingHosts    = 5 // unbound Macs waiting to be claimed or to join
	maxPendingPerIP    = 2
	pendingJoinTTL     = 30 * time.Minute // a waiting (join) Mac is dropped after this
	maxJoinsPerHost    = 4                // outstanding join/finish requests per waiting Mac
	maxClientConns     = 20
	maxPreAuthConns    = 64
	maxPairingsPerHost = 3 // PROTOCOL.md §5: at most 3 pending per Mac
	maxPairings        = 32
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
	HostMac     string            `json:"hostMac"`
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
	authed bool

	// Host connections.
	hostPub      string // b64
	hostName     string
	macID        string
	claimCommit  []byte
	bound        bool                // bound to the owner and in hub.hosts
	pendingSince time.Time           // when it started waiting (unbound)
	hostState    string              // bound: available | in-session | blocked
	hostSessDev  string              // bound: name of the device in session
	joins        map[string]*joinReq // waiting Mac: devicePub → outstanding join

	// Client connections.
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
	defer c.h.wg.Done()
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

// setupDevice is the claim's first device (§4), re-sent to the claimed Mac
// after a reconnect until it answers.
type setupDevice struct {
	HostPub   string
	DevicePub string
	Name      string
	Kind      string
	SetupMac  string
	expires   time.Time
}

// joinReq is an outstanding join/finish for a waiting Mac (§10.2).
type joinReq struct {
	devicePub, name, kind string
	expires               time.Time
}

type pairing struct {
	id         string
	idRaw      []byte
	conn       *conn  // requesting device connection (nil if it went away)
	devicePub  string // b64, from the authenticated connection
	hostPub    string // b64, the Mac being paired with
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
	hostPub   string
	accepted  bool
	created   time.Time
}

type hub struct {
	s  *Server
	mu sync.Mutex
	wg sync.WaitGroup // live connection handlers

	all          map[*conn]struct{}
	preAuth      int
	hosts        map[string]*conn // bound, connected Macs by b64 host key
	pendingHosts map[string]*conn // authenticated but unbound Macs (claim or join)
	clients      map[*conn]struct{}
	pairings     map[string]*pairing
	sessions     map[string]*rtcSession
	setup        *setupDevice
}

func newHub(s *Server) *hub {
	return &hub{
		s:            s,
		all:          map[*conn]struct{}{},
		hosts:        map[string]*conn{},
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
	h.wg.Add(1)
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
			bound := c.bound && h.hosts[c.hostPub] == c
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
		if h.hosts[c.hostPub] == c {
			delete(h.hosts, c.hostPub)
			c.bound = false
			h.hostGoneLocked(c.hostPub, "host-offline", true)
			h.s.touchHost(c.hostPub)
			h.s.log.Info("host disconnected", "macId", c.macID)
		}
		if h.pendingHosts[c.hostPub] == c {
			delete(h.pendingHosts, c.hostPub)
		}
		return
	}
	delete(h.clients, c)
	for id, rs := range h.sessions {
		if rs.client == c {
			if hc := h.hosts[rs.hostPub]; hc != nil {
				hc.sendMsg(msg{"type": "session-end", "sessionId": id, "reason": "client-disconnected"})
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

// hostGoneLocked ends the sessions and pairings of one Mac after its
// connection went away (or it was removed); notify broadcasts host-status.
func (h *hub) hostGoneLocked(hostPub, reason string, notify bool) {
	for id, rs := range h.sessions {
		if rs.hostPub != hostPub {
			continue
		}
		rs.client.sendMsg(msg{"type": "session-end", "sessionId": id, "hostPub": hostPub, "reason": reason})
		delete(h.sessions, id)
	}
	for id, p := range h.pairings {
		if p.hostPub != hostPub {
			continue
		}
		if p.conn != nil {
			p.conn.sendMsg(msg{"type": "pair-denied", "requestId": id, "hostPub": hostPub, "reason": reason})
		}
		if p.revealed && !p.bad {
			h.toApproversLocked(hostPub, msg{"type": "approval-closed", "requestId": id, "hostPub": hostPub}, p.devicePub)
		}
		delete(h.pairings, id)
	}
	if notify {
		h.broadcastHostStatusLocked(hostPub)
	}
}

// closeAll asks every connection to close and waits (up to timeout) for
// their handlers to finish.
func (h *hub) closeAll(timeout time.Duration) {
	h.mu.Lock()
	for c := range h.all {
		c.closeWith(websocket.StatusGoingAway, "shutdown")
	}
	h.mu.Unlock()
	done := make(chan struct{})
	go func() {
		h.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		h.mu.Lock()
		for c := range h.all {
			c.abort()
		}
		h.mu.Unlock()
		<-done
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

// hostInfo is the live view of one bound Mac.
type hostInfo struct {
	Pub               string `json:"pub"`
	MacID             string `json:"macId"`
	Name              string `json:"name"`
	Online            bool   `json:"online"`
	State             string `json:"state"`
	SessionDeviceName string `json:"sessionDeviceName"`
}

func (h *hub) liveInfoLocked(hb *store.HostBinding) hostInfo {
	info := hostInfo{Pub: hb.Pub, MacID: hb.MacID, Name: hb.Name, State: hostOffline}
	if hc := h.hosts[hb.Pub]; hc != nil {
		info.Online, info.State, info.SessionDeviceName = true, hc.hostState, hc.hostSessDev
	}
	return info
}

// hostInfoLocked describes one bound Mac (ok=false if it is not bound).
func (h *hub) hostInfoLocked(hostPub string) (info hostInfo, ok bool) {
	h.s.st.View(func(st *store.State) {
		if hb := st.Host(hostPub); hb != nil {
			info, ok = h.liveInfoLocked(hb), true
		}
	})
	return info, ok
}

func (h *hub) hostInfo(hostPub string) (hostInfo, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hostInfoLocked(hostPub)
}

// readyHost is one entry of ready.hosts (§10.4): the Mac plus this device's
// approval status on it.
type readyHost struct {
	hostInfo
	DeviceStatus string      `json:"deviceStatus"`
	Cert         *proto.Cert `json:"cert,omitempty"`
}

func (h *hub) readyHostsLocked(devicePub string) []readyHost {
	out := []readyHost{}
	h.s.st.View(func(st *store.State) {
		d := st.Devices[devicePub]
		for _, hb := range st.Hosts {
			rh := readyHost{hostInfo: h.liveInfoLocked(hb), DeviceStatus: store.StatusUnknown}
			if a := d.Approval(hb.Pub); a != nil {
				rh.DeviceStatus = a.Status
				if a.Status == store.StatusApproved && a.Cert != nil {
					ct := *a.Cert
					rh.Cert = &ct
				}
			}
			out = append(out, rh)
		}
	})
	return out
}

// meHost is one entry of /api/me hosts (§10.4).
type meHost struct {
	hostInfo
	ClaimedAt int64 `json:"claimedAt"`
	LastSeen  int64 `json:"lastSeen"`
}

func (h *hub) meHosts() []meHost {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.s.now()
	out := []meHost{}
	h.s.st.View(func(st *store.State) {
		for _, hb := range st.Hosts {
			mh := meHost{hostInfo: h.liveInfoLocked(hb), ClaimedAt: unix(hb.ClaimedAt), LastSeen: unix(hb.LastSeen)}
			if mh.Online {
				mh.LastSeen = now.Unix()
			}
			out = append(out, mh)
		}
	})
	return out
}

func (h *hub) broadcastHostStatusLocked(hostPub string) {
	info, ok := h.hostInfoLocked(hostPub)
	if !ok {
		return
	}
	m := msg{"type": "host-status", "hostPub": hostPub, "online": info.Online, "state": info.State, "sessionDeviceName": info.SessionDeviceName}
	for c := range h.clients {
		c.sendMsg(m)
	}
}

func (h *hub) broadcastHostsChangedLocked() {
	for c := range h.clients {
		c.sendMsg(msg{"type": "hosts-changed"})
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

// approvedOn returns the set of device keys approved on one Mac.
func (h *hub) approvedOn(hostPub string) map[string]bool {
	out := map[string]bool{}
	h.s.st.View(func(st *store.State) {
		for k, d := range st.Devices {
			if a := d.Approval(hostPub); a != nil && a.Status == store.StatusApproved {
				out[k] = true
			}
		}
	})
	return out
}

// toApproversLocked sends m to connected devices approved on hostPub, except
// the device the message is about (exclude).
func (h *hub) toApproversLocked(hostPub string, m msg, exclude ...string) {
	approved := h.approvedOn(hostPub)
	for _, x := range exclude {
		delete(approved, x)
	}
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

// approvalStatus is a device's status on one Mac (store mirror of the Mac's
// signed decisions).
func (s *Server) approvalStatus(devicePub, hostPub string) string {
	status := store.StatusUnknown
	s.st.View(func(st *store.State) { status = st.ApprovalStatus(devicePub, hostPub) })
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

// touchHost records when a bound Mac was last connected.
func (s *Server) touchHost(pub string) {
	now := s.now()
	_ = s.st.Update(func(st *store.State) error {
		hb := st.Host(pub)
		if hb == nil {
			return store.ErrNoChange
		}
		hb.LastSeen = now
		return nil
	})
}

// expire runs the in-memory expiry sweep.
func (h *hub) expire(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, p := range h.pairings {
		if now.Sub(p.created) >= pairingTTL {
			if p.conn != nil {
				p.conn.sendMsg(msg{"type": "pair-denied", "requestId": id, "hostPub": p.hostPub, "reason": "expired"})
			}
			if p.revealed && !p.bad {
				h.toApproversLocked(p.hostPub, msg{"type": "approval-closed", "requestId": id, "hostPub": p.hostPub}, p.devicePub)
			}
			delete(h.pairings, id)
		}
	}
	for id, rs := range h.sessions {
		if !rs.accepted && now.Sub(rs.created) >= sessionRequestTTL {
			rs.client.sendMsg(msg{"type": "session-end", "sessionId": id, "hostPub": rs.hostPub, "reason": "timeout"})
			if hc := h.hosts[rs.hostPub]; hc != nil {
				hc.sendMsg(msg{"type": "session-end", "sessionId": id, "reason": "timeout"})
			}
			delete(h.sessions, id)
		}
	}
	if h.setup != nil && !now.Before(h.setup.expires) {
		h.setup = nil
	}
	claimed := h.s.claimed()
	for pub, c := range h.pendingHosts {
		for dev, j := range c.joins {
			if !now.Before(j.expires) {
				delete(c.joins, dev)
			}
		}
		// A Mac waiting to join a claimed server is kept for 30 minutes; it
		// reconnects (and shows a fresh code) if it is still waiting.
		if claimed && now.Sub(c.pendingSince) >= pendingJoinTTL {
			delete(h.pendingHosts, pub)
			c.fail("join-expired")
		}
	}
	for c := range h.clients {
		if !h.s.sessionValid(c.sessionHash) {
			c.fail("session-expired")
			continue
		}
		h.s.touchSession(c.sessionHash)
	}
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
