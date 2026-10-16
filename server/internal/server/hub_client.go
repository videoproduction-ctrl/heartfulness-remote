package server

import (
	"bytes"
	"net/http"
	"time"

	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
	"github.com/videoproduction-ctrl/heartfulness-remote/server/internal/store"
)

func (s *Server) handleWSClient(w http.ResponseWriter, r *http.Request) {
	if !s.checkWSOrigin(r, false) {
		writeError(w, http.StatusForbidden, "bad-origin")
		return
	}
	cookie := ""
	if r.Header.Get("Origin") == s.cfg.Origin {
		if ck, err := r.Cookie(s.cfg.CookieName()); err == nil {
			cookie = ck.Value
		}
	}
	c := s.hub.accept(w, r, false)
	if c == nil {
		return
	}
	c.cookieTok = cookie
	c.serve(s.hub.onClient)
}

func (h *hub) onClient(c *conn, m *inMsg) bool {
	s := h.s
	switch c.stage {
	case 0:
		if m.Type != "auth" {
			c.fail("auth-required")
			return false
		}
		tok, kind := c.cookieTok, store.KindCookie
		if m.Token != "" {
			tok, kind = m.Token, store.KindBearer
		}
		c.cookieTok = ""
		a := s.lookupSession(tok, kind)
		if a == nil {
			c.fail("unauthorized")
			return false
		}
		c.sessionHash = a.hash
		c.nonce = randBytes(proto.NonceSize)
		c.stage = 1
		c.sendMsg(msg{"type": "challenge", "nonce": proto.B64(c.nonce)})
		return true
	case 1:
		if m.Type != "device-auth" {
			c.fail("auth-required")
			return false
		}
		pub, ok := b64Key(m.DevicePub)
		sig, err := proto.UnB64Len(m.Sig, proto.SignatureSize)
		if !ok || err != nil {
			c.fail("bad-request")
			return false
		}
		if !proto.Verify(pub, sig, proto.LabelClientAuth, proto.Str(s.cfg.Origin), c.nonce) {
			s.authFailureIP(c.ip, "device signature")
			c.fail("bad-signature")
			return false
		}
		return h.registerClient(c, proto.B64(pub))
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.clients[c]; !ok {
		return false
	}
	switch m.Type {
	case "pair-start":
		h.pairStartLocked(c, m)
	case "pair-reveal":
		h.pairRevealLocked(c, m)
	case "pair-approve":
		h.pairApproveLocked(c, m)
	case "pair-deny":
		h.pairDenyLocked(c, m)
	case "revoke-request":
		h.revokeRequestLocked(c, m)
	case "kill-request":
		h.killRequestLocked(c, m)
	case "session-request":
		h.sessionRequestLocked(c, m)
	case "offer", "ice", "session-end":
		h.clientSessionLocked(c, m)
	default:
		c.sendErr("unknown-type", "for", m.Type)
	}
	return true
}

func (h *hub) registerClient(c *conn, devicePub string) bool {
	s := h.s
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.clients) >= maxClientConns {
		c.fail("too-many-connections")
		return false
	}
	c.devicePub = devicePub
	c.authed = true
	c.stage = 2
	h.preAuth--
	h.clients[c] = struct{}{}
	device := msg{"status": store.StatusUnknown}
	s.st.View(func(st *store.State) {
		if d, ok := st.Devices[devicePub]; ok {
			device["status"] = d.Status
			if d.Status == store.StatusApproved && d.Cert != nil {
				device["cert"] = *d.Cert
			}
		}
	})
	c.sendMsg(msg{"type": "ready", "device": device, "host": h.hostInfoLocked()})
	if device["status"] == store.StatusApproved {
		for _, p := range h.pairings {
			if p.revealed && !p.bad {
				c.sendMsg(h.approvalNeeded(p))
			}
		}
	}
	s.touchDevice(devicePub, false)
	return true
}

// requireApproved checks (from the store, which mirrors the Mac's
// signatures) that the connection's device is approved.
func (h *hub) requireApprovedLocked(c *conn, m *inMsg) bool {
	if h.s.deviceStatus(c.devicePub) != store.StatusApproved {
		c.sendErr("not-approved", "for", m.Type)
		return false
	}
	return true
}

func (h *hub) requireHostLocked(c *conn, m *inMsg) bool {
	if h.host == nil {
		c.sendErr("host-offline", "for", m.Type)
		return false
	}
	return true
}

// ---- pairing (§5) ----

func (h *hub) pairStartLocked(c *conn, m *inMsg) {
	if h.s.deviceStatus(c.devicePub) == store.StatusApproved {
		c.sendErr("already-approved", "for", m.Type)
		return
	}
	if !h.requireHostLocked(c, m) {
		return
	}
	name, okName := cleanName(m.Name)
	commit, err := proto.UnB64Len(m.Commit, 32)
	if !okName || !validKind(m.Kind) || err != nil {
		c.sendErr("bad-request", "for", m.Type)
		return
	}
	for _, p := range h.pairings {
		if p.devicePub == c.devicePub {
			c.sendErr("pairing-in-progress", "for", m.Type, "requestId", p.id)
			return
		}
	}
	if len(h.pairings) >= maxPairings {
		c.sendErr("too-many-pending", "for", m.Type)
		return
	}
	raw := randBytes(proto.IDSize)
	p := &pairing{
		id: proto.B64(raw), idRaw: raw, conn: c, devicePub: c.devicePub,
		name: name, kind: m.Kind, commit: commit, created: h.s.now(),
	}
	h.pairings[p.id] = p
	h.host.sendMsg(msg{"type": "pair-request", "requestId": p.id, "devicePub": "", "name": name, "kind": m.Kind, "commit": m.Commit})
	c.sendMsg(msg{"type": "pair-pending", "requestId": p.id})
}

func (h *hub) pairChallengeLocked(c *conn, m *inMsg) {
	p := h.pairings[m.RequestID]
	if p == nil || p.challenged {
		c.sendErr("unknown-request", "requestId", m.RequestID)
		return
	}
	hostPub := h.hostPubBytes(c)
	claimed, ok := b64Key(m.HostPub)
	na, errNa := proto.UnB64Len(m.Na, 32)
	sig, errSig := proto.UnB64Len(m.Sig, proto.SignatureSize)
	if !ok || errNa != nil || errSig != nil || !bytes.Equal(claimed, hostPub) {
		c.sendErr("bad-request", "requestId", p.id)
		return
	}
	if !proto.Verify(hostPub, sig, proto.LabelPairChallenge, p.idRaw, p.commit, na, hostPub) {
		c.sendErr("bad-signature", "requestId", p.id)
		return
	}
	p.na, p.hostSg, p.challenged = na, sig, true
	if p.conn != nil {
		p.conn.sendMsg(msg{"type": "pair-challenge", "requestId": p.id, "hostPub": c.hostPub, "na": m.Na, "sig": m.Sig})
	}
}

func (h *hub) pairRevealLocked(c *conn, m *inMsg) {
	p := h.pairings[m.RequestID]
	if p == nil || p.devicePub != c.devicePub {
		c.sendErr("unknown-request", "requestId", m.RequestID)
		return
	}
	if !p.challenged || p.revealed {
		c.sendErr("bad-state", "requestId", p.id)
		return
	}
	nd, err := proto.UnB64Len(m.Nd, 32)
	if err != nil {
		c.sendErr("bad-request", "requestId", p.id)
		return
	}
	if !h.requireHostLocked(c, m) {
		return
	}
	p.conn = c
	devPub := h.devicePubBytes(c)
	p.nd, p.revealed = nd, true
	// devicePub comes from the authenticated connection, never from the message.
	h.host.sendMsg(msg{"type": "pair-reveal", "requestId": p.id, "devicePub": c.devicePub, "nd": m.Nd})
	if !bytes.Equal(proto.PairCommit(devPub, nd), p.commit) {
		// The host will reject it too; never ask the owner to approve it.
		p.bad = true
		return
	}
	now := h.s.now()
	_ = h.s.st.Update(func(st *store.State) error {
		d, ok := st.Devices[p.devicePub]
		if ok && d.Status == store.StatusApproved {
			return store.ErrNoChange
		}
		st.Devices[p.devicePub] = &store.Device{Pub: p.devicePub, Name: p.name, Kind: p.kind, Status: store.StatusPending, CreatedAt: now}
		st.AddEvent(store.Event{Time: now, Type: "device-pending", Device: p.name, IP: c.ip.String()})
		return nil
	})
	h.toApproversLocked(h.approvalNeeded(p))
	h.broadcastDevicesChangedLocked()
}

func (h *hub) approvalNeeded(p *pairing) msg {
	return msg{
		"type": "approval-needed", "requestId": p.id, "name": p.name, "kind": p.kind,
		"devicePub": p.devicePub, "nd": proto.B64(p.nd), "commit": proto.B64(p.commit),
		"na": proto.B64(p.na), "hostSig": proto.B64(p.hostSg),
	}
}

func (h *hub) devicePubBytes(c *conn) []byte {
	b, _ := proto.UnB64Len(c.devicePub, proto.PubKeySize)
	return b
}

func (h *hub) pairApproveLocked(c *conn, m *inMsg) {
	if !h.requireApprovedLocked(c, m) || !h.requireHostLocked(c, m) {
		return
	}
	p := h.pairings[m.RequestID]
	if p == nil || !p.revealed || p.bad {
		c.sendErr("unknown-request", "requestId", m.RequestID)
		return
	}
	sig, err := proto.UnB64Len(m.Sig, proto.SignatureSize)
	if err != nil {
		c.sendErr("bad-request", "requestId", p.id)
		return
	}
	devPub, _ := proto.UnB64Len(p.devicePub, proto.PubKeySize)
	hostPub := h.hostPubBytes(h.host)
	if !proto.Verify(h.devicePubBytes(c), sig, proto.LabelPairApprove, p.idRaw, hostPub, devPub, p.nd, p.na, proto.Str(p.name), proto.Str(p.kind)) {
		h.s.authFailureIP(c.ip, "pair-approve signature")
		c.sendErr("bad-signature", "requestId", p.id)
		return
	}
	h.host.sendMsg(msg{"type": "pair-approve", "requestId": p.id, "approverPub": c.devicePub, "sig": m.Sig})
}

func (h *hub) pairDenyLocked(c *conn, m *inMsg) {
	if !h.requireApprovedLocked(c, m) || !h.requireHostLocked(c, m) {
		return
	}
	p := h.pairings[m.RequestID]
	if p == nil {
		c.sendErr("unknown-request", "requestId", m.RequestID)
		return
	}
	h.host.sendMsg(msg{"type": "pair-deny", "requestId": p.id, "approverPub": c.devicePub})
}

func (h *hub) pairResultLocked(c *conn, m *inMsg) {
	s := h.s
	p := h.pairings[m.RequestID]
	if p == nil || m.Approved == nil {
		c.sendErr("unknown-request", "requestId", m.RequestID)
		return
	}
	now := s.now()
	finish := func(toDevice msg) {
		if p.conn != nil {
			p.conn.sendMsg(toDevice)
		}
		if p.revealed && !p.bad {
			h.toApproversLocked(msg{"type": "approval-closed", "requestId": p.id})
		}
		delete(h.pairings, p.id)
		h.broadcastDevicesChangedLocked()
	}
	if !*m.Approved {
		_ = s.st.Update(func(st *store.State) error {
			if d, ok := st.Devices[p.devicePub]; ok && d.Status == store.StatusPending {
				delete(st.Devices, p.devicePub)
			}
			st.AddEvent(store.Event{Time: now, Type: "device-denied", Device: p.name})
			return nil
		})
		finish(msg{"type": "pair-denied", "requestId": p.id, "reason": cleanReason(m.Reason, "denied")})
		return
	}
	if !p.revealed || p.bad || m.Cert == nil || m.Cert.Verify(h.hostPubBytes(c)) != nil || m.Cert.DevicePub != p.devicePub {
		s.log.Warn("pair-result rejected: certificate is not valid for this request")
		c.sendErr("bad-cert", "requestId", p.id)
		finish(msg{"type": "pair-denied", "requestId": p.id, "reason": "error"})
		return
	}
	ct := *m.Cert
	_ = s.st.Update(func(st *store.State) error {
		name, kind := certNameKind(ct, p.name, p.kind)
		d, ok := st.Devices[p.devicePub]
		if !ok {
			d = &store.Device{Pub: p.devicePub, CreatedAt: now}
			st.Devices[p.devicePub] = d
		}
		d.Name, d.Kind, d.Status, d.Cert, d.RevokedAt = name, kind, store.StatusApproved, &ct, time.Time{}
		st.AddEvent(store.Event{Time: now, Type: "device-approved", Device: name})
		return nil
	})
	finish(msg{"type": "pair-approved", "requestId": p.id, "cert": ct})
}

// ---- device management ----

func (h *hub) revokeRequestLocked(c *conn, m *inMsg) {
	if !h.requireApprovedLocked(c, m) || !h.requireHostLocked(c, m) {
		return
	}
	target, ok := b64Key(m.TargetPub)
	sig, err := proto.UnB64Len(m.Sig, proto.SignatureSize)
	if !ok || err != nil {
		c.sendErr("bad-request", "for", m.Type)
		return
	}
	if !proto.FreshTimestamp(m.Ts, h.s.now()) {
		c.sendErr("stale", "for", m.Type)
		return
	}
	if !proto.Verify(h.devicePubBytes(c), sig, proto.LabelRevokeRequest, h.hostPubBytes(h.host), target, proto.Int(m.Ts)) {
		h.s.authFailureIP(c.ip, "revoke-request signature")
		c.sendErr("bad-signature", "for", m.Type)
		return
	}
	h.host.sendMsg(msg{"type": "revoke-request", "targetPub": m.TargetPub, "ts": m.Ts, "approverPub": c.devicePub, "sig": m.Sig})
}

func (h *hub) killRequestLocked(c *conn, m *inMsg) {
	if !h.requireApprovedLocked(c, m) || !h.requireHostLocked(c, m) {
		return
	}
	if m.Action != "kill" && m.Action != "resume" {
		c.sendErr("bad-request", "for", m.Type)
		return
	}
	sig, err := proto.UnB64Len(m.Sig, proto.SignatureSize)
	if err != nil {
		c.sendErr("bad-request", "for", m.Type)
		return
	}
	if !proto.FreshTimestamp(m.Ts, h.s.now()) {
		c.sendErr("stale", "for", m.Type)
		return
	}
	if !proto.Verify(h.devicePubBytes(c), sig, proto.LabelKillRequest, h.hostPubBytes(h.host), proto.Str(m.Action), proto.Int(m.Ts)) {
		h.s.authFailureIP(c.ip, "kill-request signature")
		c.sendErr("bad-signature", "for", m.Type)
		return
	}
	h.host.sendMsg(msg{"type": "kill-request", "action": m.Action, "ts": m.Ts, "approverPub": c.devicePub, "sig": m.Sig})
}

// ---- sessions ----

func (h *hub) sessionRequestLocked(c *conn, m *inMsg) {
	if !h.requireApprovedLocked(c, m) || !h.requireHostLocked(c, m) {
		return
	}
	if _, err := proto.UnB64Len(m.SessionID, proto.IDSize); err != nil {
		c.sendErr("bad-request", "for", m.Type)
		return
	}
	if _, err := proto.UnB64Len(m.ClientNonce, proto.NonceSize); err != nil {
		c.sendErr("bad-request", "for", m.Type, "sessionId", m.SessionID)
		return
	}
	if _, exists := h.sessions[m.SessionID]; exists {
		c.sendErr("duplicate-session", "sessionId", m.SessionID)
		return
	}
	mine := 0
	for _, rs := range h.sessions {
		if rs.client == c {
			mine++
		}
	}
	if mine >= maxSessionsPerConn || len(h.sessions) >= maxSessions {
		c.sendErr("too-many-sessions", "sessionId", m.SessionID)
		return
	}
	h.sessions[m.SessionID] = &rtcSession{id: m.SessionID, client: c, devicePub: c.devicePub, created: h.s.now()}
	out := msg{"type": "session-request", "sessionId": m.SessionID, "devicePub": c.devicePub, "clientNonce": m.ClientNonce}
	if m.RelayOnly {
		out["relayOnly"] = true
	}
	h.host.sendMsg(out)
}

func (h *hub) clientSessionLocked(c *conn, m *inMsg) {
	rs := h.sessions[m.SessionID]
	if rs == nil || rs.client != c {
		c.sendErr("unknown-session", "sessionId", m.SessionID)
		return
	}
	if h.host == nil {
		c.sendErr("host-offline", "sessionId", rs.id)
		return
	}
	out := msg{"type": m.Type, "sessionId": rs.id}
	switch m.Type {
	case "offer":
		if !h.requireApprovedLocked(c, m) {
			return
		}
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
	h.host.sendMsg(out)
}
