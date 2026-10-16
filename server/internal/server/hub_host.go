package server

import (
	"crypto/subtle"
	"errors"

	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
	"github.com/videoproduction-ctrl/heartfulness-remote/server/internal/store"
)

// ---- host messages (/ws/host) ----

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
	if !c.bound || h.hosts[c.hostPub] != c {
		if h.pendingHosts[c.hostPub] == c {
			switch m.Type {
			case "claim-commit":
				if b, err := proto.UnB64Len(m.ClaimCommit, 32); err == nil {
					c.claimCommit = b
				} else {
					c.sendErr("bad-request", "for", m.Type)
				}
				return true
			case "device-approved":
				if len(c.joins) > 0 {
					h.joinApprovedLocked(c, m)
					return true
				}
			}
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
		// Already bound: nothing to do.
	default:
		c.sendErr("unknown-type", "for", m.Type)
	}
	return true
}

func (h *hub) hostReady(c *conn, claimed, joined bool) msg {
	return msg{"type": "host-ready", "claimed": claimed, "joined": joined, "origin": h.s.cfg.Origin, "macId": c.macID, "iceServers": h.s.iceServers()}
}

// hostAuth authenticates a Mac. A key bound to the owner becomes an online
// host (replacing an older connection of the same key). Any other key waits:
// to claim an unclaimed server (§4) or to join a claimed one (§10.2).
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
	if !s.cfg.HostAllowed(pub) {
		s.authFailureIP(c.ip, "host key not in HR_HOST_PUBKEY")
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
	now := s.now()

	h.mu.Lock()
	defer h.mu.Unlock()
	var claimed, bound bool
	var boundName string
	s.st.View(func(st *store.State) {
		claimed = st.Claimed()
		if hb := st.Host(pubB64); hb != nil {
			bound, boundName = true, hb.Name
		}
	})
	c.stage = 1
	c.hostPub, c.hostName, c.macID = pubB64, name, proto.MacID(pub)
	if bound {
		if old := h.hosts[pubB64]; old != nil {
			delete(h.hosts, pubB64)
			old.bound = false
			old.fail("replaced")
			h.hostGoneLocked(pubB64, "host-reconnected", false)
		}
		c.authed, c.bound = true, true
		h.preAuth--
		h.hosts[pubB64] = c
		c.hostState = hostAvailable
		_ = s.st.Update(func(st *store.State) error {
			hb := st.Host(pubB64)
			if hb == nil {
				return store.ErrNoChange
			}
			hb.Name, hb.LastSeen = name, now
			return nil
		})
		c.sendMsg(h.hostReady(c, true, true))
		h.sendSetupLocked()
		h.broadcastHostStatusLocked(pubB64)
		if name != boundName {
			h.broadcastHostsChangedLocked()
		}
		s.log.Info("host connected", "host", proto.Fingerprint(pub), "macId", c.macID)
		return true
	}
	if old := h.pendingHosts[pubB64]; old != nil {
		delete(h.pendingHosts, pubB64)
		old.fail("replaced")
	} else {
		sameIP := 0
		for _, pc := range h.pendingHosts {
			if limitKey(pc.ip) == limitKey(c.ip) {
				sameIP++
			}
		}
		if len(h.pendingHosts) >= maxPendingHosts || sameIP >= maxPendingPerIP {
			c.fail("too-many-pending")
			return false
		}
	}
	c.authed = true
	c.claimCommit = commit
	c.pendingSince = now
	h.preAuth--
	h.pendingHosts[pubB64] = c
	c.sendMsg(h.hostReady(c, claimed, false))
	if claimed {
		s.log.Info("Mac waiting to join", "host", proto.Fingerprint(pub), "macId", c.macID)
	} else {
		s.log.Info("unclaimed host connected", "host", proto.Fingerprint(pub))
	}
	return true
}

func (h *hub) hostPubBytes(c *conn) []byte {
	b, _ := proto.UnB64Len(c.hostPub, proto.PubKeySize)
	return b
}

// ---- claim (§4) ----

// pendingCommit returns the claim commit of a connected, unbound Mac.
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
// promotes its connection and forwards setup-device to it. Other waiting Macs
// become join candidates of the now-claimed server.
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
	now := h.s.now()
	delete(h.pendingHosts, hostPub)
	c.bound, c.claimCommit = true, nil
	h.hosts[hostPub] = c
	c.hostState = hostAvailable
	c.sendMsg(h.hostReady(c, true, true))
	for _, other := range h.pendingHosts {
		other.pendingSince = now
		other.sendMsg(h.hostReady(other, true, false))
	}
	sd.HostPub = hostPub
	sd.expires = now.Add(setupResendTTL)
	h.setup = &sd
	h.sendSetupLocked()
	h.broadcastHostStatusLocked(hostPub)
	h.broadcastHostsChangedLocked()
	return nil
}

func (h *hub) sendSetupLocked() {
	sd := h.setup
	if sd == nil {
		return
	}
	if !h.s.now().Before(sd.expires) || h.s.approvalStatus(sd.DevicePub, sd.HostPub) != store.StatusPending {
		h.setup = nil
		return
	}
	if hc := h.hosts[sd.HostPub]; hc != nil {
		hc.sendMsg(msg{"type": "setup-device", "devicePub": sd.DevicePub, "name": sd.Name, "kind": sd.Kind, "setupMac": sd.SetupMac})
	}
}

// ---- join (§10.2) ----

var (
	errAmbiguous   = errors.New("more than one Mac with this Mac ID")
	errLastHost    = errors.New("cannot remove the last Mac")
	errStaleCommit = errors.New("the Mac shows a different code now")
)

// pendingByMacID finds the waiting Mac (with a join code) whose Mac ID is macID.
func (h *hub) pendingByMacID(macID string) (hostPub, name string, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for pub, c := range h.pendingHosts {
		if c.macID == macID && c.claimCommit != nil && !c.closing() {
			hostPub, name = pub, c.hostName
			n++
		}
	}
	switch {
	case n == 0:
		return "", "", errNotFound
	case n > 1:
		return "", "", errAmbiguous
	}
	return hostPub, name, nil
}

// pendingJoin returns what join/begin needs to know about a waiting Mac.
func (h *hub) pendingJoin(hostPub string) (commit []byte, name, macID string, ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	c := h.pendingHosts[hostPub]
	if c == nil || c.closing() {
		return nil, "", "", false
	}
	return append([]byte(nil), c.claimCommit...), c.hostName, c.macID, true
}

// startJoin forwards setup-device for an approved device to a waiting Mac
// (join/finish). commit is the claim commit checked at join/begin: the Mac
// must still show that code.
func (h *hub) startJoin(hostPub string, commit []byte, devicePub, name, kind, setupMac string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	c := h.pendingHosts[hostPub]
	if c == nil || c.closing() {
		return errHostGone
	}
	if c.claimCommit == nil || subtle.ConstantTimeCompare(c.claimCommit, commit) != 1 {
		return errStaleCommit
	}
	full := false
	h.s.st.View(func(st *store.State) { full = len(st.Hosts) >= store.MaxHosts })
	if full {
		return store.ErrTooManyHosts
	}
	if c.joins == nil {
		c.joins = map[string]*joinReq{}
	}
	if _, again := c.joins[devicePub]; !again && len(c.joins) >= maxJoinsPerHost {
		return errFull
	}
	c.joins[devicePub] = &joinReq{devicePub: devicePub, name: name, kind: kind, expires: h.s.now().Add(setupResendTTL)}
	c.sendMsg(msg{"type": "setup-device", "devicePub": devicePub, "name": name, "kind": kind, "setupMac": setupMac})
	return nil
}

// joinApprovedLocked handles device-approved from a waiting Mac: only a cert
// signed by THIS Mac's key, for a device with an outstanding join, binds the
// Mac to the owner (§10.2 step 5).
func (h *hub) joinApprovedLocked(c *conn, m *inMsg) {
	s := h.s
	hostPub := c.hostPub
	if m.Cert == nil || m.Cert.Verify(h.hostPubBytes(c)) != nil {
		s.log.Warn("join: device-approved with a certificate not signed by this Mac")
		c.sendErr("bad-cert", "for", m.Type)
		return
	}
	ct := *m.Cert
	j := c.joins[ct.DevicePub]
	if j == nil || !s.now().Before(j.expires) {
		s.log.Warn("join: device-approved for a device that did not ask to join")
		c.sendErr("unknown-device", "for", m.Type)
		return
	}
	if _, err := proto.UnB64Len(m.HostMac, 32); err != nil {
		c.sendErr("bad-request", "for", m.Type)
		return
	}
	now := s.now()
	var devName string
	err := s.st.Update(func(st *store.State) error {
		if !st.Claimed() {
			return errNotClaimed
		}
		if err := st.AddHost(store.HostBinding{Pub: hostPub, Name: c.hostName, MacID: c.macID, ClaimedAt: now, LastSeen: now}); err != nil {
			return err
		}
		d := st.Devices[ct.DevicePub]
		if d == nil {
			d = &store.Device{Pub: ct.DevicePub, Name: j.name, Kind: j.kind, CreatedAt: now}
			st.Devices[ct.DevicePub] = d
		}
		d.Name, d.Kind = certNameKind(ct, d.Name, d.Kind)
		d.SetApproval(hostPub, &store.Approval{Status: store.StatusApproved, Cert: &ct, CreatedAt: now})
		devName = d.Name
		st.AddEvent(store.Event{Time: now, Type: "mac-joined", Device: devName})
		return nil
	})
	if errors.Is(err, store.ErrTooManyHosts) {
		delete(c.joins, ct.DevicePub)
		c.sendErr("too-many-hosts", "for", m.Type)
		h.toDeviceLocked(ct.DevicePub, msg{"type": "error", "code": "too-many-hosts", "for": "join", "hostPub": hostPub})
		return
	}
	if err != nil {
		s.log.Error("join failed", "err", err)
		c.sendErr("internal", "for", m.Type)
		return
	}
	delete(h.pendingHosts, hostPub)
	c.joins, c.claimCommit = nil, nil
	c.bound = true
	h.hosts[hostPub] = c
	c.hostState = hostAvailable
	c.sendMsg(h.hostReady(c, true, true))
	h.toDeviceLocked(ct.DevicePub, msg{"type": "host-joined", "hostPub": hostPub, "cert": ct, "hostMac": m.HostMac})
	h.broadcastHostStatusLocked(hostPub)
	h.broadcastHostsChangedLocked()
	h.broadcastDevicesChangedLocked()
	s.log.Info("Mac joined the account", "host", proto.Fingerprint(h.hostPubBytes(c)), "macId", c.macID)
}

// removeHost unbinds a Mac (POST /api/hosts/remove): its approvals are
// dropped and its connection is closed with error "removed".
func (h *hub) removeHost(hostPub, byDevice, ip string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	var bound bool
	var count int
	h.s.st.View(func(st *store.State) {
		bound, count = st.Host(hostPub) != nil, len(st.Hosts)
	})
	switch {
	case !bound:
		return errNotFound
	case count <= 1:
		return errLastHost
	}
	// End sessions and pairings while the Mac's approvers are still known.
	h.hostGoneLocked(hostPub, "host-removed", false)
	now := h.s.now()
	err := h.s.st.Update(func(st *store.State) error {
		if !st.RemoveHost(hostPub) {
			return errNotFound
		}
		st.AddEvent(store.Event{Time: now, Type: "mac-removed", Device: byDevice, IP: ip})
		return nil
	})
	if err != nil {
		return err
	}
	if c := h.hosts[hostPub]; c != nil {
		delete(h.hosts, hostPub)
		c.bound = false
		c.fail("removed")
	}
	if h.setup != nil && h.setup.HostPub == hostPub {
		h.setup = nil
	}
	h.broadcastHostsChangedLocked()
	h.broadcastDevicesChangedLocked()
	return nil
}

// ---- trust mirror ----

const maxTrustEntries = 1000

// trustSyncLocked mirrors one Mac's pins: certified devices become approved
// FOR THIS MAC, revoked ones revoked, and every other device this Mac had
// approved becomes revoked for this Mac only (the Mac is authoritative for
// itself; other Macs' approvals are untouched).
func (h *hub) trustSyncLocked(c *conn, m *inMsg) {
	s := h.s
	if len(m.Certs) > maxTrustEntries || len(m.Revocations) > maxTrustEntries {
		c.sendErr("too-large", "for", m.Type)
		return
	}
	hp := c.hostPub
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
	revoke := func(d *store.Device, a *store.Approval) {
		created := now
		if a != nil {
			created = a.CreatedAt
		}
		d.SetApproval(hp, &store.Approval{Status: store.StatusRevoked, CreatedAt: created, RevokedAt: now})
		revokedNow = append(revokedNow, d.Pub)
		changed = true
	}
	_ = s.st.Update(func(st *store.State) error {
		for pub, d := range st.Devices {
			a := d.Approval(hp)
			ct, isCert := certs[pub]
			switch {
			case revs[pub]:
				if a == nil || a.Status != store.StatusRevoked {
					revoke(d, a)
				}
			case isCert:
				nc := ct
				name, kind := certNameKind(ct, d.Name, d.Kind)
				if a == nil || a.Status != store.StatusApproved || a.Cert == nil || *a.Cert != nc || d.Name != name || d.Kind != kind {
					created := now
					if a != nil {
						created = a.CreatedAt
					}
					d.Name, d.Kind = name, kind
					d.SetApproval(hp, &store.Approval{Status: store.StatusApproved, Cert: &nc, CreatedAt: created})
					changed = true
				}
			case a != nil && a.Status == store.StatusApproved:
				revoke(d, a)
			}
		}
		for pub, ct := range certs {
			if _, ok := st.Devices[pub]; ok || revs[pub] {
				continue
			}
			nc := ct
			name, kind := certNameKind(ct, "Device", "unknown")
			d := &store.Device{Pub: pub, Name: name, Kind: kind, CreatedAt: now}
			d.SetApproval(hp, &store.Approval{Status: store.StatusApproved, Cert: &nc, CreatedAt: now})
			st.Devices[pub] = d
			changed = true
		}
		for pub := range revs {
			if _, ok := st.Devices[pub]; ok {
				continue
			}
			d := &store.Device{Pub: pub, Name: "Removed device", Kind: "unknown", CreatedAt: now}
			d.SetApproval(hp, &store.Approval{Status: store.StatusRevoked, CreatedAt: now, RevokedAt: now})
			st.Devices[pub] = d
			changed = true
		}
		if !changed {
			return store.ErrNoChange
		}
		st.AddEvent(store.Event{Time: now, Type: "trust-sync"})
		return nil
	})
	for _, pub := range revokedNow {
		h.endDeviceSessionsLocked(pub, hp, "revoked")
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

// endDeviceSessionsLocked stops relaying between a device that lost trust on
// one Mac and that Mac.
func (h *hub) endDeviceSessionsLocked(devicePub, hostPub, reason string) {
	for id, rs := range h.sessions {
		if rs.devicePub != devicePub || rs.hostPub != hostPub {
			continue
		}
		rs.client.sendMsg(msg{"type": "session-end", "sessionId": id, "hostPub": hostPub, "reason": reason})
		if hc := h.hosts[hostPub]; hc != nil {
			hc.sendMsg(msg{"type": "session-end", "sessionId": id, "reason": reason})
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
	c.hostState, c.hostSessDev = m.State, dev
	h.broadcastHostStatusLocked(c.hostPub)
}

// deviceApprovedLocked handles device-approved from a bound Mac: the answer
// to the claim's setup-device (§4). hostMac (HR1.1) is relayed when present.
func (h *hub) deviceApprovedLocked(c *conn, m *inMsg) {
	s := h.s
	hp := c.hostPub
	if m.Cert == nil || m.Cert.Verify(h.hostPubBytes(c)) != nil {
		c.sendErr("bad-cert", "for", m.Type)
		return
	}
	if m.HostMac != "" {
		if _, err := proto.UnB64Len(m.HostMac, 32); err != nil {
			c.sendErr("bad-request", "for", m.Type)
			return
		}
	}
	ct := *m.Cert
	now := s.now()
	err := s.st.Update(func(st *store.State) error {
		d := st.Devices[ct.DevicePub]
		a := d.Approval(hp)
		if a == nil || a.Status == store.StatusRevoked {
			return errNotFound
		}
		d.Name, d.Kind = certNameKind(ct, d.Name, d.Kind)
		d.SetApproval(hp, &store.Approval{Status: store.StatusApproved, Cert: &ct, CreatedAt: a.CreatedAt})
		st.AddEvent(store.Event{Time: now, Type: "device-approved", Device: d.Name})
		return nil
	})
	if err != nil {
		c.sendErr("unknown-device", "for", m.Type)
		return
	}
	if h.setup != nil && h.setup.HostPub == hp && h.setup.DevicePub == ct.DevicePub {
		h.setup = nil
	}
	approved := msg{"type": "pair-approved", "hostPub": hp, "cert": ct}
	joined := msg{"type": "host-joined", "hostPub": hp, "cert": ct}
	if m.HostMac != "" {
		approved["hostMac"], joined["hostMac"] = m.HostMac, m.HostMac
	}
	h.toDeviceLocked(ct.DevicePub, approved)
	h.toDeviceLocked(ct.DevicePub, joined)
	h.broadcastDevicesChangedLocked()
}

func (h *hub) deviceRevokedLocked(c *conn, m *inMsg) {
	s := h.s
	hp := c.hostPub
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
		created := now
		if a := d.Approval(hp); a != nil {
			created = a.CreatedAt
		}
		d.SetApproval(hp, &store.Approval{Status: store.StatusRevoked, CreatedAt: created, RevokedAt: now})
		st.AddEvent(store.Event{Time: now, Type: "device-revoked", Device: d.Name})
		return nil
	})
	h.endDeviceSessionsLocked(pub, hp, "revoked")
	h.broadcastDevicesChangedLocked()
}

// hostSessionLocked relays a Mac's session message to the client of one of
// ITS sessions; the client learns which Mac it came from (hostPub).
func (h *hub) hostSessionLocked(c *conn, m *inMsg) {
	rs := h.sessions[m.SessionID]
	if rs == nil || rs.hostPub != c.hostPub {
		c.sendErr("unknown-session", "sessionId", m.SessionID)
		return
	}
	out := msg{"type": m.Type, "sessionId": rs.id, "hostPub": rs.hostPub}
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
