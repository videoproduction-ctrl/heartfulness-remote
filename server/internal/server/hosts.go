package server

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
	"github.com/videoproduction-ctrl/heartfulness-remote/server/internal/store"
)

// Adding and removing Macs (PROTOCOL.md §10.2). Every endpoint needs a
// session (cookie or bearer) plus a device proof by a device approved on at
// least one bound Mac; they are in the auth rate-limit class, and bad claims
// and bad proofs count toward the lockout.

// normalizeMacID accepts "482 913 557", "482-913-557" or "482913557".
func normalizeMacID(s string) (string, bool) {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == ' ' || r == '-' || r == '\t':
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			return "", false
		}
	}
	if b.Len() != 9 {
		return "", false
	}
	return b.String(), true
}

// GET /api/hosts/pending?macId=…&devicePub=…&nonce=…&sig=…
// → {hostPub, name} of the connected Mac waiting to join with that Mac ID.
func (s *Server) handleHostsPending(w http.ResponseWriter, r *http.Request) {
	a := s.requireSession(w, r)
	if a == nil {
		return
	}
	q := r.URL.Query()
	if _, ok := s.checkDeviceProof(w, r, a, deviceProof{DevicePub: q.Get("devicePub"), Nonce: q.Get("nonce"), Sig: q.Get("sig")}); !ok {
		return
	}
	macID, ok := normalizeMacID(q.Get("macId"))
	if !ok {
		writeError(w, http.StatusBadRequest, "bad-request")
		return
	}
	hostPub, name, err := s.hub.pendingByMacID(macID)
	switch {
	case errors.Is(err, errNotFound):
		writeError(w, http.StatusNotFound, "not-found")
	case errors.Is(err, errAmbiguous):
		writeError(w, http.StatusConflict, "ambiguous")
	default:
		writeJSON(w, http.StatusOK, map[string]string{"hostPub": hostPub, "name": name})
	}
}

type joinBeginReq struct {
	deviceProof
	HostPub string `json:"hostPub"`
	Claim   string `json:"claim"`
}

// POST /api/hosts/join/begin {hostPub, claim: b64 Kc, …device proof}
// → {flowId, name, macId}
func (s *Server) handleJoinBegin(w http.ResponseWriter, r *http.Request) {
	a := s.requireSession(w, r)
	if a == nil {
		return
	}
	var req joinBeginReq
	if !readJSON(w, r, &req) {
		return
	}
	hostPub, okKey := b64Key(req.HostPub)
	claim, err := proto.UnB64Len(req.Claim, 32)
	if !okKey || err != nil {
		writeError(w, http.StatusBadRequest, "bad-request")
		return
	}
	dev, ok := s.checkDeviceProof(w, r, a, req.deviceProof)
	if !ok {
		return
	}
	var full, bound bool
	s.st.View(func(st *store.State) {
		full, bound = len(st.Hosts) >= store.MaxHosts, st.Host(req.HostPub) != nil
	})
	if bound {
		writeError(w, http.StatusConflict, "already-joined")
		return
	}
	if full {
		writeError(w, http.StatusConflict, "too-many-hosts")
		return
	}
	commit, name, macID, ok := s.hub.pendingJoin(req.HostPub)
	if !ok {
		writeError(w, http.StatusNotFound, "host-not-connected")
		return
	}
	if len(commit) == 0 || subtle.ConstantTimeCompare(proto.ClaimCommit(claim), commit) != 1 {
		s.authFailure(r, "join claim mismatch")
		writeError(w, http.StatusForbidden, "bad-claim")
		return
	}
	id, err := s.mem.putFlow(&flow{kind: flowJoin, hostPub: hostPub, sessionHash: a.hash, devicePub: dev.pub, commit: commit}, s.now())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "busy")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"flowId": id, "name": name, "macId": macID})
}

type joinFinishReq struct {
	deviceProof
	FlowID   string `json:"flowId"`
	SetupMac string `json:"setupMac"`
}

// POST /api/hosts/join/finish {flowId, setupMac, …device proof} → {ok}
// The server forwards setup-device to the Mac; the result arrives on the
// device's WebSocket as host-joined (§10.2 step 5).
func (s *Server) handleJoinFinish(w http.ResponseWriter, r *http.Request) {
	a := s.requireSession(w, r)
	if a == nil {
		return
	}
	var req joinFinishReq
	if !readJSON(w, r, &req) {
		return
	}
	mac, err := proto.UnB64Len(req.SetupMac, 32)
	if err != nil || req.FlowID == "" {
		writeError(w, http.StatusBadRequest, "bad-request")
		return
	}
	dev, ok := s.checkDeviceProof(w, r, a, req.deviceProof)
	if !ok {
		return
	}
	f := s.mem.takeFlow(req.FlowID, flowJoin, s.now())
	if f == nil || f.sessionHash != a.hash || f.devicePub != dev.pub {
		writeError(w, http.StatusBadRequest, "unknown-flow")
		return
	}
	err = s.hub.startJoin(proto.B64(f.hostPub), f.commit, dev.pub, dev.name, dev.kind, proto.B64(mac))
	switch {
	case errors.Is(err, errHostGone), errors.Is(err, errStaleCommit):
		writeError(w, http.StatusConflict, "host-not-connected")
	case errors.Is(err, store.ErrTooManyHosts):
		writeError(w, http.StatusConflict, "too-many-hosts")
	case errors.Is(err, errFull):
		writeError(w, http.StatusServiceUnavailable, "busy")
	case err != nil:
		writeError(w, http.StatusInternalServerError, "internal")
	default:
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

type hostRemoveReq struct {
	deviceProof
	HostPub string `json:"hostPub"`
}

// POST /api/hosts/remove {hostPub, …device proof} → {ok}
func (s *Server) handleHostRemove(w http.ResponseWriter, r *http.Request) {
	a := s.requireSession(w, r)
	if a == nil {
		return
	}
	var req hostRemoveReq
	if !readJSON(w, r, &req) {
		return
	}
	if _, ok := b64Key(req.HostPub); !ok {
		writeError(w, http.StatusBadRequest, "bad-request")
		return
	}
	dev, ok := s.checkDeviceProof(w, r, a, req.deviceProof)
	if !ok {
		return
	}
	err := s.hub.removeHost(req.HostPub, dev.name, ipFrom(r).String())
	switch {
	case errors.Is(err, errNotFound):
		writeError(w, http.StatusNotFound, "not-found")
	case errors.Is(err, errLastHost):
		writeError(w, http.StatusConflict, "last-host")
	case err != nil:
		writeError(w, http.StatusInternalServerError, "internal")
	default:
		s.log.Info("Mac removed from the account")
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}
