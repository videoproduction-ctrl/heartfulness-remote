package server

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
	"github.com/videoproduction-ctrl/heartfulness-remote/server/internal/store"
)

// waUser adapts the owner to the go-webauthn User interface.
type waUser struct {
	handle []byte
	creds  []webauthn.Credential
}

func (u *waUser) WebAuthnID() []byte                         { return u.handle }
func (u *waUser) WebAuthnName() string                       { return "owner" }
func (u *waUser) WebAuthnDisplayName() string                { return "Heartfulness Remote owner" }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func ownerUser(o *store.Owner) *waUser {
	u := &waUser{handle: append([]byte(nil), o.UserHandle...)}
	for _, p := range o.Passkeys {
		u.creds = append(u.creds, p.Credential)
	}
	return u
}

var kindRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// cleanName validates a human-readable name: 1–64 characters, no control
// characters, trimmed.
func cleanName(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > 64 {
		return "", false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == ' ' || r == ' ' || unicode.In(r, unicode.Bidi_Control) {
			return "", false
		}
	}
	return s, true
}

func validKind(k string) bool { return kindRE.MatchString(k) }

type setupBeginReq struct {
	HostPub string `json:"hostPub"`
	Claim   string `json:"claim"`
}

func (s *Server) handleSetupBegin(w http.ResponseWriter, r *http.Request) {
	var req setupBeginReq
	if !readJSON(w, r, &req) {
		return
	}
	hostPub, ok := b64Key(req.HostPub)
	claim, err := proto.UnB64Len(req.Claim, 32)
	if !ok || err != nil {
		writeError(w, http.StatusBadRequest, "bad-request")
		return
	}
	if s.claimed() {
		writeError(w, http.StatusConflict, "already-claimed")
		return
	}
	if s.cfg.HostPubPin != nil && !bytes.Equal(hostPub, s.cfg.HostPubPin) {
		s.authFailure(r, "setup for a host key that is not the pinned one")
		writeError(w, http.StatusForbidden, "host-not-allowed")
		return
	}
	commit, ok := s.hub.pendingCommit(req.HostPub)
	if !ok {
		writeError(w, http.StatusNotFound, "host-not-connected")
		return
	}
	if commit == nil || subtle.ConstantTimeCompare(proto.ClaimCommit(claim), commit) != 1 {
		s.authFailure(r, "setup claim mismatch")
		writeError(w, http.StatusForbidden, "bad-claim")
		return
	}
	handle := randBytes(32)
	user := &waUser{handle: handle}
	creation, sd, err := s.wa.BeginRegistration(user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
	)
	if err != nil {
		s.log.Error("begin registration", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	id, err := s.mem.putFlow(&flow{kind: flowSetup, sd: *sd, hostPub: hostPub, userHandle: handle}, s.now())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "busy")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"flowId": id, "options": creation})
}

type deviceInfo struct {
	Pub  string `json:"pub"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type setupFinishReq struct {
	FlowID     string          `json:"flowId"`
	Credential json.RawMessage `json:"credential"`
	Device     deviceInfo      `json:"device"`
	SetupMac   string          `json:"setupMac"`
}

func (s *Server) handleSetupFinish(w http.ResponseWriter, r *http.Request) {
	var req setupFinishReq
	if !readJSON(w, r, &req) {
		return
	}
	f := s.mem.takeFlow(req.FlowID, flowSetup, s.now())
	if f == nil {
		writeError(w, http.StatusBadRequest, "unknown-flow")
		return
	}
	devPub, ok := b64Key(req.Device.Pub)
	name, okName := cleanName(req.Device.Name)
	mac, err := proto.UnB64Len(req.SetupMac, 32)
	if !ok || !okName || !validKind(req.Device.Kind) || err != nil {
		writeError(w, http.StatusBadRequest, "bad-request")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(req.Credential)
	if err != nil {
		s.authFailure(r, "setup: unparseable credential")
		writeError(w, http.StatusBadRequest, "bad-credential")
		return
	}
	cred, err := s.wa.CreateCredential(&waUser{handle: f.userHandle}, f.sd, parsed)
	if err != nil {
		s.authFailure(r, "setup: credential verification")
		writeError(w, http.StatusUnauthorized, "webauthn-failed")
		return
	}
	devB64 := proto.B64(devPub)
	setup := setupDevice{DevicePub: devB64, Name: name, Kind: req.Device.Kind, SetupMac: proto.B64(mac)}
	var tok string
	ip := ipFrom(r).String()
	err = s.hub.completeClaim(proto.B64(f.hostPub), setup, func(st *store.State, hostName string) error {
		if st.Claimed() {
			return errAlreadyClaimed
		}
		now := s.now()
		st.Owner = &store.Owner{
			UserHandle: f.userHandle,
			CreatedAt:  now,
			Passkeys:   []store.Passkey{{ID: proto.B64(cred.ID), Name: "Passkey 1", CreatedAt: now, Credential: *cred}},
		}
		st.Host = &store.HostBinding{Pub: proto.B64(f.hostPub), Name: hostName, ClaimedAt: now}
		st.Devices = map[string]*store.Device{devB64: {Pub: devB64, Name: name, Kind: req.Device.Kind, Status: store.StatusPending, CreatedAt: now}}
		st.Sessions = map[string]*store.Session{}
		tok = s.newSession(st, store.KindCookie, "", now)
		st.AddEvent(store.Event{Time: now, Type: "claimed", Device: name, IP: ip})
		return nil
	})
	switch {
	case errors.Is(err, errAlreadyClaimed):
		writeError(w, http.StatusConflict, "already-claimed")
		return
	case errors.Is(err, errHostGone):
		writeError(w, http.StatusConflict, "host-not-connected")
		return
	case err != nil:
		s.log.Error("claim failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	s.log.Info("server claimed", "host", proto.Fingerprint(f.hostPub))
	s.setSessionCookie(w, tok)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	if !s.claimed() {
		writeError(w, http.StatusConflict, "not-claimed")
		return
	}
	assertion, sd, err := s.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		s.log.Error("begin login", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	id, err := s.mem.putFlow(&flow{kind: flowLogin, sd: *sd}, s.now())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "busy")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"flowId": id, "options": assertion})
}

type loginFinishReq struct {
	FlowID     string          `json:"flowId"`
	Credential json.RawMessage `json:"credential"`
}

func (s *Server) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	var req loginFinishReq
	if !readJSON(w, r, &req) {
		return
	}
	f := s.mem.takeFlow(req.FlowID, flowLogin, s.now())
	if f == nil {
		writeError(w, http.StatusBadRequest, "unknown-flow")
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(req.Credential)
	if err != nil {
		s.authFailure(r, "login: unparseable assertion")
		writeError(w, http.StatusBadRequest, "bad-credential")
		return
	}
	var owner *waUser
	s.st.View(func(st *store.State) {
		if st.Claimed() {
			owner = ownerUser(st.Owner)
		}
	})
	if owner == nil {
		writeError(w, http.StatusConflict, "not-claimed")
		return
	}
	_, cred, err := s.wa.ValidatePasskeyLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
		if subtle.ConstantTimeCompare(userHandle, owner.handle) != 1 {
			return nil, errors.New("unknown user")
		}
		return owner, nil
	}, f.sd, parsed)
	if err == nil && cred.Authenticator.CloneWarning {
		err = errors.New("authenticator signature counter went backwards")
	}
	if err != nil {
		s.authFailure(r, "login: assertion verification")
		s.event("login-failed", "", ipFrom(r).String())
		writeError(w, http.StatusUnauthorized, "webauthn-failed")
		return
	}
	var tok string
	credID := proto.B64(cred.ID)
	err = s.st.Update(func(st *store.State) error {
		if !st.Claimed() {
			return errors.New("not claimed")
		}
		for i := range st.Owner.Passkeys {
			if st.Owner.Passkeys[i].ID == credID {
				st.Owner.Passkeys[i].Credential.Authenticator = cred.Authenticator
				st.Owner.Passkeys[i].Credential.Flags = cred.Flags
			}
		}
		now := s.now()
		tok = s.newSession(st, store.KindCookie, "", now)
		st.AddEvent(store.Event{Time: now, Type: "login", IP: ipFrom(r).String()})
		return nil
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	s.setSessionCookie(w, tok)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type passkeyBeginReq struct {
	deviceProof
	Name string `json:"name"`
}

func (s *Server) handlePasskeyBegin(w http.ResponseWriter, r *http.Request) {
	a := s.requireSession(w, r)
	if a == nil {
		return
	}
	var req passkeyBeginReq
	if !readJSON(w, r, &req) {
		return
	}
	if _, ok := s.checkDeviceProof(w, r, a, req.deviceProof); !ok {
		return
	}
	name := ""
	if req.Name != "" {
		n, ok := cleanName(req.Name)
		if !ok {
			writeError(w, http.StatusBadRequest, "bad-name")
			return
		}
		name = n
	}
	var owner *waUser
	s.st.View(func(st *store.State) {
		if st.Claimed() {
			owner = ownerUser(st.Owner)
		}
	})
	if owner == nil {
		writeError(w, http.StatusConflict, "not-claimed")
		return
	}
	creation, sd, err := s.wa.BeginRegistration(owner,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		webauthn.WithExclusions(webauthn.Credentials(owner.creds).CredentialDescriptors()),
	)
	if err != nil {
		s.log.Error("begin registration", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	id, err := s.mem.putFlow(&flow{kind: flowPasskey, sd: *sd, sessionHash: a.hash, name: name}, s.now())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "busy")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"flowId": id, "options": creation})
}

type passkeyFinishReq struct {
	deviceProof
	FlowID     string          `json:"flowId"`
	Credential json.RawMessage `json:"credential"`
	Name       string          `json:"name"` // optional; may also be given in begin
}

func (s *Server) handlePasskeyFinish(w http.ResponseWriter, r *http.Request) {
	a := s.requireSession(w, r)
	if a == nil {
		return
	}
	var req passkeyFinishReq
	if !readJSON(w, r, &req) {
		return
	}
	devName, ok := s.checkDeviceProof(w, r, a, req.deviceProof)
	if !ok {
		return
	}
	f := s.mem.takeFlow(req.FlowID, flowPasskey, s.now())
	if f == nil || f.sessionHash != a.hash {
		writeError(w, http.StatusBadRequest, "unknown-flow")
		return
	}
	if req.Name != "" {
		n, ok := cleanName(req.Name)
		if !ok {
			writeError(w, http.StatusBadRequest, "bad-name")
			return
		}
		f.name = n
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(req.Credential)
	if err != nil {
		s.authFailure(r, "passkey add: unparseable credential")
		writeError(w, http.StatusBadRequest, "bad-credential")
		return
	}
	var owner *waUser
	s.st.View(func(st *store.State) {
		if st.Claimed() {
			owner = ownerUser(st.Owner)
		}
	})
	if owner == nil {
		writeError(w, http.StatusConflict, "not-claimed")
		return
	}
	cred, err := s.wa.CreateCredential(owner, f.sd, parsed)
	if err != nil {
		s.authFailure(r, "passkey add: credential verification")
		writeError(w, http.StatusUnauthorized, "webauthn-failed")
		return
	}
	id := proto.B64(cred.ID)
	err = s.st.Update(func(st *store.State) error {
		if !st.Claimed() {
			return errors.New("not claimed")
		}
		for _, p := range st.Owner.Passkeys {
			if p.ID == id {
				return errDuplicate
			}
		}
		name := f.name
		if name == "" {
			name = fmt.Sprintf("Passkey %d", len(st.Owner.Passkeys)+1)
		}
		now := s.now()
		st.Owner.Passkeys = append(st.Owner.Passkeys, store.Passkey{ID: id, Name: name, CreatedAt: now, Credential: *cred})
		st.AddEvent(store.Event{Time: now, Type: "passkey-added", Device: devName, IP: ipFrom(r).String()})
		return nil
	})
	if errors.Is(err, errDuplicate) {
		writeError(w, http.StatusConflict, "duplicate")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	s.hub.broadcastDevicesChanged()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

type passkeyDeleteReq struct {
	deviceProof
	ID string `json:"id"`
}

func (s *Server) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	a := s.requireSession(w, r)
	if a == nil {
		return
	}
	var req passkeyDeleteReq
	if !readJSON(w, r, &req) {
		return
	}
	devName, ok := s.checkDeviceProof(w, r, a, req.deviceProof)
	if !ok {
		return
	}
	err := s.st.Update(func(st *store.State) error {
		if !st.Claimed() {
			return errNotFound
		}
		idx := -1
		for i, p := range st.Owner.Passkeys {
			if p.ID == req.ID {
				idx = i
			}
		}
		if idx < 0 {
			return errNotFound
		}
		if len(st.Owner.Passkeys) == 1 {
			return errLastPasskey
		}
		st.Owner.Passkeys = append(st.Owner.Passkeys[:idx], st.Owner.Passkeys[idx+1:]...)
		st.AddEvent(store.Event{Time: s.now(), Type: "passkey-deleted", Device: devName, IP: ipFrom(r).String()})
		return nil
	})
	switch {
	case errors.Is(err, errNotFound):
		writeError(w, http.StatusNotFound, "not-found")
	case errors.Is(err, errLastPasskey):
		writeError(w, http.StatusConflict, "last-passkey")
	case err != nil:
		writeError(w, http.StatusInternalServerError, "internal")
	default:
		s.hub.broadcastDevicesChanged()
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

var (
	errAlreadyClaimed = errors.New("already claimed")
	errHostGone       = errors.New("host not connected")
	errDuplicate      = errors.New("duplicate")
	errNotFound       = errors.New("not found")
	errLastPasskey    = errors.New("cannot delete the last passkey")
)
