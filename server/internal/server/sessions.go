package server

import (
	"net/http"
	"time"

	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
	"github.com/videoproduction-ctrl/heartfulness-remote/server/internal/store"
)

// lastUsed is persisted at most this often per session.
const touchEvery = 5 * time.Minute

type authInfo struct {
	hash string // SHA-256 of the token (hex)
	kind string
}

// newSession creates a session and returns the raw token (never stored).
func (s *Server) newSession(st *store.State, kind, name string, now time.Time) string {
	tok := proto.B64(randBytes(32))
	life := store.CookieLifetime
	if kind == store.KindBearer {
		life = store.BearerLifetime
	}
	h := tokenHash(tok)
	st.Sessions[h] = &store.Session{Hash: h, Kind: kind, Name: name, Created: now, LastUsed: now, Expires: now.Add(life)}
	return tok
}

func (s *Server) setSessionCookie(w http.ResponseWriter, tok string) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.CookieName(),
		Value:    tok,
		Path:     "/",
		MaxAge:   int(store.CookieLifetime / time.Second),
		HttpOnly: true,
		Secure:   s.cfg.Secure(),
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.CookieName(),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cfg.Secure(),
		SameSite: http.SameSiteStrictMode,
	})
}

// sessionToken extracts the session token from r: a bearer header, or the
// session cookie — the cookie only for requests from our own origin.
func (s *Server) sessionToken(r *http.Request) (tok, kind string) {
	if t := bearerToken(r); t != "" {
		return t, store.KindBearer
	}
	if o := r.Header.Get("Origin"); o != "" && o != s.cfg.Origin {
		return "", ""
	}
	c, err := r.Cookie(s.cfg.CookieName())
	if err != nil || c.Value == "" {
		return "", ""
	}
	return c.Value, store.KindCookie
}

// lookupSession validates a token of the expected kind and refreshes its
// idle timer.
func (s *Server) lookupSession(tok, kind string) *authInfo {
	if tok == "" || len(tok) > 128 {
		return nil
	}
	h := tokenHash(tok)
	now := s.now()
	var valid, stale bool
	s.st.View(func(st *store.State) {
		ss, ok := st.Sessions[h]
		if !ok || ss.Kind != kind || !st.Claimed() {
			return
		}
		valid = ss.Valid(now)
		stale = now.Sub(ss.LastUsed) >= touchEvery
	})
	if !valid {
		return nil
	}
	if stale {
		s.touchSession(h)
	}
	return &authInfo{hash: h, kind: kind}
}

func (s *Server) touchSession(h string) {
	now := s.now()
	_ = s.st.Update(func(st *store.State) error {
		ss, ok := st.Sessions[h]
		if !ok || now.Sub(ss.LastUsed) < touchEvery {
			return store.ErrNoChange
		}
		ss.LastUsed = now
		return nil
	})
}

func (s *Server) sessionValid(h string) bool {
	now := s.now()
	ok := false
	s.st.View(func(st *store.State) {
		if ss, found := st.Sessions[h]; found {
			ok = ss.Valid(now) && st.Claimed()
		}
	})
	return ok
}

// requireSession writes 401 and returns nil when the request has no valid session.
func (s *Server) requireSession(w http.ResponseWriter, r *http.Request) *authInfo {
	tok, kind := s.sessionToken(r)
	a := s.lookupSession(tok, kind)
	if a == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return nil
	}
	return a
}

// deviceProof is embedded in requests that need "session + device proof".
type deviceProof struct {
	DevicePub string `json:"devicePub"`
	Nonce     string `json:"nonce"`
	Sig       string `json:"sig"`
}

// provenDevice is the device that passed a device proof.
type provenDevice struct {
	pub, name, kind string
}

// checkDeviceProof verifies HR1/client-auth(origin, nonce) by a device that
// is approved on at least one bound Mac, using a single-use nonce issued to
// this session.
func (s *Server) checkDeviceProof(w http.ResponseWriter, r *http.Request, a *authInfo, p deviceProof) (provenDevice, bool) {
	pub, ok := b64Key(p.DevicePub)
	nonce, err := proto.UnB64Len(p.Nonce, proto.NonceSize)
	if !ok || err != nil {
		writeError(w, http.StatusBadRequest, "bad-request")
		return provenDevice{}, false
	}
	sig, err := proto.UnB64Len(p.Sig, proto.SignatureSize)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad-request")
		return provenDevice{}, false
	}
	if !s.mem.takeNonce(p.Nonce, a.hash, s.now()) {
		writeError(w, http.StatusForbidden, "bad-nonce")
		return provenDevice{}, false
	}
	if !proto.Verify(pub, sig, proto.LabelClientAuth, proto.Str(s.cfg.Origin), nonce) {
		s.authFailure(r, "device proof signature")
		writeError(w, http.StatusForbidden, "bad-signature")
		return provenDevice{}, false
	}
	dev := provenDevice{pub: proto.B64(pub)}
	approved := false
	s.st.View(func(st *store.State) {
		if d, ok := st.Devices[dev.pub]; ok {
			dev.name, dev.kind = d.Name, d.Kind
		}
		approved = st.ApprovedOnAny(dev.pub)
	})
	if !approved {
		writeError(w, http.StatusForbidden, "device-not-approved")
		return provenDevice{}, false
	}
	return dev, true
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	a := s.requireSession(w, r)
	if a == nil {
		return
	}
	_ = s.st.Update(func(st *store.State) error {
		delete(st.Sessions, a.hash)
		st.AddEvent(store.Event{Time: s.now(), Type: "logout", IP: ipFrom(r).String()})
		return nil
	})
	s.hub.dropSession(a.hash)
	if a.kind == store.KindCookie {
		s.clearSessionCookie(w)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleNonce(w http.ResponseWriter, r *http.Request) {
	a := s.requireSession(w, r)
	if a == nil {
		return
	}
	n, err := s.mem.newNonce(a.hash, s.now())
	if err != nil {
		writeError(w, http.StatusTooManyRequests, "too-many-nonces")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"nonce": n})
}

type meApproval struct {
	HostPub string `json:"hostPub"`
	Status  string `json:"status"`
}

type meDevice struct {
	Pub       string       `json:"pub"`
	Name      string       `json:"name"`
	Kind      string       `json:"kind"`
	CreatedAt int64        `json:"createdAt"`
	LastSeen  int64        `json:"lastSeen"`
	Approvals []meApproval `json:"approvals"`
}

type mePasskey struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt int64  `json:"createdAt"`
}

func unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// handleMe returns the account overview (PROTOCOL.md §10.4): the Macs, the
// devices with their per-Mac approvals, and the passkeys.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	if s.requireSession(w, r) == nil {
		return
	}
	hosts := s.hub.meHosts()
	devices := []meDevice{}
	passkeys := []mePasskey{}
	s.st.View(func(st *store.State) {
		for _, d := range st.SortedDevices() {
			md := meDevice{Pub: d.Pub, Name: d.Name, Kind: d.Kind, CreatedAt: unix(d.CreatedAt), LastSeen: unix(d.LastSeen), Approvals: []meApproval{}}
			for _, hb := range st.Hosts {
				if a := d.Approval(hb.Pub); a != nil {
					md.Approvals = append(md.Approvals, meApproval{HostPub: hb.Pub, Status: a.Status})
				}
			}
			devices = append(devices, md)
		}
		if st.Owner != nil {
			for _, p := range st.Owner.Passkeys {
				passkeys = append(passkeys, mePasskey{ID: p.ID, Name: p.Name, CreatedAt: unix(p.CreatedAt)})
			}
		}
	})
	writeJSON(w, http.StatusOK, map[string]any{"hosts": hosts, "devices": devices, "passkeys": passkeys})
}
