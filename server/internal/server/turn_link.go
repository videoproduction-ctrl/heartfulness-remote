package server

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/videoproduction-ctrl/heartfulness-remote/server/internal/store"
)

// TURNTTL is the lifetime of coturn REST API credentials.
const TURNTTL = 24 * time.Hour

// ICEServer is an RTCIceServer dictionary.
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// TURNCredential computes coturn "use-auth-secret" credentials:
// username = "<expiry-unix>:hr", credential = base64(HMAC-SHA1(secret, username)).
func TURNCredential(secret string, expiry time.Time) (username, credential string) {
	username = strconv.FormatInt(expiry.Unix(), 10) + ":hr"
	m := hmac.New(sha1.New, []byte(secret))
	m.Write([]byte(username))
	return username, base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// iceServers returns STUN + TURN (udp, tcp) servers with fresh credentials.
// In dev mode without a TURN secret it returns an empty list (LAN only).
func (s *Server) iceServers() []ICEServer {
	if s.cfg.TurnSecret == "" {
		return []ICEServer{}
	}
	host := s.cfg.TurnHost
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	hp := host + ":" + strconv.Itoa(s.cfg.TurnPort)
	user, cred := TURNCredential(s.cfg.TurnSecret, s.now().Add(TURNTTL))
	return []ICEServer{
		{URLs: []string{"stun:" + hp}},
		{URLs: []string{"turn:" + hp + "?transport=udp", "turn:" + hp + "?transport=tcp"}, Username: user, Credential: cred},
	}
}

func (s *Server) handleTurn(w http.ResponseWriter, r *http.Request) {
	if s.requireSession(w, r) == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"iceServers": s.iceServers(), "ttl": int(TURNTTL / time.Second)})
}

// ---- link flow for native apps (PROTOCOL.md §6) ----

type linkStartReq struct {
	Name string `json:"name"`
}

func (s *Server) handleLinkStart(w http.ResponseWriter, r *http.Request) {
	var req linkStartReq
	if !readJSON(w, r, &req) {
		return
	}
	name, ok := cleanName(req.Name)
	if !ok {
		writeError(w, http.StatusBadRequest, "bad-name")
		return
	}
	if !s.claimed() {
		writeError(w, http.StatusConflict, "not-claimed")
		return
	}
	code, poll, err := s.mem.newLink(name, ipFrom(r).String(), s.now())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "busy")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": code, "pollToken": poll, "expiresIn": int(linkTTL / time.Second)})
}

type linkApproveReq struct {
	Code string `json:"code"`
}

func (s *Server) handleLinkApprove(w http.ResponseWriter, r *http.Request) {
	a := s.requireSession(w, r)
	if a == nil {
		return
	}
	var req linkApproveReq
	if !readJSON(w, r, &req) {
		return
	}
	ip := ipFrom(r).String()
	name, ok, err := s.mem.approveLink(req.Code, func(name string) (string, error) {
		var tok string
		err := s.st.Update(func(st *store.State) error {
			if !st.Claimed() {
				return errors.New("not claimed")
			}
			now := s.now()
			tok = s.newSession(st, store.KindBearer, name, now)
			st.AddEvent(store.Event{Time: now, Type: "link-approved", Device: name, IP: ip})
			return nil
		})
		return tok, err
	}, s.now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if !ok {
		s.authFailure(r, "bad link code")
		writeError(w, http.StatusNotFound, "bad-code")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": name})
}

type linkPollReq struct {
	PollToken string `json:"pollToken"`
}

func (s *Server) handleLinkPoll(w http.ResponseWriter, r *http.Request) {
	var req linkPollReq
	if !readJSON(w, r, &req) {
		return
	}
	if req.PollToken == "" || len(req.PollToken) > 128 {
		writeError(w, http.StatusBadRequest, "bad-request")
		return
	}
	status, tok := s.mem.pollLink(req.PollToken, s.now())
	resp := map[string]string{"status": status}
	if tok != "" {
		resp["token"] = tok
	}
	writeJSON(w, http.StatusOK, resp)
}
