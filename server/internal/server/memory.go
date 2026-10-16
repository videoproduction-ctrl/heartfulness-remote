package server

import (
	"crypto/subtle"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
)

// Ephemeral, memory-only state. Nothing here is ever written to disk.
const (
	flowTTL        = 5 * time.Minute
	nonceTTL       = 60 * time.Second
	linkTTL        = 10 * time.Minute
	maxFlows       = 256
	maxNonces      = 1024
	maxNoncesPerSn = 16
	maxLinks       = 32
	linkAlphabet   = "ABCDEFGHJKMNPQRSTUVWXYZ23456789" // no I, L, O, 0, 1
	linkCodeLen    = 8
)

var errFull = errors.New("too many outstanding requests")

type flowKind int

const (
	flowSetup flowKind = iota + 1
	flowLogin
	flowPasskey
)

type flow struct {
	kind        flowKind
	sd          webauthn.SessionData
	expires     time.Time
	hostPub     []byte // setup: claimed host key
	userHandle  []byte // setup: new owner handle
	sessionHash string // passkey: session that started the flow
	name        string // passkey: display name
}

type nonceRec struct {
	sessionHash string
	expires     time.Time
}

type linkRec struct {
	codeHash  string // SHA-256 of the normalized code
	pollHash  string // SHA-256 of the poll token
	name      string
	expires   time.Time
	approved  bool
	token     string // bearer token, held only until the app polls once
	createdIP string
}

type memory struct {
	mu     sync.Mutex
	flows  map[string]*flow
	nonces map[string]nonceRec
	links  []*linkRec
}

func newMemory() *memory {
	return &memory{flows: map[string]*flow{}, nonces: map[string]nonceRec{}}
}

func (m *memory) expire(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked(now)
}

func (m *memory) expireLocked(now time.Time) {
	for k, f := range m.flows {
		if !now.Before(f.expires) {
			delete(m.flows, k)
		}
	}
	for k, n := range m.nonces {
		if !now.Before(n.expires) {
			delete(m.nonces, k)
		}
	}
	kept := m.links[:0]
	for _, l := range m.links {
		if now.Before(l.expires) {
			kept = append(kept, l)
		}
	}
	m.links = kept
}

// putFlow stores a flow and returns its id.
func (m *memory) putFlow(f *flow, now time.Time) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.flows) >= maxFlows {
		m.expireLocked(now)
		if len(m.flows) >= maxFlows {
			return "", errFull
		}
	}
	id := proto.B64(randBytes(proto.IDSize))
	f.expires = now.Add(flowTTL)
	m.flows[id] = f
	return id, nil
}

// takeFlow removes and returns a live flow of the given kind (single use).
func (m *memory) takeFlow(id string, kind flowKind, now time.Time) *flow {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.flows[id]
	if !ok {
		return nil
	}
	delete(m.flows, id)
	if f.kind != kind || !now.Before(f.expires) {
		return nil
	}
	return f
}

func (m *memory) newNonce(sessionHash string, now time.Time) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, n := range m.nonces {
		if n.sessionHash == sessionHash && now.Before(n.expires) {
			count++
		}
	}
	if count >= maxNoncesPerSn {
		return "", errFull
	}
	if len(m.nonces) >= maxNonces {
		m.expireLocked(now)
		if len(m.nonces) >= maxNonces {
			return "", errFull
		}
	}
	n := proto.B64(randBytes(proto.NonceSize))
	m.nonces[n] = nonceRec{sessionHash: sessionHash, expires: now.Add(nonceTTL)}
	return n, nil
}

// takeNonce consumes a nonce issued to the given session.
func (m *memory) takeNonce(nonce, sessionHash string, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nonces[nonce]
	if !ok {
		return false
	}
	delete(m.nonces, nonce)
	return n.sessionHash == sessionHash && now.Before(n.expires)
}

// newLink creates a link code. Returns the display code and poll token.
func (m *memory) newLink(name, ip string, now time.Time) (code, pollToken string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked(now)
	if len(m.links) >= maxLinks {
		return "", "", errFull
	}
	raw := randomCode()
	pollToken = proto.B64(randBytes(32))
	m.links = append(m.links, &linkRec{
		codeHash:  tokenHash(raw),
		pollHash:  tokenHash(pollToken),
		name:      name,
		expires:   now.Add(linkTTL),
		createdIP: ip,
	})
	return raw[:4] + "-" + raw[4:], pollToken, nil
}

// approveLink marks the pending link with this code approved and stores the
// bearer token for the app to collect. Returns the link name.
func (m *memory) approveLink(code string, mkToken func(name string) (string, error), now time.Time) (string, bool, error) {
	norm := normalizeCode(code)
	if len(norm) != linkCodeLen {
		return "", false, nil
	}
	h := tokenHash(norm)
	m.mu.Lock()
	defer m.mu.Unlock()
	var found *linkRec
	for _, l := range m.links {
		if subtle.ConstantTimeCompare([]byte(l.codeHash), []byte(h)) == 1 && !l.approved && now.Before(l.expires) {
			found = l
		}
	}
	if found == nil {
		return "", false, nil
	}
	tok, err := mkToken(found.name)
	if err != nil {
		return "", false, err
	}
	found.approved = true
	found.token = tok
	return found.name, true, nil
}

// pollLink returns "pending", "approved" (with the token, once) or "expired".
func (m *memory) pollLink(pollToken string, now time.Time) (status, token string) {
	h := tokenHash(pollToken)
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, l := range m.links {
		if subtle.ConstantTimeCompare([]byte(l.pollHash), []byte(h)) != 1 {
			continue
		}
		if !now.Before(l.expires) {
			break
		}
		if !l.approved {
			return "pending", ""
		}
		token = l.token
		m.links = append(m.links[:i], m.links[i+1:]...)
		return "approved", token
	}
	return "expired", ""
}

func randomCode() string {
	var sb strings.Builder
	max := byte(256 - 256%len(linkAlphabet))
	for sb.Len() < linkCodeLen {
		for _, b := range randBytes(16) {
			if b >= max {
				continue // rejection sampling: no modulo bias
			}
			sb.WriteByte(linkAlphabet[int(b)%len(linkAlphabet)])
			if sb.Len() == linkCodeLen {
				break
			}
		}
	}
	return sb.String()
}

func normalizeCode(s string) string {
	var sb strings.Builder
	for _, r := range strings.ToUpper(s) {
		if r == '-' || r == ' ' || r == '\t' {
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
