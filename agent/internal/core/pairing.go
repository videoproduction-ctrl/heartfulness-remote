package core

import (
	"crypto/rand"
	"crypto/subtle"
	"regexp"
	"slices"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
)

// Pairing limits (PROTOCOL.md §5).
const (
	MaxPendingPairs = 3
	PairTTL         = 5 * time.Minute
	DenyLimit       = 5
	DenyWindow      = time.Hour
	AutoDenyFor     = time.Hour
)

// Deny reasons sent in pair-result.
const (
	ReasonDenied         = "denied"
	ReasonExpired        = "expired"
	ReasonCommitMismatch = "commit-mismatch"
	ReasonTooMany        = "too-many-pending"
	ReasonRateLimited    = "rate-limited"
	ReasonInvalid        = "invalid"
	ReasonRevoked        = "revoked"
	ReasonUnavailable    = "unavailable"
)

// PairPhase of a request.
type PairPhase int

// Phases.
const (
	PhaseChallenged PairPhase = iota + 1 // pair-challenge sent, waiting for reveal
	PhaseRevealed                        // commit verified, waiting for approval
)

// PairReq is one pending pairing request.
type PairReq struct {
	ID        []byte
	IDB64     string
	Name      string
	Kind      string
	Commit    []byte
	NA        []byte
	DevicePub []byte
	ND        []byte
	SAS       string // 6 digits, no space
	Created   time.Time
	Expires   time.Time
	Phase     PairPhase
}

// Pairing is the pairing state machine. It is not safe for concurrent use
// (the agent drives it from its event loop).
type Pairing struct {
	pending       map[string]*PairReq
	Denials       []int64 // unix seconds
	AutoDenyUntil int64
	rand          func([]byte)
}

// NewPairing restores counters from the trust store.
func NewPairing(denials []int64, autoDenyUntil int64) *Pairing {
	return &Pairing{
		pending:       map[string]*PairReq{},
		Denials:       slices.Clone(denials),
		AutoDenyUntil: autoDenyUntil,
		rand:          func(b []byte) { _, _ = rand.Read(b) },
	}
}

var kindRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,23}$`)

// ValidName reports whether a device name is acceptable. Names are signed
// (cert, pair-approve, setup MAC), so they are validated, never rewritten.
func ValidName(s string) bool {
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > 64 {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

// ValidKind reports whether a device kind is acceptable.
func ValidKind(s string) bool { return kindRe.MatchString(s) }

// IsBrowserKind reports whether a kind is subject to allowBrowserClients.
// Only explicitly native kinds are exempt; anything unknown counts as browser.
func IsBrowserKind(kind string) bool {
	switch kind {
	case "tauri", "native", "app", "desktop":
		return false
	}
	return true
}

// Pending returns the request with this id (any phase).
func (p *Pairing) Pending(id string) (*PairReq, bool) {
	r, ok := p.pending[id]
	return r, ok
}

// List returns all pending requests, oldest first.
func (p *Pairing) List() []*PairReq {
	out := make([]*PairReq, 0, len(p.pending))
	for _, r := range p.pending {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b *PairReq) int { return a.Created.Compare(b.Created) })
	return out
}

// Remove drops a request.
func (p *Pairing) Remove(id string) { delete(p.pending, id) }

// Expire removes and returns requests past their deadline.
func (p *Pairing) Expire(now time.Time) []*PairReq {
	var out []*PairReq
	for id, r := range p.pending {
		if !now.Before(r.Expires) {
			out = append(out, r)
			delete(p.pending, id)
		}
	}
	return out
}

// AutoDenying reports whether new requests are currently auto-denied.
func (p *Pairing) AutoDenying(now time.Time) bool { return now.Unix() < p.AutoDenyUntil }

// RecordDenial counts a denial; it returns true when this denial triggered
// the 1-hour auto-deny period.
func (p *Pairing) RecordDenial(now time.Time) bool {
	cut := now.Add(-DenyWindow).Unix()
	p.Denials = slices.DeleteFunc(p.Denials, func(t int64) bool { return t <= cut })
	p.Denials = append(p.Denials, now.Unix())
	if len(p.Denials) >= DenyLimit && !p.AutoDenying(now) {
		p.AutoDenyUntil = now.Add(AutoDenyFor).Unix()
		p.Denials = nil
		return true
	}
	return false
}

// Request handles pair-request. On success the returned request carries a
// fresh na (generated only now, after the commit was received). On failure
// it returns the deny reason.
func (p *Pairing) Request(id []byte, name, kind string, commit []byte, now time.Time) (*PairReq, string) {
	p.Expire(now)
	if p.AutoDenying(now) {
		return nil, ReasonRateLimited
	}
	if len(id) != proto.IDSize || len(commit) != 32 || !ValidName(name) || !ValidKind(kind) {
		return nil, ReasonInvalid
	}
	idb := proto.B64(id)
	if _, dup := p.pending[idb]; dup {
		return nil, ReasonInvalid
	}
	if len(p.pending) >= MaxPendingPairs {
		return nil, ReasonTooMany
	}
	na := make([]byte, proto.NonceSize)
	p.rand(na)
	r := &PairReq{
		ID: slices.Clone(id), IDB64: idb, Name: name, Kind: kind,
		Commit: slices.Clone(commit), NA: na,
		Created: now, Expires: now.Add(PairTTL), Phase: PhaseChallenged,
	}
	p.pending[idb] = r
	return r, ""
}

// Reveal handles pair-reveal: the commitment must open to (devicePub, nd).
// A mismatch removes the request (the caller records a denial).
func (p *Pairing) Reveal(id string, devicePub, nd, hostPub []byte, now time.Time) (*PairReq, string) {
	r, ok := p.pending[id]
	if !ok {
		return nil, ReasonInvalid
	}
	if !now.Before(r.Expires) {
		delete(p.pending, id)
		return r, ReasonExpired
	}
	if r.Phase != PhaseChallenged {
		return nil, ReasonInvalid // duplicate reveal: ignore, keep the request
	}
	if len(devicePub) != proto.PubKeySize || len(nd) != proto.NonceSize {
		delete(p.pending, id)
		return r, ReasonCommitMismatch
	}
	if subtle.ConstantTimeCompare(proto.PairCommit(devicePub, nd), r.Commit) != 1 {
		delete(p.pending, id)
		return r, ReasonCommitMismatch
	}
	r.DevicePub = slices.Clone(devicePub)
	r.ND = slices.Clone(nd)
	r.SAS = proto.SAS(hostPub, devicePub, nd, r.NA)
	r.Phase = PhaseRevealed
	return r, ""
}

// VerifyApproval checks an HR1/pair-approve signature by approverPub.
// The caller must additionally ensure approverPub is pinned and not revoked.
func (r *PairReq) VerifyApproval(hostPub, approverPub, sig []byte) bool {
	if r.Phase != PhaseRevealed {
		return false
	}
	return proto.Verify(approverPub, sig, proto.LabelPairApprove,
		r.ID, hostPub, r.DevicePub, r.ND, r.NA, proto.Str(r.Name), proto.Str(r.Kind))
}

// ChallengeTBS is the transcript the host signs for pair-challenge.
func (r *PairReq) ChallengeTBS(hostPub []byte) []byte {
	return proto.TBS(proto.LabelPairChallenge, r.ID, r.Commit, r.NA, hostPub)
}
