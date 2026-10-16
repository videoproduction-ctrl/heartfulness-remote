package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/webrtc/v4"

	"github.com/videoproduction-ctrl/heartfulness-remote/agent/internal/accesslog"
	"github.com/videoproduction-ctrl/heartfulness-remote/agent/internal/signaling"
	"github.com/videoproduction-ctrl/heartfulness-remote/agent/internal/trust"
	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
)

// Defaults and limits.
const (
	DefaultMaxKbps     = 40000
	MinKbps            = 1000
	AbsoluteMaxKbps    = 250000
	DefaultIdleMin     = 30
	MaxIdleMin         = 24 * 60
	OfferTimeout       = 60 * time.Second
	ConnectTimeout     = 45 * time.Second
	SignTimeout        = 15 * time.Second
	replayCacheTTL     = 2*proto.MaxClockSkew + time.Minute
	maxSetupFailures   = 20
	stateRefreshPeriod = 2 * time.Second
	// setupSecretSize is the size of T for claiming an unclaimed server (§4);
	// joining an account uses proto.JoinSecretSize (§10.2).
	setupSecretSize = 32
)

// Options configure an Agent.
type Options struct {
	// Codecs the Mac side can produce, in preference order. Nil = derived
	// from CONFIG (H.265 when hevcAvailable and allowed, then H.264).
	Codecs []Codec
	// Simulator permits VP8 (hostsim only; the test Chromium has no H.264).
	Simulator bool
	// DownloadsDir overrides "~/Downloads/Heartfulness Remote".
	DownloadsDir string
	// HomeDir overrides the download/listing root (the user's home).
	HomeDir string
	// AllowInsecure permits http:// server URLs for non-loopback hosts.
	AllowInsecure bool
	// IncludeLoopback gathers loopback ICE candidates (tests).
	IncludeLoopback bool
	// NoSignaling disables the WebSocket client (tests drive OnReady/OnMessage).
	NoSignaling bool
	// Logf receives diagnostics (stderr). Never passed secrets.
	Logf func(format string, a ...any)
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Agent is the host agent core.
type Agent struct {
	io   HostIO
	opts Options
	logf func(string, ...any)
	now  func() time.Time

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	qmu     sync.Mutex
	queue   []func()
	qsig    chan struct{}
	stopped bool

	// Immutable after Start.
	cfg        Config
	hostPub    []byte
	hostPubB64 string
	macID      string
	storageKey []byte
	origin     string
	wsURL      string
	homeDir    string
	dlDir      string

	// Loop-owned state.
	settings    Settings
	store       *trust.Store // nil when the trust store is unusable
	storeErr    error
	alog        *accesslog.Log
	pairing     *Pairing
	server      string
	serverError string
	claimed     bool // the server has an owner (§4)
	joined      bool // this Mac is in the owner's account (§10.2)
	sender      signaling.Sender
	sig         *signaling.Client
	iceServers  []webrtc.ICEServer
	// One-time secret T: 32 bytes to claim an unclaimed server (§4), or
	// proto.JoinSecretSize bytes to join the owner's account (§10.2). Memory
	// only, never logged.
	setupT        []byte
	setupKa       []byte
	setupCommit   string // b64 claimCommit H(Kc) of setupT ("" without T)
	sentCommit    string // claimCommit sent in the latest host-auth
	setupFailures int
	reconnects    int // forced reconnects (re-send host-auth), for tests
	displays      []Display
	activeDisplay int64
	sess          *Session
	seen          map[string]time.Time
	lastState     []byte
	dirty         bool
	lastStateTick time.Time

	media   atomic.Pointer[Session] // session receiving OnVideo/OnAudio
	started atomic.Bool
}

// New creates an agent; call Start with the CONFIG.
func New(hio HostIO, opts Options) *Agent {
	a := &Agent{
		io: hio, opts: opts,
		logf: opts.Logf, now: opts.Now,
		qsig: make(chan struct{}, 1),
		done: make(chan struct{}),
		seen: map[string]time.Time{},
	}
	if a.logf == nil {
		a.logf = func(string, ...any) {}
	}
	if a.now == nil {
		a.now = time.Now
	}
	a.server = signaling.StatusOffline
	return a
}

// Done is closed when the agent has shut down.
func (a *Agent) Done() <-chan struct{} { return a.done }

// Stop shuts the agent down (ends any session) and waits.
func (a *Agent) Stop() {
	if !a.started.Load() {
		return
	}
	a.post(func() { a.shutdown("host-shutdown") })
	<-a.done
}

func sanitizeSettings(s Settings) Settings {
	if s.MaxKbps <= 0 {
		s.MaxKbps = DefaultMaxKbps
	}
	s.MaxKbps = min(max(s.MaxKbps, MinKbps), AbsoluteMaxKbps)
	if s.IdleTimeoutMin <= 0 {
		s.IdleTimeoutMin = DefaultIdleMin
	}
	s.IdleTimeoutMin = min(s.IdleTimeoutMin, MaxIdleMin)
	switch s.Codec {
	case "h264", "h265", "auto":
	default:
		s.Codec = "auto"
	}
	return s
}

// Start validates the CONFIG, opens the trust store and access log, and
// starts the event loop and (unless disabled) the signaling client.
func (a *Agent) Start(parent context.Context, cfg Config) error {
	hp, err := proto.UnB64Len(cfg.HostPub, proto.PubKeySize)
	if err != nil {
		return fmt.Errorf("CONFIG.hostPub: %w", err)
	}
	key, err := proto.UnB64Len(cfg.StorageKey, 32)
	if err != nil {
		return errors.New("CONFIG.storageKey must be 32 bytes (b64url)")
	}
	if cfg.DataDir == "" || !filepath.IsAbs(cfg.DataDir) {
		return errors.New("CONFIG.dataDir must be an absolute path")
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(cfg.DataDir, 0o700)
	origin, wsURL, err := signaling.Endpoints(cfg.ServerURL, a.opts.AllowInsecure)
	if err != nil {
		return err
	}
	a.cfg = cfg
	a.hostPub = hp
	a.hostPubB64 = proto.B64(hp)
	a.macID = proto.MacID(hp)
	a.storageKey = key
	a.origin, a.wsURL = origin, wsURL
	a.settings = sanitizeSettings(cfg.Settings)
	a.homeDir = a.opts.HomeDir
	if a.homeDir == "" {
		if a.homeDir, err = os.UserHomeDir(); err != nil {
			return err
		}
	}
	a.dlDir = a.opts.DownloadsDir
	if a.dlDir == "" {
		a.dlDir = filepath.Join(a.homeDir, "Downloads", "Heartfulness Remote")
	}
	a.ctx, a.cancel = context.WithCancel(parent)

	a.openStores()
	a.started.Store(true)
	go a.loop()
	if !a.opts.NoSignaling && a.store != nil {
		a.startSignaling()
	}
	return nil
}

func (a *Agent) startSignaling() {
	c := signaling.New(a.origin, a.wsURL, a, Version)
	c.Logf = a.logf
	a.sig = c
	go c.Run(a.ctx)
}

// openStores loads pins.json and the access log, handling tampering.
func (a *Agent) openStores() {
	logPath := filepath.Join(a.cfg.DataDir, trust.LogFileName)
	st, err := trust.Open(a.cfg.DataDir, a.storageKey, a.hostPub)
	if err != nil {
		a.storeErr = err
		a.logf("trust store: %v", err)
		code := "trust-store-tampered"
		if errors.Is(err, trust.ErrHostMismatch) {
			code = "trust-store-host-mismatch"
		} else if !errors.Is(err, trust.ErrTampered) {
			code = "trust-store-error"
		}
		a.server, a.serverError = signaling.StatusError, code
		a.alog, _ = accesslog.Open(logPath, a.storageKey, nil)
		if a.alog != nil {
			_ = a.alog.Append(accesslog.Entry{Event: accesslog.EvTrustTampered, Detail: err.Error()})
		}
		a.io.EmitEvent(Event{Event: code, Detail: err.Error()})
		a.pairing = NewPairing(nil, 0)
		a.dirty = true
		return
	}
	a.store = st
	d := st.Snapshot()
	a.pairing = NewPairing(d.Denials, d.AutoDenyUntil)
	a.alog, err = accesslog.Open(logPath, a.storageKey, st)
	if err != nil {
		a.logf("access log: %v", err)
	} else if res := a.alog.Verify(); !res.Verified {
		a.logf("access log verification failed: %s", res.Error)
		_ = a.alog.Append(accesslog.Entry{Event: accesslog.EvLogTampered, Detail: res.Error})
		_ = a.alog.ReAnchor()
		a.io.EmitEvent(Event{Event: "log-tampered", Detail: res.Error})
	}
	if st.DeviceCount() == 0 {
		a.newSetupSecret()
	}
	a.dirty = true
}

func (a *Agent) appendLog(e accesslog.Entry) {
	if a.alog == nil {
		return
	}
	if err := a.alog.Append(e); err != nil {
		a.logf("access log append: %v", err)
	}
}

// ---------------------------------------------------------------- event loop

func (a *Agent) post(f func()) {
	a.qmu.Lock()
	if a.stopped {
		a.qmu.Unlock()
		return
	}
	a.queue = append(a.queue, f)
	a.qmu.Unlock()
	select {
	case a.qsig <- struct{}{}:
	default:
	}
}

// call runs f on the loop and waits for it. Never call from the loop.
func (a *Agent) call(f func()) bool {
	ch := make(chan struct{})
	a.post(func() { f(); close(ch) })
	select {
	case <-ch:
		return true
	case <-a.done:
		return false
	}
}

func (a *Agent) loop() {
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	defer close(a.done)
	a.dirty = true
	for {
		select {
		case <-a.ctx.Done():
			a.shutdown("host-shutdown")
		case <-a.qsig:
		case <-tick.C:
			a.tick()
		}
		for {
			a.qmu.Lock()
			q := a.queue
			a.queue = nil
			a.qmu.Unlock()
			if len(q) == 0 {
				break
			}
			for _, f := range q {
				f()
			}
		}
		a.flushState()
		a.qmu.Lock()
		stopped := a.stopped
		a.qmu.Unlock()
		if stopped {
			return
		}
	}
}

func (a *Agent) shutdown(reason string) {
	if s := a.sess; s != nil {
		a.endSession(s, reason, true)
	}
	a.flushState()
	if a.cancel != nil {
		a.cancel()
	}
	a.qmu.Lock()
	a.stopped = true
	a.queue = nil
	a.qmu.Unlock()
}

func (a *Agent) tick() {
	now := a.now()
	for _, r := range a.pairing.Expire(now) {
		if r.Phase == PhaseRevealed || r.Phase == PhaseChallenged {
			a.sendPairResult(r.IDB64, false, nil, ReasonExpired)
			a.appendLog(accesslog.Entry{Event: accesslog.EvPairDenied, Device: r.Name, Detail: ReasonExpired})
		}
		a.dirty = true
	}
	for k, t := range a.seen {
		if now.After(t) {
			delete(a.seen, k)
		}
	}
	if s := a.sess; s != nil {
		a.tickSession(s, now)
	}
	if now.Sub(a.lastStateTick) >= stateRefreshPeriod {
		a.lastStateTick = now
		if s := a.sess; s != nil && s.state == sessConnected {
			s.refreshStats()
			a.dirty = true
		}
	}
}

// ------------------------------------------------------------------- state

func (a *Agent) flushState() {
	if !a.dirty {
		return
	}
	a.dirty = false
	st := a.buildState()
	b, _ := json.Marshal(st)
	if bytes.Equal(b, a.lastState) {
		return
	}
	a.lastState = b
	a.io.EmitState(st)
}

func (a *Agent) buildState() State {
	st := State{
		Server: a.server, ServerError: a.serverError, Claimed: a.claimed,
		Joined: a.joined, MacID: a.macID,
		Pending: []PendingState{}, Devices: []DeviceState{},
	}
	// Show a code only when the server knows its commit (it was in the
	// host-auth of the current connection), so whatever is on screen works.
	if a.setupT != nil && a.store != nil && a.server == signaling.StatusOnline && a.setupCommit == a.sentCommit {
		switch {
		case !a.claimed && len(a.setupT) == setupSecretSize:
			st.SetupURL = a.origin + "/#setup=" + proto.B64(a.setupT) + "." + a.hostPubB64
		case a.claimed && !a.joined && len(a.setupT) == proto.JoinSecretSize:
			st.JoinURL = a.origin + "/#join=" + proto.B64(a.setupT) + "." + a.hostPubB64
			st.JoinCode = proto.JoinCode(a.setupT)
		}
	}
	if a.store != nil {
		d := a.store.Snapshot()
		st.Killed = d.Killed
		for _, dev := range d.Devices {
			pub, _ := proto.UnB64(dev.Pub)
			st.Devices = append(st.Devices, DeviceState{
				Pub: dev.Pub, Name: dev.Name, Kind: dev.Kind,
				AddedAt: dev.AddedAt, LastUsed: dev.LastUsed, Fingerprint: proto.Fingerprint(pub),
			})
		}
	}
	for _, r := range a.pairing.List() {
		if r.Phase != PhaseRevealed {
			continue
		}
		st.Pending = append(st.Pending, PendingState{
			RequestID: r.IDB64, Name: r.Name, Kind: r.Kind,
			SAS: proto.FormatSAS(r.SAS), ExpiresAt: r.Expires.Unix(),
		})
	}
	if s := a.sess; s != nil && s.state == sessConnected {
		st.Session = &SessionState{
			Device: s.deviceInfo(), Since: s.connectedAt.Unix(),
			Transport: s.transportName(), RTTMs: s.rttMs(), Codec: s.codec.id.String(),
		}
	}
	return st
}

func (a *Agent) killed() bool { return a.store != nil && a.store.Killed() }

// ----------------------------------------------------------------- signing

var errBadHostSig = errors.New("Mac returned an invalid host signature")

// sign asks the Mac to sign TBS(label, fields…) and verifies the result.
func (a *Agent) sign(label string, fields ...[]byte) ([]byte, error) {
	tbs := proto.TBS(label, fields...)
	ctx, cancel := context.WithTimeout(a.ctx, SignTimeout)
	defer cancel()
	sig, err := a.io.Sign(ctx, tbs)
	if err != nil {
		return nil, err
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(a.hostPub, tbs, sig) {
		return nil, errBadHostSig
	}
	return sig, nil
}

func (a *Agent) issueCert(devicePub []byte, name, kind string) (proto.Cert, error) {
	issued := a.now().Unix()
	sig, err := a.sign(proto.LabelCert, a.hostPub, devicePub, proto.Str(name), proto.Str(kind), proto.Int(issued))
	if err != nil {
		return proto.Cert{}, err
	}
	c := proto.Cert{
		HostPub: proto.B64(a.hostPub), DevicePub: proto.B64(devicePub),
		Name: name, Kind: kind, IssuedAt: issued, Sig: proto.B64(sig),
	}
	if err := c.Verify(a.hostPub); err != nil {
		return proto.Cert{}, err
	}
	return c, nil
}

// --------------------------------------------------------------- signaling

// HostAuth implements signaling.Handler.
func (a *Agent) HostAuth(ctx context.Context, origin string, nonce []byte) (any, error) {
	var commit string
	if !a.call(func() {
		commit = a.setupCommit
		a.sentCommit = commit
		a.dirty = true
	}) {
		return nil, errors.New("agent stopped")
	}
	sig, err := a.sign(proto.LabelHostAuth, proto.Str(origin), nonce)
	if err != nil {
		return nil, err
	}
	return hostAuthMsg{
		Type: "host-auth", HostPub: proto.B64(a.hostPub), Name: a.cfg.HostName,
		Version: Version, Sig: proto.B64(sig), ClaimCommit: commit,
	}, nil
}

// OnStatus implements signaling.Handler.
func (a *Agent) OnStatus(status, code string) {
	a.post(func() {
		if a.store == nil {
			return // keep the trust-store error visible
		}
		a.server, a.serverError = status, code
		if status != signaling.StatusOnline {
			a.sender = nil
		}
		a.dirty = true
	})
}

// OnReady implements signaling.Handler.
func (a *Agent) OnReady(s signaling.Sender, raw []byte) {
	a.post(func() {
		var m inMsg
		if err := json.Unmarshal(raw, &m); err != nil {
			return
		}
		a.sender = s
		a.server, a.serverError = signaling.StatusOnline, ""
		if m.Origin != "" && m.Origin != a.origin {
			a.logf("server reports origin %q, configured %q (using configured)", m.Origin, a.origin)
		}
		a.setICEServers(m.IceServers)
		a.applyMembership(m, true)
	})
}

// bound reports whether the server treats this Mac as the owner's (claimed
// and in the account). Only a bound Mac sends trust-sync and host-status; a
// pending (unclaimed or joining) Mac may not.
func (a *Agent) bound() bool { return a.claimed && a.joined }

// applyMembership applies claimed/joined from host-ready (or an in-band
// update), and makes sure the right one-time secret exists and is committed:
//
//	unclaimed server            → 32-byte setup T, setupURL (§4)
//	claimed, Mac not in account → 10-byte join T, joinURL + joinCode (§10.2)
//	Mac in the account          → nothing to show
//
// A T that exists when the Mac becomes joined is kept: on a first claim the
// server reports claimed before it forwards setup-device (§4 step 4–5).
// fresh is true for the host-ready that opens a connection.
func (a *Agent) applyMembership(m inMsg, fresh bool) {
	wasBound := a.bound()
	a.claimed = m.Claimed
	// Servers before HR1.1 send no "joined": one Mac per server, so a claimed
	// server that accepted us means this Mac is the owner's.
	a.joined = a.claimed && (m.Joined == nil || *m.Joined)
	if m.MacID != "" && m.MacID != a.macID {
		a.logf("server reports Mac ID %q, ours is %q (using ours)", truncate(m.MacID, 16), a.macID)
	}
	if a.bound() && (fresh || !wasBound) {
		a.sendTrustSync()
		a.sendHostStatus()
	}
	a.ensureSecret()
	a.dirty = true
}

// ensureSecret creates the one-time secret the server state calls for and,
// if the server does not have its commit yet, reconnects so that host-auth
// carries it (the server reads claimCommit only from host-auth).
func (a *Agent) ensureSecret() {
	if a.store == nil {
		return // trust store unusable: no setup or join
	}
	var want int
	switch {
	case !a.claimed:
		want = setupSecretSize
	case !a.joined:
		want = proto.JoinSecretSize
	default:
		return
	}
	if len(a.setupT) != want {
		a.newSecret(want)
	}
	if a.setupCommit != a.sentCommit {
		a.requestReconnect()
	}
}

// requestReconnect drops the signaling connection and reconnects at once,
// so the next host-auth carries the current claimCommit.
func (a *Agent) requestReconnect() {
	a.reconnects++
	if a.sig != nil {
		a.sig.Reconnect()
	}
}

// OnMessage implements signaling.Handler.
func (a *Agent) OnMessage(typ string, raw []byte) {
	a.post(func() { a.handleSignal(typ, raw) })
}

func (a *Agent) send(msg any) {
	if a.sender == nil {
		return
	}
	if err := a.sender.Send(msg); err != nil {
		a.logf("signaling send: %v", err)
	}
}

func (a *Agent) handleSignal(typ string, raw []byte) {
	var m inMsg
	if err := json.Unmarshal(raw, &m); err != nil {
		a.logf("signaling: malformed %q message", typ)
		return
	}
	if a.store == nil {
		return // trust store unusable: refuse everything
	}
	if m.HostPub != "" && m.HostPub != a.hostPubB64 {
		// Routed messages name the target Mac (§10.3); never act on one
		// meant for another Mac.
		a.logf("signaling: %q for another Mac ignored", truncate(typ, 32))
		return
	}
	switch typ {
	case "pair-request":
		a.handlePairRequest(m)
	case "pair-reveal":
		a.handlePairReveal(m)
	case "pair-approve":
		a.handlePairApprove(m)
	case "pair-deny":
		a.denyPair(m.RequestID, "denied by an approved device")
	case "setup-device":
		a.handleSetupDevice(m)
	case "revoke-request":
		a.handleRevokeRequest(m)
	case "kill-request":
		a.handleKillRequest(m)
	case "session-request":
		a.handleSessionRequest(m)
	case "offer":
		a.handleOffer(m)
	case "ice":
		a.handleICE(m)
	case "session-end":
		if s := a.sess; s != nil && s.idB64 == m.SessionID {
			a.endSession(s, "client:"+truncate(m.Reason, 32), false)
		}
	case "host-ready":
		// Sent again on the same connection when the server gets claimed or
		// this Mac joins the owner's account.
		a.setICEServers(m.IceServers)
		a.applyMembership(m, false)
	case "hosts-changed":
		// Only meaningful for a Mac when it says whether we are in the account.
		if m.Joined != nil {
			if *m.Joined {
				m.Claimed = true
			} else {
				m.Claimed = a.claimed
			}
			a.applyMembership(m, false)
		}
	case "turn":
		a.setICEServers(m.IceServers)
	case "error":
		a.logf("server error: %s", truncate(m.Code, 64))
		if m.Code == "removed" {
			a.removedFromAccount()
		}
	}
}

// removedFromAccount handles error{code:"removed"} (§10.2): the owner removed
// this Mac from the account. The Mac keeps its own pins (it stays the root of
// trust) but is no longer joined, so it shows a fresh join code.
func (a *Agent) removedFromAccount() {
	a.claimed, a.joined = true, false
	a.appendLog(accesslog.Entry{Event: accesslog.EvRemovedFromAccount, Detail: "removed from the account on the server"})
	a.io.EmitEvent(Event{Event: "removed-from-account"})
	a.newSecret(proto.JoinSecretSize)
	a.requestReconnect() // the server closes the socket too; one reconnect results
	a.dirty = true
}

func (a *Agent) setICEServers(raw json.RawMessage) {
	if len(raw) == 0 {
		return
	}
	var list []struct {
		URLs       json.RawMessage `json:"urls"`
		Username   string          `json:"username"`
		Credential string          `json:"credential"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return
	}
	var out []webrtc.ICEServer
	for _, s := range list {
		var urls []string
		var one string
		if json.Unmarshal(s.URLs, &one) == nil {
			urls = []string{one}
		} else {
			_ = json.Unmarshal(s.URLs, &urls)
		}
		urls = slices.DeleteFunc(urls, func(u string) bool {
			l := strings.ToLower(u)
			return !(strings.HasPrefix(l, "stun:") || strings.HasPrefix(l, "stuns:") ||
				strings.HasPrefix(l, "turn:") || strings.HasPrefix(l, "turns:"))
		})
		if len(urls) == 0 {
			continue
		}
		srv := webrtc.ICEServer{URLs: urls}
		if s.Username != "" {
			srv.Username, srv.Credential = s.Username, s.Credential
		}
		out = append(out, srv)
		if len(out) >= 8 {
			break
		}
	}
	a.iceServers = out
}

func (a *Agent) sendTrustSync() {
	if a.store == nil || !a.bound() {
		return
	}
	a.send(trustSyncMsg{Type: "trust-sync", Certs: a.store.Certs(), Revocations: a.store.Revocations()})
}

func (a *Agent) sendHostStatus() {
	if !a.bound() {
		return
	}
	m := hostStatusMsg{Type: "host-status", State: "available"}
	if a.killed() {
		m.State = "blocked"
	} else if s := a.sess; s != nil && s.state == sessConnected {
		m.State, m.SessionDeviceName = "in-session", s.dev.Name
	}
	a.send(m)
}

// ------------------------------------------------------------ setup (§4)

func (a *Agent) newSetupSecret() { a.newSecret(setupSecretSize) }

// newSecret replaces T with n fresh random bytes (32 = claim, 10 = join).
// The caller reconnects when the server must learn the new commit.
func (a *Agent) newSecret(n int) {
	clear(a.setupT)
	clear(a.setupKa)
	t := make([]byte, n)
	if _, err := rand.Read(t); err != nil {
		panic(err)
	}
	kc, ka, err := proto.SetupKeys(t)
	if err != nil {
		panic(err)
	}
	a.setupT, a.setupKa = t, ka
	a.setupCommit = proto.B64(proto.ClaimCommit(kc))
	clear(kc)
	a.setupFailures = 0
	a.dirty = true
}

func (a *Agent) forgetSetupSecret() {
	clear(a.setupT)
	clear(a.setupKa)
	a.setupT, a.setupKa, a.setupCommit = nil, nil, ""
	a.dirty = true
}

// handleSetupDevice finishes a first claim (§4) or a join (§10.2): both
// prove knowledge of T with setupMac = HMAC(Ka, …) and are answered with
// device-approved {cert, hostMac}.
func (a *Agent) handleSetupDevice(m inMsg) {
	if a.setupKa == nil {
		a.logf("setup-device without an active setup code: ignored")
		return
	}
	dp, err1 := proto.UnB64Len(m.DevicePub, proto.PubKeySize)
	mac, err2 := proto.UnB64Len(m.SetupMac, sha256.Size)
	if err1 != nil || err2 != nil || !ValidName(m.Name) || !ValidKind(m.Kind) ||
		!proto.CheckSetupMAC(a.setupKa, a.hostPub, dp, m.Name, m.Kind, mac) {
		a.setupFailures++
		a.appendLog(accesslog.Entry{Event: accesslog.EvSetupFailed, Device: m.Name, Detail: "setup MAC invalid"})
		a.io.EmitEvent(Event{Event: "setup-failed"})
		if a.setupFailures >= maxSetupFailures {
			a.newSecret(len(a.setupT)) // invalidate the displayed code
			a.requestReconnect()       // and give the server the new commit
		}
		return
	}
	join := len(a.setupT) == proto.JoinSecretSize
	if a.store.IsRevoked(m.DevicePub) {
		a.logf("setup-device for a revoked key: refused")
		return
	}
	cert, err := a.issueCert(dp, m.Name, m.Kind)
	if err != nil {
		a.logf("setup-device: signing failed: %v", err)
		return
	}
	now := a.now().Unix()
	dev := trust.Device{Pub: m.DevicePub, Name: m.Name, Kind: m.Kind, AddedAt: now, LastUsed: now, Cert: cert}
	if err := a.store.Pin(dev); err != nil {
		a.logf("setup-device: saving failed: %v", err)
		return
	}
	hostMac := proto.HostConfirmMAC(a.setupKa, a.hostPub, dp)
	a.forgetSetupSecret()
	wasBound := a.bound()
	a.claimed, a.joined = true, true
	a.send(deviceApprovedMsg{Type: "device-approved", Cert: cert, HostMac: proto.B64(hostMac)})
	a.sendTrustSync()
	if !wasBound {
		a.sendHostStatus()
	}
	fp := proto.Fingerprint(dp)
	if join {
		a.appendLog(accesslog.Entry{Event: accesslog.EvJoinedAccount, Device: m.Name, DeviceFP: fp, Detail: "added to your account"})
		a.appendLog(accesslog.Entry{Event: accesslog.EvDeviceAdded, Device: m.Name, DeviceFP: fp, Detail: "added this Mac to your account"})
	} else {
		a.appendLog(accesslog.Entry{Event: accesslog.EvDeviceAdded, Device: m.Name, DeviceFP: fp, Detail: "first device (setup)"})
	}
	a.io.EmitEvent(Event{Event: "device-added", Device: devInfo(dev)})
	if join {
		a.io.EmitEvent(Event{Event: "joined-account", Device: devInfo(dev)})
	}
	a.dirty = true
}

// --------------------------------------------------------------- pairing

func (a *Agent) sendPairResult(reqID string, approved bool, cert *proto.Cert, reason string) {
	a.send(pairResultMsg{Type: "pair-result", RequestID: reqID, Approved: approved, Cert: cert, Reason: reason})
}

func (a *Agent) handlePairRequest(m inMsg) {
	now := a.now()
	id, err := proto.UnB64Len(m.RequestID, proto.IDSize)
	if err != nil {
		return
	}
	if a.killed() {
		a.sendPairResult(m.RequestID, false, nil, ReasonUnavailable)
		return
	}
	commit, _ := proto.UnB64(m.Commit)
	r, reason := a.pairing.Request(id, m.Name, m.Kind, commit, now)
	if r == nil {
		a.sendPairResult(m.RequestID, false, nil, reason)
		a.logf("pair-request refused: %s", reason)
		return
	}
	sig, err := a.sign(proto.LabelPairChallenge, r.ID, r.Commit, r.NA, a.hostPub)
	if err != nil {
		a.pairing.Remove(r.IDB64)
		a.sendPairResult(r.IDB64, false, nil, ReasonUnavailable)
		a.logf("pair-challenge signing failed: %v", err)
		return
	}
	a.send(pairChallengeMsg{Type: "pair-challenge", RequestID: r.IDB64, HostPub: proto.B64(a.hostPub), NA: proto.B64(r.NA), Sig: proto.B64(sig)})
}

func (a *Agent) handlePairReveal(m inMsg) {
	now := a.now()
	dp, _ := proto.UnB64(m.DevicePub)
	nd, _ := proto.UnB64(m.ND)
	r, reason := a.pairing.Reveal(m.RequestID, dp, nd, a.hostPub, now)
	switch reason {
	case "":
	case ReasonInvalid:
		return
	default:
		a.sendPairResult(m.RequestID, false, nil, reason)
		if reason == ReasonCommitMismatch {
			a.recordDenial(now)
			a.appendLog(accesslog.Entry{Event: accesslog.EvPairDenied, Device: r.Name, Detail: reason})
		}
		a.dirty = true
		return
	}
	if a.store.IsRevoked(m.DevicePub) {
		a.pairing.Remove(r.IDB64)
		a.sendPairResult(r.IDB64, false, nil, ReasonRevoked)
		a.dirty = true
		return
	}
	a.io.EmitEvent(Event{Event: "pair-request", Device: &DeviceInfo{
		Pub: m.DevicePub, Name: r.Name, Kind: r.Kind, Fingerprint: proto.Fingerprint(dp),
	}, Detail: proto.FormatSAS(r.SAS)})
	a.dirty = true
}

func (a *Agent) recordDenial(now time.Time) {
	if a.pairing.RecordDenial(now) {
		a.logf("pairing: too many denials, auto-denying new requests for 1 h")
	}
	_ = a.store.Update(func(d *trust.Data) {
		d.Denials = slices.Clone(a.pairing.Denials)
		d.AutoDenyUntil = a.pairing.AutoDenyUntil
	})
}

func (a *Agent) handlePairApprove(m inMsg) {
	r, ok := a.pairing.Pending(m.RequestID)
	if !ok || r.Phase != PhaseRevealed {
		return
	}
	approver, okDev := a.store.Device(m.ApproverPub)
	ap, err1 := proto.UnB64Len(m.ApproverPub, proto.PubKeySize)
	sig, err2 := proto.UnB64Len(m.Sig, proto.SignatureSize)
	if !okDev || err1 != nil || err2 != nil || !r.VerifyApproval(a.hostPub, ap, sig) {
		a.logf("pair-approve rejected (approver not pinned or bad signature)")
		a.appendLog(accesslog.Entry{Event: accesslog.EvApprovalRejected, Device: r.Name, Detail: "invalid approval"})
		return
	}
	a.approvePair(r, "approved by "+approver.Name)
}

// approvePair issues the cert, pins the device and answers the requester.
func (a *Agent) approvePair(r *PairReq, how string) {
	if a.store.IsRevoked(proto.B64(r.DevicePub)) {
		a.pairing.Remove(r.IDB64)
		a.sendPairResult(r.IDB64, false, nil, ReasonRevoked)
		return
	}
	cert, err := a.issueCert(r.DevicePub, r.Name, r.Kind)
	if err != nil {
		a.logf("pairing: cert signing failed: %v", err)
		return
	}
	now := a.now().Unix()
	dev := trust.Device{Pub: proto.B64(r.DevicePub), Name: r.Name, Kind: r.Kind, AddedAt: now, LastUsed: now, Cert: cert}
	if err := a.store.Pin(dev); err != nil {
		a.logf("pairing: saving failed: %v", err)
		return
	}
	a.pairing.Remove(r.IDB64)
	a.sendPairResult(r.IDB64, true, &cert, "")
	a.sendTrustSync()
	fp := proto.Fingerprint(r.DevicePub)
	a.appendLog(accesslog.Entry{Event: accesslog.EvPairApproved, Device: r.Name, DeviceFP: fp, Detail: how})
	a.appendLog(accesslog.Entry{Event: accesslog.EvDeviceAdded, Device: r.Name, DeviceFP: fp, Detail: r.Kind})
	a.io.EmitEvent(Event{Event: "device-added", Device: devInfo(dev)})
	a.dirty = true
}

func (a *Agent) denyPair(reqID, how string) {
	r, ok := a.pairing.Pending(reqID)
	if !ok {
		return
	}
	a.pairing.Remove(reqID)
	a.sendPairResult(reqID, false, nil, ReasonDenied)
	a.recordDenial(a.now())
	a.appendLog(accesslog.Entry{Event: accesslog.EvPairDenied, Device: r.Name, Detail: how})
	a.dirty = true
}

// ------------------------------------------------- revoke / kill (§7.3)

// freshSigned verifies a device-signed management request: pinned approver,
// fresh timestamp, valid signature, not replayed.
func (a *Agent) freshSigned(approverPub, sigB64 string, ts int64, label string, fields ...[]byte) (bool, string) {
	approver, ok := a.store.Device(approverPub)
	if !ok {
		return false, ""
	}
	ap, err1 := proto.UnB64Len(approverPub, proto.PubKeySize)
	sig, err2 := proto.UnB64Len(sigB64, proto.SignatureSize)
	if err1 != nil || err2 != nil || !proto.FreshTimestamp(ts, a.now()) {
		return false, ""
	}
	if !proto.Verify(ap, sig, label, fields...) {
		return false, ""
	}
	k := label + "|" + proto.B64(proto.Hash(sig))
	if _, dup := a.seen[k]; dup {
		return false, ""
	}
	a.seen[k] = a.now().Add(replayCacheTTL)
	return true, approver.Name
}

func (a *Agent) handleRevokeRequest(m inMsg) {
	tp, err := proto.UnB64Len(m.TargetPub, proto.PubKeySize)
	if err != nil {
		return
	}
	ok, by := a.freshSigned(m.ApproverPub, m.Sig, int64(m.TS), proto.LabelRevokeRequest, a.hostPub, tp, proto.Int(int64(m.TS)))
	if !ok {
		a.logf("revoke-request rejected")
		return
	}
	a.revoke(m.TargetPub, "revoked by "+by)
}

func (a *Agent) revoke(devicePub, how string) {
	dp, err := proto.UnB64Len(devicePub, proto.PubKeySize)
	if err != nil {
		return
	}
	at := a.now().Unix()
	sig, err := a.sign(proto.LabelRevoked, a.hostPub, dp, proto.Int(at))
	if err != nil {
		a.logf("revocation signing failed: %v", err)
		return
	}
	rev := proto.Revocation{HostPub: proto.B64(a.hostPub), DevicePub: devicePub, RevokedAt: at, Sig: proto.B64(sig)}
	dev, found, err := a.store.Revoke(rev)
	if err != nil {
		a.logf("revocation saving failed: %v", err)
		return
	}
	if s := a.sess; s != nil && s.dev.Pub == devicePub {
		a.endSession(s, "revoked", true)
	}
	a.send(deviceRevokedMsg{Type: "device-revoked", Revocation: rev})
	a.sendTrustSync()
	name := dev.Name
	if !found {
		name = "(unknown device)"
	}
	a.appendLog(accesslog.Entry{Event: accesslog.EvDeviceRemoved, Device: name, DeviceFP: proto.Fingerprint(dp), Detail: how})
	if found {
		a.io.EmitEvent(Event{Event: "device-removed", Device: devInfo(dev)})
	}
	a.dirty = true
}

func (a *Agent) handleKillRequest(m inMsg) {
	if m.Action != "kill" && m.Action != "resume" {
		return
	}
	ok, by := a.freshSigned(m.ApproverPub, m.Sig, int64(m.TS), proto.LabelKillRequest, a.hostPub, proto.Str(m.Action), proto.Int(int64(m.TS)))
	if !ok {
		a.logf("kill-request rejected")
		return
	}
	a.setKilled(m.Action == "kill", "by "+by)
}

func (a *Agent) setKilled(k bool, how string) {
	if a.store == nil {
		return
	}
	if err := a.store.Update(func(d *trust.Data) { d.Killed = k }); err != nil {
		a.logf("kill switch: saving failed: %v", err)
	}
	if k {
		if s := a.sess; s != nil {
			a.endSession(s, "killed", true)
		}
		a.appendLog(accesslog.Entry{Event: accesslog.EvKilled, Detail: how})
		a.io.EmitEvent(Event{Event: "killed", Detail: how})
	} else {
		a.appendLog(accesslog.Entry{Event: accesslog.EvResumed, Detail: how})
		a.io.EmitEvent(Event{Event: "resumed", Detail: how})
	}
	a.sendHostStatus()
	a.dirty = true
}

// ---------------------------------------------------------------- commands

// OnCommand handles a COMMAND frame payload.
func (a *Agent) OnCommand(raw []byte) {
	var c Command
	if err := json.Unmarshal(raw, &c); err != nil {
		a.logf("command: malformed")
		return
	}
	c.Raw = raw
	a.post(func() { a.handleCommand(c) })
}

func (a *Agent) handleCommand(c Command) {
	switch c.Cmd {
	case "quit":
		a.shutdown("host-shutdown")
		return
	case "log-read":
		a.readLog(c.Limit)
		return
	case "reset-trust-store":
		a.resetTrustStore()
		return
	case "displays":
		a.setDisplays(c.List, c.Active)
		return
	case "settings":
		raw := c.Settings
		if len(raw) == 0 {
			raw = c.Raw
		}
		a.applySettings(raw)
		return
	}
	if a.store == nil {
		return
	}
	switch c.Cmd {
	case "kill":
		a.setKilled(true, "on this Mac")
	case "resume":
		a.setKilled(false, "on this Mac")
	case "disconnect":
		if s := a.sess; s != nil {
			a.endSession(s, "host-disconnected", true)
		}
	case "approve":
		if r, ok := a.pairing.Pending(c.RequestID); ok && r.Phase == PhaseRevealed {
			a.approvePair(r, "approved on this Mac")
		}
	case "deny":
		a.denyPair(c.RequestID, "denied on this Mac")
	case "revoke":
		a.revoke(c.DevicePub, "revoked on this Mac")
	case "clipboard":
		if s := a.sess; s != nil && s.state == sessConnected {
			s.sendClipboard(c.Text)
		}
	case "new-setup-code":
		// A setup code for an unclaimed server, a join code otherwise
		// (corrected on the next host-ready if the server says differently).
		if a.claimed {
			a.newSecret(proto.JoinSecretSize)
		} else {
			a.newSetupSecret()
		}
		a.requestReconnect() // re-send host-auth with the new claimCommit
	default:
		a.logf("command: unknown %q", truncate(c.Cmd, 32))
	}
}

func (a *Agent) applySettings(raw json.RawMessage) {
	s := a.settings
	if err := json.Unmarshal(raw, &s); err != nil {
		return
	}
	a.settings = sanitizeSettings(s)
	if sess := a.sess; sess != nil {
		if !a.settings.AllowBrowserClients && IsBrowserKind(sess.dev.Kind) {
			a.endSession(sess, "browser-disabled", true)
		} else {
			sess.setMaxKbps(a.settings.MaxKbps)
		}
	}
}

// OnConfig applies a CONFIG received after Start (settings only).
func (a *Agent) OnConfig(cfg Config) {
	b, _ := json.Marshal(cfg.Settings)
	a.post(func() {
		if cfg.HostPub != a.cfg.HostPub || cfg.StorageKey != a.cfg.StorageKey || cfg.DataDir != a.cfg.DataDir {
			a.logf("CONFIG: identity changes require a restart; ignored")
		}
		a.cfg.HEVCAvailable, a.cfg.AudioAvailable = cfg.HEVCAvailable, cfg.AudioAvailable
		a.applySettings(b)
	})
}

func (a *Agent) setDisplays(list []Display, active int64) {
	if len(list) > 16 {
		list = list[:16]
	}
	a.displays = slices.Clone(list)
	if active == 0 && len(list) > 0 {
		active = list[0].ID
		for _, d := range list {
			if d.Primary {
				active = d.ID
			}
		}
	}
	a.activeDisplay = active
	if s := a.sess; s != nil {
		s.setDisplays(a.displays, active)
	}
}

// maxLogRead bounds LOG frames well below the 16 MiB IPC limit.
const maxLogRead = 5000

func (a *Agent) readLog(limit int) {
	if limit <= 0 || limit > maxLogRead {
		limit = maxLogRead
	}
	if a.alog == nil {
		a.io.EmitLog(LogResult{Entries: []accesslog.Entry{}, Verified: false, Error: "access log unavailable"})
		return
	}
	res := a.alog.Verify()
	entries := accesslog.Tail(res.Entries, limit)
	if entries == nil {
		entries = []accesslog.Entry{}
	}
	if a.store == nil && res.Error == "" {
		res.Error = "trust store unavailable"
	}
	a.io.EmitLog(LogResult{Entries: entries, Verified: res.Verified, Error: res.Error})
}

// resetTrustStore is an explicit owner action from the Mac UI, allowed only
// while the trust store is unusable (tampered / foreign host key): it moves
// pins.json and the access log aside as evidence and starts afresh (setup
// code). A healthy store is never wiped by this command.
func (a *Agent) resetTrustStore() {
	if a.store != nil {
		a.logf("reset-trust-store refused: the trust store is healthy")
		return
	}
	if s := a.sess; s != nil {
		a.endSession(s, "trust-reset", true)
	}
	suffix := strconv.FormatInt(a.now().Unix(), 10)
	if err := trust.Quarantine(a.cfg.DataDir, suffix); err != nil {
		a.logf("reset-trust-store: %v", err)
		return
	}
	a.store, a.storeErr, a.alog = nil, nil, nil
	a.server, a.serverError = signaling.StatusOffline, ""
	a.openStores()
	a.appendLog(accesslog.Entry{Event: accesslog.EvTrustStoreReset, Detail: "previous files kept with suffix ." + suffix})
	if a.store != nil && !a.opts.NoSignaling {
		if a.sig == nil {
			a.startSignaling()
		} else {
			a.sig.Reconnect()
		}
	}
	a.dirty = true
}

// --------------------------------------------------------------- helpers

func devInfo(d trust.Device) *DeviceInfo {
	pub, _ := proto.UnB64(d.Pub)
	return &DeviceInfo{Pub: d.Pub, Name: d.Name, Kind: d.Kind, Fingerprint: proto.Fingerprint(pub)}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
