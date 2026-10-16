package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/interceptor"
	"github.com/pion/interceptor/pkg/cc"
	"github.com/pion/interceptor/pkg/gcc"
	"github.com/pion/interceptor/pkg/nack"
	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
	"github.com/pion/webrtc/v4"

	"github.com/videoproduction-ctrl/heartfulness-remote/agent/internal/accesslog"
	"github.com/videoproduction-ctrl/heartfulness-remote/agent/internal/trust"
	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
)

// Session limits.
const (
	MaxOfferSDP      = 128 << 10
	maxDCMessage     = 2 << 20 // accept clip (≤ 1 MiB text) after JSON escaping
	rtpMTU           = 1200 - 12
	keyframeInterval = 500 * time.Millisecond
	initialKbps      = 8000
	idleWarnBefore   = 60 * time.Second
)

// Session reject reasons (PROTOCOL.md §7.3).
const (
	RejectBlocked         = "blocked"
	RejectBusy            = "busy"
	RejectNotTrusted      = "not-trusted"
	RejectBrowserDisabled = "browser-disabled"
	RejectError           = "error"
)

type sessState int

const (
	sessAccepted sessState = iota + 1
	sessNegotiating
	sessConnected
	sessClosed
)

// Offer verification errors.
var (
	errOfferReplay      = errors.New("offer replayed (nonce already used)")
	errOfferStale       = errors.New("offer arrived too late")
	errOfferFingerprint = errors.New("offer must contain exactly one sha-256 fingerprint")
	errOfferSig         = errors.New("offer signature invalid")
	errOfferUntrusted   = errors.New("device no longer trusted")
	errOfferInvalid     = errors.New("offer malformed")
)

// Session is one remote-control session.
type Session struct {
	a           *Agent
	id          []byte
	idB64       string
	dev         trust.Device
	devPub      []byte
	clientNonce []byte
	hostNonce   []byte
	relayOnly   bool
	acceptedAt  time.Time

	// Loop-owned.
	state       sessState
	offerUsed   bool
	answeredAt  time.Time
	connectedAt time.Time
	idleWarned  bool
	pendingICE  []webrtc.ICECandidateInit
	pc          *webrtc.PeerConnection
	codec       codecChoice
	audioOn     bool

	// Media (OnVideo/OnAudio goroutines).
	live    atomic.Bool
	vmu     sync.Mutex
	vtrack  *webrtc.TrackLocalStaticRTP
	vpay    rtp.Payloader
	vseq    rtp.Sequencer
	vts0    uint32
	needKey bool
	amu     sync.Mutex
	atrack  *webrtc.TrackLocalStaticRTP
	apay    rtp.Payloader
	aseq    rtp.Sequencer
	ats0    uint32

	kmu        sync.Mutex
	lastKeyReq time.Time

	// Bandwidth.
	bmu        sync.Mutex
	targetBps  int
	mode       string
	clientMax  int
	settingMax int
	lastKbps   int
	lastFPS    int

	// Stats.
	smu       sync.Mutex
	transport string
	rtt       int

	// Data channels and transfers.
	dmu           sync.Mutex
	control       *webrtc.DataChannel
	input         *webrtc.DataChannel
	pointer       *webrtc.DataChannel
	file          *webrtc.DataChannel
	displays      []Display
	uploads       map[[16]byte]*upload
	downloads     map[[16]byte]*download
	fileLow       chan struct{}
	activeDisplay atomic.Int64
	lastInput     atomic.Int64
	inputBucket   *tokenBucket
	pointerBucket *tokenBucket
	closed        atomic.Bool
}

func (s *Session) deviceInfo() DeviceInfo {
	return DeviceInfo{Pub: s.dev.Pub, Name: s.dev.Name, Kind: s.dev.Kind, Fingerprint: proto.Fingerprint(s.devPub)}
}

func (s *Session) transportName() string {
	s.smu.Lock()
	defer s.smu.Unlock()
	if s.transport == "" {
		return "direct"
	}
	return s.transport
}

func (s *Session) rttMs() int {
	s.smu.Lock()
	defer s.smu.Unlock()
	return s.rtt
}

// decideSession applies the §7.3 acceptance rules. replace is true when the
// same device already has a session (the old one is ended).
func decideSession(killed, known bool, dev trust.Device, allowBrowser bool, active *Session) (reject string, replace bool) {
	switch {
	case killed:
		return RejectBlocked, false
	case !known:
		return RejectNotTrusted, false
	case IsBrowserKind(dev.Kind) && !allowBrowser:
		return RejectBrowserDisabled, false
	}
	if active != nil && active.state != sessClosed {
		if active.dev.Pub != dev.Pub {
			return RejectBusy, false
		}
		return "", true
	}
	return "", false
}

// verifyOffer checks an offer against the accepted session request. pinned
// is the device key from the trust store (never from the server message).
func verifyOffer(s *Session, pinned, hostPub []byte, sdp string, sig []byte, now time.Time) error {
	if s.offerUsed {
		return errOfferReplay
	}
	if now.Sub(s.acceptedAt) > OfferTimeout {
		return errOfferStale
	}
	if pinned == nil {
		return errOfferUntrusted
	}
	if len(sdp) == 0 || len(sdp) > MaxOfferSDP {
		return errOfferInvalid
	}
	if _, err := proto.SDPFingerprint(sdp); err != nil {
		return errOfferFingerprint
	}
	if !proto.Verify(pinned, sig, proto.LabelOffer,
		s.id, hostPub, s.devPub, s.clientNonce, s.hostNonce, proto.Hash([]byte(sdp))) {
		return errOfferSig
	}
	return nil
}

// ---------------------------------------------------------- agent side

func (a *Agent) handleSessionRequest(m inMsg) {
	sid, err := proto.UnB64Len(m.SessionID, proto.IDSize)
	if err != nil {
		return
	}
	reject := func(r string) {
		a.send(sessionRejectMsg{Type: "session-reject", SessionID: m.SessionID, Reason: r})
		a.logf("session-request rejected: %s", r)
	}
	cn, err := proto.UnB64Len(m.ClientNonce, proto.NonceSize)
	if err != nil {
		reject(RejectError)
		return
	}
	dev, known := a.store.Device(m.DevicePub)
	reason, replace := decideSession(a.killed(), known, dev, a.settings.AllowBrowserClients, a.sess)
	if reason != "" {
		reject(reason)
		return
	}
	if a.sess != nil && a.sess.idB64 == m.SessionID {
		reject(RejectError)
		return
	}
	if replace {
		a.endSession(a.sess, "replaced", true)
	}
	devPub, _ := proto.UnB64Len(dev.Pub, proto.PubKeySize)
	s := &Session{
		a: a, id: sid, idB64: m.SessionID, dev: dev, devPub: devPub,
		clientNonce: cn, hostNonce: randBytes(proto.NonceSize),
		relayOnly: m.RelayOnly || a.settings.RelayOnly, acceptedAt: a.now(),
		state: sessAccepted, mode: "auto", settingMax: a.settings.MaxKbps,
		uploads: map[[16]byte]*upload{}, downloads: map[[16]byte]*download{},
		fileLow: make(chan struct{}, 1), displays: slices.Clone(a.displays),
		inputBucket: newTokenBucket(400, 800), pointerBucket: newTokenBucket(600, 1200),
	}
	s.activeDisplay.Store(a.activeDisplay)
	a.sess = s
	a.send(sessionAcceptMsg{Type: "session-accept", SessionID: s.idB64, HostNonce: proto.B64(s.hostNonce)})
}

func (a *Agent) handleOffer(m inMsg) {
	s := a.sess
	if s == nil || s.idB64 != m.SessionID {
		a.logf("offer for an unknown session ignored")
		return
	}
	sig, _ := proto.UnB64(m.Sig)
	var pinned []byte
	if d, ok := a.store.Device(s.dev.Pub); ok && !a.killed() {
		pinned, _ = proto.UnB64Len(d.Pub, proto.PubKeySize)
	}
	if err := verifyOffer(s, pinned, a.hostPub, m.SDP, sig, a.now()); err != nil {
		a.logf("offer rejected: %v", err)
		if errors.Is(err, errOfferReplay) {
			return // never let a replay disturb the running session
		}
		a.appendLog(accesslog.Entry{Event: accesslog.EvOfferRejected, Device: s.dev.Name, DeviceFP: proto.Fingerprint(s.devPub), Detail: err.Error()})
		a.endSession(s, "offer-rejected", true)
		return
	}
	s.offerUsed = true
	s.state = sessNegotiating
	answer, err := s.start(m.SDP)
	if err != nil {
		a.logf("session setup failed: %v", err)
		reason := RejectError
		if errors.Is(err, errNoCommonCodec) {
			reason = "no-common-codec"
		}
		a.endSession(s, reason, true)
		return
	}
	sigA, err := a.sign(proto.LabelAnswer, s.id, a.hostPub, s.devPub, s.clientNonce, s.hostNonce,
		proto.Hash([]byte(m.SDP)), proto.Hash([]byte(answer)))
	if err != nil {
		a.logf("answer signing failed: %v", err)
		a.endSession(s, RejectError, true)
		return
	}
	a.send(answerMsg{Type: "answer", SessionID: s.idB64, SDP: answer, Sig: proto.B64(sigA)})
	s.answeredAt = a.now()
	for _, c := range s.pendingICE {
		_ = s.pc.AddICECandidate(c)
	}
	s.pendingICE = nil
}

func (a *Agent) handleICE(m inMsg) {
	s := a.sess
	if s == nil || s.idB64 != m.SessionID || len(m.Candidate) > 4096 {
		return
	}
	if len(m.Candidate) == 0 || string(m.Candidate) == "null" {
		return // end of candidates
	}
	var c webrtc.ICECandidateInit
	if err := json.Unmarshal(m.Candidate, &c); err != nil || c.Candidate == "" {
		return
	}
	if s.pc == nil {
		if len(s.pendingICE) < 64 {
			s.pendingICE = append(s.pendingICE, c)
		}
		return
	}
	if err := s.pc.AddICECandidate(c); err != nil {
		a.logf("ice: %v", err)
	}
}

func (a *Agent) tickSession(s *Session, now time.Time) {
	switch s.state {
	case sessAccepted:
		if now.Sub(s.acceptedAt) > OfferTimeout {
			a.endSession(s, "offer-timeout", true)
		}
	case sessNegotiating:
		if now.Sub(s.answeredAt) > ConnectTimeout {
			a.endSession(s, "connect-timeout", true)
		}
	case sessConnected:
		s.updateBitrate()
		s.checkTransfers(now)
		timeout := time.Duration(a.settings.IdleTimeoutMin) * time.Minute
		idle := now.Sub(time.Unix(0, s.lastInput.Load()))
		switch {
		case idle >= timeout:
			a.endSession(s, "idle", true)
		case idle >= timeout-idleWarnBefore:
			if !s.idleWarned {
				s.idleWarned = true
				left := int((timeout - idle).Round(time.Second).Seconds())
				a.io.EmitEvent(Event{Event: "idle-warning", Device: ptr(s.deviceInfo()), Detail: fmt.Sprintf("%d", left)})
				s.sendCtl(noticeMsg{T: "notice", Level: "warn",
					Text: fmt.Sprintf("No activity: this session ends in %d seconds.", left)})
			}
		default:
			s.idleWarned = false
		}
	}
}

func ptr[T any](v T) *T { return &v }

func (a *Agent) onPCState(s *Session, st webrtc.PeerConnectionState) {
	if a.sess != s || s.state == sessClosed {
		return
	}
	switch st {
	case webrtc.PeerConnectionStateConnected:
		if s.state == sessNegotiating {
			a.onConnected(s)
		}
	case webrtc.PeerConnectionStateFailed:
		a.endSession(s, "connection-failed", true)
	case webrtc.PeerConnectionStateClosed:
		a.endSession(s, "connection-closed", true)
	}
}

func (a *Agent) onConnected(s *Session) {
	now := a.now()
	s.state = sessConnected
	s.connectedAt = now
	s.lastInput.Store(now.UnixNano())
	s.refreshStats()
	_ = a.store.Touch(s.dev.Pub, now.Unix())
	s.vmu.Lock()
	s.needKey = true
	s.vmu.Unlock()
	s.live.Store(true)
	a.media.Store(s)
	kbps, fps := s.desiredEncoder()
	s.bmu.Lock()
	s.lastKbps, s.lastFPS = kbps, fps
	s.bmu.Unlock()
	a.io.EmitEncoder(EncoderCmd{Cmd: "start", Codec: s.codec.id.String(), Profile: s.codec.profile,
		FPS: fps, Kbps: kbps, Display: s.activeDisplay.Load()})
	if s.audioOn {
		a.io.EmitAudioCtl("start")
	}
	a.appendLog(accesslog.Entry{Event: accesslog.EvSessionStart, Device: s.dev.Name,
		DeviceFP: proto.Fingerprint(s.devPub), Transport: s.transportName()})
	a.io.EmitEvent(Event{Event: "session-start", Device: ptr(s.deviceInfo()), Detail: s.transportName()})
	a.sendHostStatus()
	a.dirty = true
}

// endSession tears a session down. notifyServer sends session-end.
func (a *Agent) endSession(s *Session, reason string, notifyServer bool) {
	if s == nil || s.state == sessClosed {
		return
	}
	prev := s.state
	s.state = sessClosed
	if a.sess == s {
		a.sess = nil
	}
	a.media.CompareAndSwap(s, nil)
	s.live.Store(false)
	s.close(reason)
	if prev == sessConnected {
		a.io.EmitEncoder(EncoderCmd{Cmd: "stop"})
		if s.audioOn {
			a.io.EmitAudioCtl("stop")
		}
		dur := int64(a.now().Sub(s.connectedAt).Round(time.Second).Seconds())
		a.appendLog(accesslog.Entry{Event: accesslog.EvSessionEnd, Device: s.dev.Name,
			DeviceFP: proto.Fingerprint(s.devPub), Transport: s.transportName(), Duration: dur, Detail: reason})
		a.io.EmitEvent(Event{Event: "session-end", Device: ptr(s.deviceInfo()), Detail: reason})
		a.sendHostStatus()
	}
	if notifyServer {
		a.send(sessionEndMsg{Type: "session-end", SessionID: s.idB64, Reason: reason})
	}
	a.dirty = true
}

// codecs returns the producible codecs in preference order.
func (a *Agent) codecs() []Codec {
	if a.opts.Codecs != nil {
		out := slices.Clone(a.opts.Codecs)
		if !a.opts.Simulator {
			out = slices.DeleteFunc(out, func(c Codec) bool { return c == CodecVP8 })
		}
		return out
	}
	var out []Codec
	if a.cfg.HEVCAvailable && a.settings.Codec != "h264" {
		out = append(out, CodecH265)
	}
	return append(out, CodecH264)
}

// ------------------------------------------------------- peer connection

func (s *Session) start(offer string) (string, error) {
	a := s.a
	choice, err := chooseVideoCodec(offer, a.codecs())
	if err != nil {
		return "", err
	}
	s.codec = choice
	m := &webrtc.MediaEngine{}
	if err := m.RegisterCodec(webrtc.RTPCodecParameters{RTPCodecCapability: choice.cap, PayloadType: 96}, webrtc.RTPCodecTypeVideo); err != nil {
		return "", err
	}
	opus := webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: 48000, Channels: 2, SDPFmtpLine: fmtpOpus}
	if err := m.RegisterCodec(webrtc.RTPCodecParameters{RTPCodecCapability: opus, PayloadType: 111}, webrtc.RTPCodecTypeAudio); err != nil {
		return "", err
	}
	reg := &interceptor.Registry{}
	maxBps := s.settingMax * 1000
	ccf, err := cc.NewInterceptor(func() (cc.BandwidthEstimator, error) {
		return gcc.NewSendSideBWE(
			gcc.SendSideBWEInitialBitrate(min(initialKbps, s.settingMax)*1000),
			gcc.SendSideBWEMinBitrate(300_000),
			gcc.SendSideBWEMaxBitrate(maxBps),
			gcc.SendSideBWEPacer(gcc.NewNoOpPacer()),
		)
	})
	if err != nil {
		return "", err
	}
	ccf.OnNewPeerConnection(func(_ string, est cc.BandwidthEstimator) {
		est.OnTargetBitrateChange(func(bps int) {
			s.bmu.Lock()
			s.targetBps = bps
			s.bmu.Unlock()
		})
	})
	reg.Add(ccf) // first: innermost, sees the transport-cc sequence numbers
	if err := webrtc.ConfigureTWCCHeaderExtensionSender(m, reg); err != nil {
		return "", err
	}
	if err := webrtc.ConfigureNackWithOptions(m, reg, nil, nack.ResponderSize(8192)); err != nil {
		return "", err
	}
	if err := webrtc.ConfigureRTCPReports(reg); err != nil {
		return "", err
	}
	m.RegisterFeedback(webrtc.RTCPFeedback{Type: webrtc.TypeRTCPFBTransportCC}, webrtc.RTPCodecTypeVideo)
	m.RegisterFeedback(webrtc.RTCPFeedback{Type: webrtc.TypeRTCPFBTransportCC}, webrtc.RTPCodecTypeAudio)
	m.RegisterFeedback(webrtc.RTCPFeedback{Type: webrtc.TypeRTCPFBCCM, Parameter: "fir"}, webrtc.RTPCodecTypeVideo)

	se := webrtc.SettingEngine{}
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4, webrtc.NetworkTypeUDP6})
	se.SetSCTPMaxMessageSize(maxDCMessage)
	se.SetSCTPMaxReceiveBufferSize(4 << 20)
	se.SetICETimeouts(5*time.Second, 15*time.Second, 2*time.Second)
	if a.opts.IncludeLoopback {
		se.SetIncludeLoopbackCandidate(true)
	}
	api := webrtc.NewAPI(webrtc.WithMediaEngine(m), webrtc.WithInterceptorRegistry(reg), webrtc.WithSettingEngine(se))
	conf := webrtc.Configuration{
		ICEServers:    slices.Clone(a.iceServers),
		BundlePolicy:  webrtc.BundlePolicyMaxBundle,
		RTCPMuxPolicy: webrtc.RTCPMuxPolicyRequire,
	}
	if s.relayOnly {
		conf.ICETransportPolicy = webrtc.ICETransportPolicyRelay
	}
	// No Certificates: pion generates a fresh ECDSA P-256 DTLS certificate
	// for every PeerConnection; its fingerprint is what we sign.
	pc, err := api.NewPeerConnection(conf)
	if err != nil {
		return "", err
	}
	s.pc = pc
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		var cand any
		if c != nil {
			j := c.ToJSON()
			cand = j
		}
		a.post(func() {
			if a.sess == s && s.state != sessClosed {
				a.send(iceMsg{Type: "ice", SessionID: s.idB64, Candidate: cand})
			}
		})
	})
	pc.OnConnectionStateChange(func(st webrtc.PeerConnectionState) {
		a.post(func() { a.onPCState(s, st) })
	})
	pc.OnDataChannel(s.onDataChannel)

	if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offer}); err != nil {
		return "", err
	}
	s.vtrack, err = webrtc.NewTrackLocalStaticRTP(choice.cap, "video", "hr")
	if err != nil {
		return "", err
	}
	vs, err := pc.AddTrack(s.vtrack)
	if err != nil {
		return "", err
	}
	go s.readRTCP(vs, true)
	s.vpay = payloaderFor(choice.id)
	s.vseq = rtp.NewRandomSequencer()
	s.vts0 = randUint32()
	if a.cfg.AudioAvailable || a.opts.Simulator {
		s.atrack, err = webrtc.NewTrackLocalStaticRTP(opus, "audio", "hr")
		if err != nil {
			return "", err
		}
		as, err := pc.AddTrack(s.atrack)
		if err != nil {
			return "", err
		}
		go s.readRTCP(as, false)
		s.apay = &codecs.OpusPayloader{}
		s.aseq = rtp.NewRandomSequencer()
		s.ats0 = randUint32()
		s.audioOn = true
	}
	ans, err := pc.CreateAnswer(nil)
	if err != nil {
		return "", err
	}
	if err := pc.SetLocalDescription(ans); err != nil {
		return "", err
	}
	if _, err := proto.SDPFingerprint(ans.SDP); err != nil {
		return "", fmt.Errorf("own answer: %w", err)
	}
	return ans.SDP, nil
}

func payloaderFor(c Codec) rtp.Payloader {
	switch c {
	case CodecH265:
		return &codecs.H265Payloader{}
	case CodecVP8:
		return &codecs.VP8Payloader{EnablePictureID: true}
	default:
		return &codecs.H264Payloader{}
	}
}

func randUint32() uint32 {
	b := randBytes(4)
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func (s *Session) readRTCP(sender *webrtc.RTPSender, video bool) {
	for {
		pkts, _, err := sender.ReadRTCP()
		if err != nil {
			return
		}
		if !video {
			continue
		}
		for _, p := range pkts {
			switch p.(type) {
			case *rtcp.PictureLossIndication, *rtcp.FullIntraRequest:
				s.requestKeyframe()
			}
		}
	}
}

func (s *Session) requestKeyframe() {
	s.kmu.Lock()
	now := time.Now()
	if now.Sub(s.lastKeyReq) < keyframeInterval {
		s.kmu.Unlock()
		return
	}
	s.lastKeyReq = now
	s.kmu.Unlock()
	s.a.io.EmitEncoder(EncoderCmd{Cmd: "keyframe"})
}

// OnVideo feeds one encoded access unit (Annex-B) from the Mac.
func (a *Agent) OnVideo(codec Codec, keyframe bool, ptsMicros uint64, data []byte) {
	if s := a.media.Load(); s != nil {
		s.writeVideo(codec, keyframe, ptsMicros, data)
	}
}

// OnAudio feeds one 20 ms Opus packet from the Mac.
func (a *Agent) OnAudio(ptsMicros uint64, data []byte) {
	if s := a.media.Load(); s != nil {
		s.writeAudio(ptsMicros, data)
	}
}

func (s *Session) writeVideo(codec Codec, keyframe bool, pts uint64, data []byte) {
	if !s.live.Load() || codec != s.codec.id || len(data) == 0 {
		return
	}
	s.vmu.Lock()
	if s.needKey && !keyframe {
		s.vmu.Unlock()
		s.requestKeyframe()
		return
	}
	s.needKey = false
	// RTP timestamps come straight from the capture pts (90 kHz), so the
	// receiver sees the real (variable) frame timing of ScreenCaptureKit.
	ts := s.vts0 + uint32(pts*9/100)
	payloads := s.vpay.Payload(rtpMTU, data)
	for i, p := range payloads {
		pkt := &rtp.Packet{Header: rtp.Header{
			Version: 2, Marker: i == len(payloads)-1,
			SequenceNumber: s.vseq.NextSequenceNumber(), Timestamp: ts,
		}, Payload: p}
		if err := s.vtrack.WriteRTP(pkt); err != nil {
			break
		}
	}
	s.vmu.Unlock()
}

func (s *Session) writeAudio(pts uint64, data []byte) {
	if !s.live.Load() || s.atrack == nil || len(data) == 0 {
		return
	}
	s.amu.Lock()
	defer s.amu.Unlock()
	ts := s.ats0 + uint32(pts*48/1000)
	for _, p := range s.apay.Payload(rtpMTU, data) {
		_ = s.atrack.WriteRTP(&rtp.Packet{Header: rtp.Header{
			Version: 2, SequenceNumber: s.aseq.NextSequenceNumber(), Timestamp: ts,
		}, Payload: p})
	}
}

// ------------------------------------------------------------- bandwidth

func (s *Session) capKbps() int {
	c := s.settingMax
	if s.clientMax > 0 {
		c = min(c, s.clientMax)
	}
	return max(c, MinKbps)
}

// desiredEncoder maps the GCC target and the quality mode to encoder
// settings: "smooth" keeps 60 fps, "sharp" spends bits on 30 fps frames,
// "auto" switches with hysteresis.
func (s *Session) desiredEncoder() (kbps, fps int) {
	s.bmu.Lock()
	defer s.bmu.Unlock()
	target := s.targetBps / 1000
	if target <= 0 {
		target = initialKbps
	}
	kbps = min(max(target, MinKbps), s.capKbps())
	switch s.mode {
	case "smooth":
		fps = 60
	case "sharp":
		fps = 30
	default:
		switch {
		case kbps >= 6000:
			fps = 60
		case kbps < 4000:
			fps = 30
		case s.lastFPS != 0:
			fps = s.lastFPS
		default:
			fps = 60
		}
	}
	return kbps, fps
}

func (s *Session) updateBitrate() {
	kbps, fps := s.desiredEncoder()
	s.bmu.Lock()
	changed := fps != s.lastFPS || s.lastKbps == 0 || abs(kbps-s.lastKbps)*100 > 5*s.lastKbps
	if changed {
		s.lastKbps, s.lastFPS = kbps, fps
	}
	s.bmu.Unlock()
	if changed {
		s.a.io.EmitEncoder(EncoderCmd{Cmd: "bitrate", Kbps: kbps, FPS: fps})
	}
}

func (s *Session) setMaxKbps(k int) {
	s.bmu.Lock()
	s.settingMax = k
	s.bmu.Unlock()
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// refreshStats updates transport (direct/relay) and RTT. Loop only.
func (s *Session) refreshStats() {
	if s.pc == nil {
		return
	}
	transport := "direct"
	if sctp := s.pc.SCTP(); sctp != nil && sctp.Transport() != nil {
		if pair, err := sctp.Transport().ICETransport().GetSelectedCandidatePair(); err == nil && pair != nil {
			if pair.Local.Typ == webrtc.ICECandidateTypeRelay || pair.Remote.Typ == webrtc.ICECandidateTypeRelay {
				transport = "relay"
			}
		}
	}
	rtt := -1
	for _, st := range s.pc.GetStats() {
		if cp, ok := st.(webrtc.ICECandidatePairStats); ok && cp.Nominated &&
			cp.State == webrtc.StatsICECandidatePairStateSucceeded && cp.CurrentRoundTripTime > 0 {
			rtt = int(cp.CurrentRoundTripTime*1000 + 0.5)
		}
	}
	s.smu.Lock()
	s.transport = transport
	if rtt >= 0 {
		s.rtt = rtt
	}
	s.smu.Unlock()
}

// close sends bye, aborts transfers and closes the peer connection.
func (s *Session) close(reason string) {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	s.dmu.Lock()
	ctl := s.control
	for id, u := range s.uploads {
		u.up.Abort()
		delete(s.uploads, id)
	}
	for id, d := range s.downloads {
		d.cancel()
		delete(s.downloads, id)
	}
	s.dmu.Unlock()
	if ctl != nil {
		if b, err := json.Marshal(byeMsg{T: "bye", Reason: reason}); err == nil {
			_ = ctl.SendText(string(b))
		}
	}
	if pc := s.pc; pc != nil {
		go func() {
			time.Sleep(100 * time.Millisecond) // let "bye" leave
			_ = pc.Close()
		}()
	}
}
