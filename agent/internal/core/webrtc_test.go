package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/interceptor"
	"github.com/pion/rtcp"
	"github.com/pion/webrtc/v4"

	"github.com/videoproduction-ctrl/heartfulness-remote/agent/internal/accesslog"
	"github.com/videoproduction-ctrl/heartfulness-remote/agent/internal/mediafile"
	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
)

// testClient plays the browser: a pion peer with a pinned device key that
// talks to the agent through an in-memory signaling path.
type testClient struct {
	t        *testing.T
	pc       *webrtc.PeerConnection
	control  *webrtc.DataChannel
	input    *webrtc.DataChannel
	pointer  *webrtc.DataChannel
	file     *webrtc.DataChannel
	ctlMsgs  chan map[string]any
	fileMsgs chan []byte

	videoPkts, audioPkts atomic.Int64
	sawSPS, sawIDR       atomic.Bool
	videoSSRC            atomic.Uint32
	videoMime            atomic.Value
}

func newTestClient(t *testing.T) *testClient {
	t.Helper()
	m := &webrtc.MediaEngine{}
	if err := m.RegisterDefaultCodecs(); err != nil {
		t.Fatal(err)
	}
	reg := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(m, reg); err != nil {
		t.Fatal(err)
	}
	se := webrtc.SettingEngine{}
	se.SetIncludeLoopbackCandidate(true)
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	api := webrtc.NewAPI(webrtc.WithMediaEngine(m), webrtc.WithInterceptorRegistry(reg), webrtc.WithSettingEngine(se))
	pc, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	c := &testClient{t: t, pc: pc, ctlMsgs: make(chan map[string]any, 256), fileMsgs: make(chan []byte, 4096)}
	t.Cleanup(func() { _ = pc.Close() })
	for _, k := range []webrtc.RTPCodecType{webrtc.RTPCodecTypeVideo, webrtc.RTPCodecTypeAudio} {
		if _, err := pc.AddTransceiverFromKind(k, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly}); err != nil {
			t.Fatal(err)
		}
	}
	unordered, zero := false, uint16(0)
	c.control, _ = pc.CreateDataChannel("control", nil)
	c.input, _ = pc.CreateDataChannel("input", nil)
	c.pointer, _ = pc.CreateDataChannel("pointer", &webrtc.DataChannelInit{Ordered: &unordered, MaxRetransmits: &zero})
	c.file, _ = pc.CreateDataChannel("file", nil)
	c.control.OnMessage(func(msg webrtc.DataChannelMessage) {
		var m map[string]any
		if json.Unmarshal(msg.Data, &m) == nil {
			c.ctlMsgs <- m
		}
	})
	c.file.OnMessage(func(msg webrtc.DataChannelMessage) {
		if !msg.IsString {
			c.fileMsgs <- append([]byte{}, msg.Data...)
		}
	})
	pc.OnTrack(func(tr *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		video := tr.Kind() == webrtc.RTPCodecTypeVideo
		if video {
			c.videoSSRC.Store(uint32(tr.SSRC()))
			c.videoMime.Store(tr.Codec().MimeType + ";" + tr.Codec().SDPFmtpLine)
		}
		for {
			p, _, err := tr.ReadRTP()
			if err != nil {
				return
			}
			if !video {
				c.audioPkts.Add(1)
				continue
			}
			c.videoPkts.Add(1)
			if len(p.Payload) < 2 {
				continue
			}
			switch p.Payload[0] & 0x1f {
			case 24: // STAP-A: SPS/PPS aggregated in front of the IDR
				if len(p.Payload) > 3 && p.Payload[3]&0x1f == 7 {
					c.sawSPS.Store(true)
				}
			case 7:
				c.sawSPS.Store(true)
			case 5:
				c.sawIDR.Store(true)
			case 28: // FU-A
				if p.Payload[1]&0x80 != 0 && p.Payload[1]&0x1f == 5 {
					c.sawIDR.Store(true)
				}
			}
		}
	})
	return c
}

func (c *testClient) ctl(t *testing.T, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	if err := c.control.SendText(string(b)); err != nil {
		t.Fatal(err)
	}
}

// nextCtl waits for a control message of type typ.
func (c *testClient) nextCtl(t *testing.T, typ string, timeout time.Duration) map[string]any {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case m := <-c.ctlMsgs:
			if m["t"] == typ {
				return m
			}
		case <-deadline:
			t.Fatalf("timed out waiting for control %q", typ)
		}
	}
}

func waitOpen(t *testing.T, dcs ...*webrtc.DataChannel) {
	t.Helper()
	waitFor(t, "data channels open", 10*time.Second, func() bool {
		for _, d := range dcs {
			if d.ReadyState() != webrtc.DataChannelStateOpen {
				return false
			}
		}
		return true
	})
}

func (h *fakeHost) encoderCmds(cmd string) []EncoderCmd {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []EncoderCmd
	for _, c := range h.encoder {
		if c.Cmd == cmd {
			out = append(out, c)
		}
	}
	return out
}

func (h *fakeHost) inputContains(sub string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, in := range h.inputs {
		if strings.Contains(string(in), sub) {
			return true
		}
	}
	return false
}

func TestWebRTCIntegration(t *testing.T) {
	e := newEnv(t, true)
	dev := e.pin(t, "Test Browser", "browser")
	hostPub := e.host.pub()

	// Files for download / listing.
	_ = os.MkdirAll(filepath.Join(e.home, "Documents"), 0o700)
	download := make([]byte, 200_000)
	_, _ = rand.Read(download)
	if err := os.WriteFile(filepath.Join(e.home, "Documents", "data.bin"), download, 0o600); err != nil {
		t.Fatal(err)
	}
	video, err := mediafile.LoadVideo("../../testdata/test.h264")
	if err != nil {
		t.Fatal(err)
	}
	audio, err := mediafile.LoadOpus("../../testdata/test.ogg")
	if err != nil {
		t.Fatal(err)
	}
	e.cmd(map[string]any{"cmd": "displays", "active": 69733382, "list": []map[string]any{
		{"id": 69733382, "name": "Built-in Retina Display", "width": 3024, "height": 1964, "scale": 2, "primary": true},
		{"id": 2, "name": "Studio Display", "width": 5120, "height": 2880, "scale": 2, "primary": false},
	}})

	c := newTestClient(t)
	sid, cn := randBytes(16), randBytes(32)
	e.msg(map[string]any{"type": "session-request", "sessionId": b64(sid), "devicePub": b64(pubOf(dev)), "clientNonce": b64(cn)})
	acc := e.srv.next(t, "session-accept", 2*time.Second)
	hn := unb64(t, acc["hostNonce"])

	offer, err := c.pc.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	gathered := webrtc.GatheringCompletePromise(c.pc)
	if err := c.pc.SetLocalDescription(offer); err != nil {
		t.Fatal(err)
	}
	<-gathered
	offerSDP := c.pc.LocalDescription().SDP
	if _, err := proto.SDPFingerprint(offerSDP); err != nil {
		t.Fatal(err)
	}
	sig := proto.Sign(dev, proto.LabelOffer, sid, hostPub, pubOf(dev), cn, hn, proto.Hash([]byte(offerSDP)))

	// Route host → server messages: answer + trickled ICE to the client,
	// everything else to `rest`.
	rest := make(chan map[string]any, 256)
	answered := make(chan string, 1)
	var routerWG sync.WaitGroup
	stopRouter := make(chan struct{})
	routerWG.Add(1)
	go func() {
		defer routerWG.Done()
		for {
			select {
			case <-stopRouter:
				return
			case m := <-e.srv.ch:
				switch m["type"] {
				case "answer":
					answered <- m["_raw"].(string)
				case "ice":
					cand, ok := m["candidate"].(map[string]any)
					if !ok {
						continue
					}
					b, _ := json.Marshal(cand)
					var ci webrtc.ICECandidateInit
					_ = json.Unmarshal(b, &ci)
					// The answer is always routed before the host's candidates.
					_ = c.pc.AddICECandidate(ci)
				default:
					rest <- m
				}
			}
		}
	}()
	defer func() { close(stopRouter); routerWG.Wait() }()

	e.msg(map[string]any{"type": "offer", "sessionId": b64(sid), "sdp": offerSDP, "sig": b64(sig)})
	var ans struct {
		SessionID string `json:"sessionId"`
		SDP       string `json:"sdp"`
		Sig       string `json:"sig"`
	}
	select {
	case raw := <-answered:
		_ = json.Unmarshal([]byte(raw), &ans)
	case <-time.After(10 * time.Second):
		t.Fatal("no answer")
	}
	answerSig, _ := proto.UnB64(ans.Sig)
	verifyAnswer := func(sdp string) bool {
		if _, err := proto.SDPFingerprint(sdp); err != nil {
			return false
		}
		return proto.Verify(hostPub, answerSig, proto.LabelAnswer, sid, hostPub, pubOf(dev), cn, hn,
			proto.Hash([]byte(offerSDP)), proto.Hash([]byte(sdp)))
	}
	if ans.SessionID != b64(sid) || !verifyAnswer(ans.SDP) {
		t.Fatal("answer signature does not verify against the pinned host key")
	}
	// A MITM swapping the DTLS fingerprint in the answer is detected by the
	// client-side signature check.
	fp, _ := proto.SDPFingerprint(ans.SDP)
	evilFP := strings.Repeat("AB:", 31) + "AB"
	tampered := strings.ReplaceAll(ans.SDP, fp, evilFP)
	tampered = strings.ReplaceAll(tampered, strings.ToLower(fp), evilFP)
	if tampered == ans.SDP {
		t.Fatal("tamper did not change the SDP")
	}
	if verifyAnswer(tampered) {
		t.Fatal("tampered answer verified")
	}
	// A wrong host key does not verify either.
	otherHost, _, _ := ed25519.GenerateKey(nil)
	if proto.Verify(otherHost, answerSig, proto.LabelAnswer, sid, hostPub, pubOf(dev), cn, hn,
		proto.Hash([]byte(offerSDP)), proto.Hash([]byte(ans.SDP))) {
		t.Fatal("verified with a foreign host key")
	}
	if err := c.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: ans.SDP}); err != nil {
		t.Fatal(err)
	}

	// Connected: ENCODER start, AUDIO_CTL start, STATE.session, events.
	waitFor(t, "ENCODER start", 15*time.Second, func() bool { return len(e.host.encoderCmds("start")) > 0 })
	start := e.host.encoderCmds("start")[0]
	if start.Codec != "h264" || start.Profile != "high" || start.Display != 69733382 || start.Kbps < MinKbps || start.FPS == 0 {
		t.Fatalf("ENCODER start %+v", start)
	}
	waitFor(t, "AUDIO_CTL start", 2*time.Second, func() bool {
		e.host.mu.Lock()
		defer e.host.mu.Unlock()
		return len(e.host.audioCtl) > 0 && e.host.audioCtl[0] == "start"
	})
	e.sync()
	st := e.host.lastState()
	if st.Session == nil || st.Session.Device.Name != "Test Browser" || st.Session.Transport != "direct" {
		t.Fatalf("STATE.session %+v", st.Session)
	}
	if !e.host.hasEvent("session-start") {
		t.Fatal("no session-start event")
	}
	func() {
		deadline := time.After(3 * time.Second)
		for {
			select {
			case m := <-rest:
				if m["type"] == "host-status" && m["state"] == "in-session" && m["sessionDeviceName"] == "Test Browser" {
					return
				}
			case <-deadline:
				t.Fatal("no in-session host-status")
			}
		}
	}()

	// Feed media like the Mac app would.
	feedStop := make(chan struct{})
	var feedWG sync.WaitGroup
	feedWG.Add(1)
	go func() {
		defer feedWG.Done()
		tick := time.NewTicker(33 * time.Millisecond)
		defer tick.Stop()
		var pts uint64
		i, a := 0, 0
		lastKey := 0
		for {
			select {
			case <-feedStop:
				return
			case <-tick.C:
			}
			if k := len(e.host.encoderCmds("keyframe")); k != lastKey {
				lastKey, i = k, 0 // keyframe request: restart at the IDR
			}
			f := video.Frames[i%len(video.Frames)]
			e.a.OnVideo(CodecH264, f.Key, pts, f.Data)
			e.a.OnAudio(pts, audio[a%len(audio)])
			e.a.OnAudio(pts+20000, audio[(a+1)%len(audio)])
			i, a = i+1, a+2
			pts += 33333
		}
	}()
	defer func() { close(feedStop); feedWG.Wait() }()

	waitOpen(t, c.control, c.input, c.pointer, c.file)
	hello := c.nextCtl(t, "hello", 5*time.Second)
	if hello["codec"] != "h264" || hello["hostName"] != "Test Mac" || hello["activeDisplay"] != float64(69733382) {
		t.Fatalf("hello %v", hello)
	}
	if f, _ := hello["features"].(map[string]any); f["audio"] != true || f["files"] != true {
		t.Fatalf("features %v", hello["features"])
	}
	if ds, _ := hello["displays"].([]any); len(ds) != 2 {
		t.Fatalf("displays %v", hello["displays"])
	}

	waitFor(t, "video and audio RTP", 10*time.Second, func() bool {
		return c.videoPkts.Load() > 30 && c.audioPkts.Load() > 20 && c.sawSPS.Load() && c.sawIDR.Load()
	})
	if mime, _ := c.videoMime.Load().(string); !strings.HasPrefix(mime, "video/H264") || !strings.Contains(mime, "64001f") {
		t.Fatalf("negotiated %q", mime)
	}

	// PLI from the client → ENCODER keyframe.
	before := len(e.host.encoderCmds("keyframe"))
	time.Sleep(keyframeInterval) // rate limit window
	if err := c.pc.WriteRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: c.videoSSRC.Load()}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "keyframe on PLI", 5*time.Second, func() bool { return len(e.host.encoderCmds("keyframe")) > before })

	// Input + pointer → INPUT with the display id; malformed input dropped.
	_ = c.input.SendText(`{"t":"k","c":"Key A","d":true}`)
	_ = c.input.SendText(`{"t":"exec","cmd":"x"}`)
	_ = c.input.SendText(`{"t":"k","c":"KeyA","d":true}`)
	_ = c.input.SendText(`{"t":"txt","s":"` + strings.Repeat("x", MaxTextChars+1) + `"}`)
	_ = c.input.SendText(`{"t":"k","c":"KeyA","d":false}`)
	_ = c.pointer.SendText(`{"t":"m","x":0.25,"y":2}`)
	waitFor(t, "INPUT", 5*time.Second, func() bool {
		return e.host.inputContains(`"c":"KeyA","d":false`) && e.host.inputContains(`{"t":"m","x":0.25,"y":1,"display":69733382}`)
	})
	if e.host.inputContains("Key A") || e.host.inputContains("exec") || e.host.inputContains("xxxx") {
		t.Fatal("malformed input forwarded")
	}
	if !e.host.inputContains(`{"t":"k","c":"KeyA","d":true,"display":69733382}`) {
		t.Fatal("key down missing")
	}
	// Display switch changes the id carried by INPUT.
	c.ctl(t, map[string]any{"t": "select-display", "id": 2})
	waitFor(t, "ENCODER display", 3*time.Second, func() bool {
		d := e.host.encoderCmds("display")
		return len(d) > 0 && d[len(d)-1].ID == 2
	})
	_ = c.pointer.SendText(`{"t":"m","x":0.5,"y":0.5}`)
	waitFor(t, "INPUT on display 2", 3*time.Second, func() bool { return e.host.inputContains(`"x":0.5,"y":0.5,"display":2`) })
	c.ctl(t, map[string]any{"t": "select-display", "id": 999}) // unknown display ignored

	// Ping/pong.
	c.ctl(t, map[string]any{"t": "ping", "id": 7, "ts": 12345})
	if p := c.nextCtl(t, "pong", 3*time.Second); p["id"] != float64(7) || p["ts"] != float64(12345) {
		t.Fatalf("pong %v", p)
	}

	// Clipboard both ways.
	c.ctl(t, map[string]any{"t": "clip", "text": "from the client ✓"})
	waitFor(t, "CLIPBOARD_SET", 3*time.Second, func() bool {
		e.host.mu.Lock()
		defer e.host.mu.Unlock()
		return len(e.host.clipboard) == 1 && e.host.clipboard[0] == "from the client ✓"
	})
	e.cmd(map[string]any{"cmd": "clipboard", "text": "from the Mac"})
	if m := c.nextCtl(t, "clip", 3*time.Second); m["text"] != "from the Mac" {
		t.Fatalf("clip %v", m)
	}

	// Upload (client → Mac).
	upData := make([]byte, 100_000)
	_, _ = rand.Read(upData)
	upID := randBytes(16)
	c.ctl(t, map[string]any{"t": "file-start", "id": b64(upID), "name": "../../evil name.txt", "size": len(upData), "dir": "up"})
	if m := c.nextCtl(t, "file-accept", 3*time.Second); m["id"] != b64(upID) {
		t.Fatalf("file-accept %v", m)
	}
	for i := 0; i < len(upData); i += 16 << 10 {
		chunk := append(append([]byte{}, upID...), upData[i:min(i+16<<10, len(upData))]...)
		if err := c.file.Send(chunk); err != nil {
			t.Fatal(err)
		}
	}
	sum := sha256.Sum256(upData)
	c.ctl(t, map[string]any{"t": "file-end", "id": b64(upID), "sha256": b64(sum[:])})
	saved := c.nextCtl(t, "file-saved", 5*time.Second)
	if saved["name"] != "evil name.txt" {
		t.Fatalf("file-saved %v", saved)
	}
	got, err := os.ReadFile(filepath.Join(e.dlDir, "evil name.txt"))
	if err != nil || !bytes.Equal(got, upData) {
		t.Fatalf("uploaded content: %v", err)
	}
	waitFor(t, "file-received event", 2*time.Second, func() bool { return e.host.hasEvent("file-received") })

	// Upload with a wrong checksum is rejected and leaves nothing behind.
	badID := randBytes(16)
	c.ctl(t, map[string]any{"t": "file-start", "id": b64(badID), "name": "bad.bin", "size": 5, "dir": "up"})
	c.nextCtl(t, "file-accept", 3*time.Second)
	_ = c.file.Send(append(append([]byte{}, badID...), []byte("hello")...))
	c.ctl(t, map[string]any{"t": "file-end", "id": b64(badID), "sha256": b64(make([]byte, 32))})
	if m := c.nextCtl(t, "file-error", 5*time.Second); m["id"] != b64(badID) {
		t.Fatalf("file-error %v", m)
	}
	if _, err := os.Stat(filepath.Join(e.dlDir, "bad.bin")); err == nil {
		t.Fatal("bad upload saved")
	}

	// Listing and download (Mac → client).
	c.ctl(t, map[string]any{"t": "ls", "reqId": "r1", "path": ""})
	ls := c.nextCtl(t, "ls-result", 3*time.Second)
	if ents, _ := ls["entries"].([]any); len(ents) != 1 || ents[0].(map[string]any)["name"] != "Documents" {
		t.Fatalf("ls %v", ls)
	}
	c.ctl(t, map[string]any{"t": "get", "reqId": "r2", "path": "Documents/data.bin"})
	fs := c.nextCtl(t, "file-start", 3*time.Second)
	if fs["dir"] != "down" || fs["reqId"] != "r2" || fs["size"] != float64(len(download)) || fs["name"] != "data.bin" {
		t.Fatalf("file-start %v", fs)
	}
	downID := unb64(t, fs["id"])
	end := c.nextCtl(t, "file-end", 10*time.Second)
	var recv []byte
	for len(recv) < len(download) {
		select {
		case chunk := <-c.fileMsgs:
			if !bytes.Equal(chunk[:16], downID) || len(chunk)-16 > 16<<10 {
				t.Fatal("bad chunk")
			}
			recv = append(recv, chunk[16:]...)
		case <-time.After(5 * time.Second):
			t.Fatalf("download incomplete: %d of %d", len(recv), len(download))
		}
	}
	dsum := sha256.Sum256(recv)
	if !bytes.Equal(recv, download) || end["sha256"] != b64(dsum[:]) {
		t.Fatal("download content/hash mismatch")
	}
	// Escaping the home folder is refused.
	c.ctl(t, map[string]any{"t": "get", "reqId": "r3", "path": "../data/pins.json"})
	if m := c.nextCtl(t, "file-error", 3*time.Second); m["reqId"] != "r3" || m["reason"] != "outside-home" {
		t.Fatalf("escape: %v", m)
	}

	// RTT/transport refresh keeps working.
	e.clock.add(3 * time.Second)
	time.Sleep(600 * time.Millisecond)
	e.sync()
	if st := e.host.lastState(); st.Session == nil || st.Session.Transport != "direct" {
		t.Fatalf("session state %+v", st.Session)
	}

	// Client ends the session.
	e.msg(map[string]any{"type": "session-end", "sessionId": b64(sid), "reason": "user"})
	waitFor(t, "ENCODER stop", 3*time.Second, func() bool { return len(e.host.encoderCmds("stop")) == 1 })
	e.sync()
	if e.host.lastState().Session != nil || !e.host.hasEvent("session-end") {
		t.Fatal("session not cleared")
	}
	e.host.mu.Lock()
	ac := append([]string{}, e.host.audioCtl...)
	e.host.mu.Unlock()
	if ac[len(ac)-1] != "stop" {
		t.Fatalf("audio ctl %v", ac)
	}
	// Late media after the session is dropped without panics.
	e.a.OnVideo(CodecH264, true, 1, video.Frames[0].Data)

	// Access log: session start/end, files, verified chain.
	e.cmd(map[string]any{"cmd": "log-read", "limit": 50})
	e.host.mu.Lock()
	lr := e.host.logs[len(e.host.logs)-1]
	e.host.mu.Unlock()
	if !lr.Verified {
		t.Fatalf("log not verified: %s", lr.Error)
	}
	entries, _ := jsonRoundTrip[[]accesslog.Entry](lr.Entries)
	seen := map[string]accesslog.Entry{}
	for _, en := range entries {
		seen[en.Event] = en
	}
	for _, ev := range []string{accesslog.EvSessionStart, accesslog.EvSessionEnd, accesslog.EvFileReceived, accesslog.EvFileSent} {
		if _, ok := seen[ev]; !ok {
			t.Errorf("access log lacks %s", ev)
		}
	}
	if s := seen[accesslog.EvSessionEnd]; s.Device != "Test Browser" || s.DeviceFP != proto.Fingerprint(pubOf(dev)) || s.Transport != "direct" || s.Detail != "client:user" {
		t.Errorf("session-end entry %+v", s)
	}
	if f := seen[accesslog.EvFileReceived]; f.File != "evil name.txt" || f.Size != int64(len(upData)) {
		t.Errorf("file entry %+v", f)
	}
}
