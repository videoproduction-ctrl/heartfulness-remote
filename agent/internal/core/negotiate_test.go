package core

import (
	"crypto/ed25519"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/turn/v5"
	"github.com/pion/webrtc/v4"

	"github.com/videoproduction-ctrl/heartfulness-remote/agent/internal/accesslog"
	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
)

type answerMsgIn struct {
	SessionID string `json:"sessionId"`
	SDP       string `json:"sdp"`
	Sig       string `json:"sig"`
}

type negotiation struct {
	sid, cn, hn []byte
	offerSDP    string
	ans         answerMsgIn
	answerSig   []byte
	rest        chan map[string]any
	setRemote   func()
}

// negotiate runs session-request → accept → signed offer → answer through
// the fake signaling path. Host ICE candidates are queued until setRemote
// is called (after the caller verified the answer), like the web client.
func negotiate(t *testing.T, e *testEnv, c *testClient, dev ed25519.PrivateKey, relayOnly bool) *negotiation {
	t.Helper()
	hostPub := e.host.pub()
	n := &negotiation{sid: randBytes(16), cn: randBytes(32), rest: make(chan map[string]any, 256)}
	req := map[string]any{"type": "session-request", "sessionId": b64(n.sid), "devicePub": b64(pubOf(dev)), "clientNonce": b64(n.cn)}
	if relayOnly {
		req["relayOnly"] = true
	}
	e.msg(req)
	n.hn = unb64(t, e.srv.next(t, "session-accept", 2*time.Second)["hostNonce"])

	offer, err := c.pc.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	gathered := webrtc.GatheringCompletePromise(c.pc)
	if err := c.pc.SetLocalDescription(offer); err != nil {
		t.Fatal(err)
	}
	<-gathered
	n.offerSDP = c.pc.LocalDescription().SDP
	sig := proto.Sign(dev, proto.LabelOffer, n.sid, hostPub, pubOf(dev), n.cn, n.hn, proto.Hash([]byte(n.offerSDP)))

	var mu sync.Mutex
	var queued []webrtc.ICECandidateInit
	remoteSet := false
	answered := make(chan string, 1)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
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
					mu.Lock()
					if remoteSet {
						_ = c.pc.AddICECandidate(ci)
					} else {
						queued = append(queued, ci)
					}
					mu.Unlock()
				default:
					n.rest <- m
				}
			}
		}
	}()
	t.Cleanup(func() { close(stop); wg.Wait() })

	e.msg(map[string]any{"type": "offer", "sessionId": b64(n.sid), "sdp": n.offerSDP, "sig": b64(sig)})
	select {
	case raw := <-answered:
		_ = json.Unmarshal([]byte(raw), &n.ans)
	case <-time.After(10 * time.Second):
		t.Fatal("no answer")
	}
	n.answerSig, _ = proto.UnB64(n.ans.Sig)
	n.setRemote = func() {
		if err := c.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: n.ans.SDP}); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		remoteSet = true
		for _, ci := range queued {
			_ = c.pc.AddICECandidate(ci)
		}
		queued = nil
		mu.Unlock()
	}
	return n
}

// startTURN runs an in-process TURN server on 127.0.0.1 (test only).
func startTURN(t *testing.T) (url, user, pass string) {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no UDP: %v", err)
	}
	user, pass = "tester", "secret-pass"
	key := turn.GenerateAuthKey(user, "hr.test", pass)
	srv, err := turn.NewServer(turn.ServerConfig{
		Realm: "hr.test",
		AuthHandler: func(ra *turn.RequestAttributes) (string, []byte, bool) {
			if ra.Username == user {
				return user, key, true
			}
			return "", nil, false
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn:            pc,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return "turn:" + pc.LocalAddr().String() + "?transport=udp", user, pass
}

func TestWebRTCRelayOnly(t *testing.T) {
	e := newEnv(t, true)
	dev := e.pin(t, "Hotel laptop", "tauri")
	url, user, pass := startTURN(t)
	// TURN credentials arrive from the server (host-ready / turn message).
	e.msg(map[string]any{"type": "turn", "iceServers": []any{
		map[string]any{"urls": "stun:127.0.0.1:9"}, // string form accepted
		map[string]any{"urls": []string{url}, "username": user, "credential": pass},
		map[string]any{"urls": []string{"https://evil.example"}}, // dropped
	}})
	var servers []webrtc.ICEServer
	e.a.call(func() { servers = e.a.iceServers })
	if len(servers) != 2 || servers[1].Username != user {
		t.Fatalf("ice servers %+v", servers)
	}

	c := newTestClient(t, webrtc.Configuration{
		ICEServers:         []webrtc.ICEServer{{URLs: []string{url}, Username: user, Credential: pass}},
		ICETransportPolicy: webrtc.ICETransportPolicyRelay,
	})
	n := negotiate(t, e, c, dev, true)
	if !proto.Verify(e.host.pub(), n.answerSig, proto.LabelAnswer, n.sid, e.host.pub(), pubOf(dev), n.cn, n.hn,
		proto.Hash([]byte(n.offerSDP)), proto.Hash([]byte(n.ans.SDP))) {
		t.Fatal("answer signature")
	}
	n.setRemote()
	waitFor(t, "ENCODER start over TURN", 20*time.Second, func() bool { return len(e.host.encoderCmds("start")) > 0 })
	e.sync()
	st := e.host.lastState()
	if st.Session == nil || st.Session.Transport != "relay" {
		t.Fatalf("transport %+v", st.Session)
	}
	waitOpen(t, c.control, c.input)
	_ = c.input.SendText(`{"t":"k","c":"Enter","d":true}`)
	waitFor(t, "INPUT over TURN", 5*time.Second, func() bool { return e.host.inputContains(`"c":"Enter"`) })

	// Host-side kill ends the session with "killed".
	e.cmd(map[string]any{"cmd": "kill"})
	waitFor(t, "session end", 3*time.Second, func() bool { return len(e.host.encoderCmds("stop")) == 1 })
	if m := c.nextCtl(t, "bye", 3*time.Second); m["reason"] != "killed" {
		t.Fatalf("bye %v", m)
	}
	e.cmd(map[string]any{"cmd": "log-read"})
	e.host.mu.Lock()
	lr := e.host.logs[len(e.host.logs)-1]
	e.host.mu.Unlock()
	entries, _ := jsonRoundTrip[[]accesslog.Entry](lr.Entries)
	found := false
	for _, en := range entries {
		if en.Event == accesslog.EvSessionStart && en.Transport == "relay" && en.Device == "Hotel laptop" {
			found = true
		}
	}
	if !lr.Verified || !found {
		t.Fatalf("log %+v", lr)
	}
}
