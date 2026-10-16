// Command hostsim simulates the Mac side of the host (the Swift app) for
// tests and local development on Linux: it holds the host key, feeds video
// (VP8 .ivf or H.264 Annex-B .h264) and Opus audio (.ogg) from files, records
// every INPUT / CLIPBOARD_SET / EVENT (plus ENCODER / AUDIO_CTL) as JSON lines
// and writes the latest STATE to a file. Commands are read from stdin:
//
//	approve <requestId> | deny <requestId> | kill | resume | disconnect
//	clipboard <text> | revoke <devicePub> | new-setup-code | log [n] | quit
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/videoproduction-ctrl/heartfulness-remote/agent/internal/core"
	"github.com/videoproduction-ctrl/heartfulness-remote/agent/internal/mediafile"
	"github.com/videoproduction-ctrl/heartfulness-remote/agent/internal/trust"
	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
)

func main() {
	var (
		server     = flag.String("server", "http://localhost:8080", "server URL (origin)")
		dataDir    = flag.String("data", "", "data directory (pins.json, access-log.jsonl)")
		keyPath    = flag.String("key", "", "host key file (created if missing, 0600); default DATA/host.key")
		name       = flag.String("name", "Simulated Mac", "host name")
		videoPath  = flag.String("video", "", "video file: .ivf (VP8) or .h264 (Annex-B)")
		audioPath  = flag.String("audio", "", "Opus .ogg file (20 ms pages), optional")
		fps        = flag.Int("fps", 30, "video frame rate")
		inputLog   = flag.String("input-log", "", "append INPUT/CLIPBOARD_SET/EVENT/ENCODER/AUDIO_CTL as JSON lines")
		stateFile  = flag.String("state-file", "", "write the latest STATE here (atomically)")
		downloads  = flag.String("downloads", "", "upload destination (default ~/Downloads/Heartfulness Remote)")
		home       = flag.String("home", "", "root for ls/get (default: $HOME)")
		allowBr    = flag.Bool("allow-browser", true, "settings.allowBrowserClients")
		relayOnly  = flag.Bool("relay-only", false, "settings.relayOnly")
		idleMin    = flag.Int("idle-min", 30, "settings.idleTimeoutMin")
		maxKbps    = flag.Int("max-kbps", 40000, "settings.maxKbps")
		insecure   = flag.Bool("allow-insecure", false, "allow http:// for non-loopback servers (LAN dev)")
		loopbackIC = flag.Bool("loopback-ice", false, "include loopback ICE candidates")
	)
	flag.Parse()
	logger := log.New(os.Stderr, "hostsim: ", log.LstdFlags|log.Lmsgprefix)
	if *dataDir == "" {
		logger.Fatal("--data is required")
	}
	absData, err := filepath.Abs(*dataDir)
	if err != nil {
		logger.Fatal(err)
	}
	if err := os.MkdirAll(absData, 0o700); err != nil {
		logger.Fatal(err)
	}
	if *keyPath == "" {
		*keyPath = filepath.Join(absData, "host.key")
	}
	priv, err := loadOrCreateKey(*keyPath)
	if err != nil {
		logger.Fatalf("host key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	var src *mediafile.Video
	var codecs []core.Codec
	if *videoPath != "" {
		src, err = mediafile.LoadVideo(*videoPath)
		if err != nil {
			logger.Fatalf("video: %v", err)
		}
		codecs = []core.Codec{simCodec(src.Codec)}
	} else {
		codecs = []core.Codec{core.CodecVP8, core.CodecH264}
	}
	var audio [][]byte
	if *audioPath != "" {
		if audio, err = mediafile.LoadOpus(*audioPath); err != nil {
			logger.Fatalf("audio: %v", err)
		}
	}

	sim := &simHost{
		priv: priv, logger: logger, video: src, audio: audio, fps: max(*fps, 1),
		stateFile: *stateFile,
	}
	if *inputLog != "" {
		f, err := os.OpenFile(*inputLog, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err != nil {
			logger.Fatalf("input log: %v", err)
		}
		defer f.Close()
		sim.inputLog = f
	}
	cfg := core.Config{
		ServerURL: *server, HostPub: proto.B64(pub), HostName: *name, DataDir: absData,
		StorageKey: proto.B64(storageKey(priv)),
		Settings: core.Settings{AllowBrowserClients: *allowBr, RelayOnly: *relayOnly,
			IdleTimeoutMin: *idleMin, MaxKbps: *maxKbps, Codec: "auto"},
		HEVCAvailable: false, AudioAvailable: len(audio) > 0,
	}
	agent := core.New(sim, core.Options{
		Codecs: codecs, Simulator: true, DownloadsDir: *downloads, HomeDir: *home,
		AllowInsecure: *insecure, IncludeLoopback: *loopbackIC, Logf: logger.Printf,
	})
	sim.agent = agent
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := agent.Start(ctx, cfg); err != nil {
		logger.Fatalf("start: %v", err)
	}
	agent.OnCommand(mustJSON(map[string]any{"cmd": "displays", "active": 1, "list": []map[string]any{
		{"id": 1, "name": "Simulated Display", "width": 1280, "height": 720, "scale": 1, "primary": true},
	}}))
	logger.Printf("host key fingerprint %s (pub %s)", proto.Fingerprint(pub), proto.B64(pub))

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		agent.Stop()
	}()
	go sim.readCommands(os.Stdin)
	<-agent.Done()
	sim.stopVideo()
	sim.stopAudio()
}

func simCodec(name string) core.Codec {
	if name == mediafile.VP8 {
		return core.CodecVP8
	}
	return core.CodecH264
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// loadOrCreateKey reads a b64url Ed25519 seed (32 bytes) or creates one.
func loadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		if err := trust.WriteFileAtomic(path, []byte(proto.B64(seed)+"\n"), 0o600); err != nil {
			return nil, err
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	if err != nil {
		return nil, err
	}
	seed, err := proto.UnB64Len(strings.TrimSpace(string(b)), ed25519.SeedSize)
	if err != nil {
		return nil, fmt.Errorf("%s: expected a b64url 32-byte seed", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// storageKey derives the simulator's HMAC key from the host seed (the Mac
// app keeps a separate random key in the Keychain instead).
func storageKey(priv ed25519.PrivateKey) []byte {
	m := hmac.New(sha256.New, priv.Seed())
	m.Write([]byte("hr-hostsim/storage-key"))
	return m.Sum(nil)
}

// simHost implements core.HostIO.
type simHost struct {
	priv      ed25519.PrivateKey
	logger    *log.Logger
	agent     *core.Agent
	video     *mediafile.Video
	audio     [][]byte
	fps       int
	stateFile string

	logMu    sync.Mutex
	inputLog *os.File

	vmu      sync.Mutex
	vstop    chan struct{}
	vrestart chan struct{}
	amu      sync.Mutex
	astop    chan struct{}
}

// allowedLabels mirrors what the Swift app must enforce before signing.
var allowedLabels = []string{
	proto.LabelHostAuth, proto.LabelPairChallenge, proto.LabelCert, proto.LabelRevoked, proto.LabelAnswer,
}

func (h *simHost) Sign(_ context.Context, data []byte) ([]byte, error) {
	label, _, ok := strings.Cut(string(data), "\x00")
	if !ok {
		return nil, errors.New("not a transcript")
	}
	for _, l := range allowedLabels {
		if l == label {
			return ed25519.Sign(h.priv, data), nil
		}
	}
	return nil, fmt.Errorf("refusing to sign label %q", label)
}

func (h *simHost) record(kind string, v any) {
	if h.inputLog == nil {
		return
	}
	line := mustJSON(map[string]any{"type": kind, "ts": time.Now().UnixMilli(), "data": v})
	h.logMu.Lock()
	defer h.logMu.Unlock()
	_, _ = h.inputLog.Write(append(line, '\n'))
}

func (h *simHost) EmitState(s core.State) {
	if h.stateFile != "" {
		if err := trust.WriteFileAtomic(h.stateFile, append(mustJSON(s), '\n'), 0o600); err != nil {
			h.logger.Printf("state file: %v", err)
		}
	}
	h.logger.Printf("STATE server=%s claimed=%v killed=%v devices=%d pending=%d session=%v",
		s.Server, s.Claimed, s.Killed, len(s.Devices), len(s.Pending), s.Session != nil)
}

func (h *simHost) EmitInput(msg json.RawMessage) { h.record("INPUT", msg) }

func (h *simHost) EmitClipboard(text string) {
	h.record("CLIPBOARD_SET", map[string]string{"text": text})
}

func (h *simHost) EmitEvent(e core.Event) {
	h.record("EVENT", e)
	h.logger.Printf("EVENT %s %s", e.Event, e.Detail)
}

func (h *simHost) EmitLog(l core.LogResult) {
	b := mustJSON(l)
	fmt.Fprintln(os.Stdout, string(b))
}

func (h *simHost) EmitAudioCtl(cmd string) {
	h.record("AUDIO_CTL", map[string]string{"cmd": cmd})
	if cmd == "start" {
		h.startAudio()
	} else {
		h.stopAudio()
	}
}

func (h *simHost) EmitEncoder(c core.EncoderCmd) {
	h.record("ENCODER", c)
	switch c.Cmd {
	case "start":
		h.startVideo()
	case "stop":
		h.stopVideo()
	case "keyframe", "display":
		h.vmu.Lock()
		if h.vrestart != nil {
			select {
			case h.vrestart <- struct{}{}:
			default:
			}
		}
		h.vmu.Unlock()
	}
}

func (h *simHost) startVideo() {
	if h.video == nil {
		return
	}
	h.stopVideo()
	stop, restart := make(chan struct{}), make(chan struct{}, 1)
	h.vmu.Lock()
	h.vstop, h.vrestart = stop, restart
	h.vmu.Unlock()
	go func() {
		interval := time.Second / time.Duration(h.fps)
		t := time.NewTicker(interval)
		defer t.Stop()
		start := time.Now()
		i := 0
		for {
			select {
			case <-stop:
				return
			case <-restart:
				i = 0 // files start with a keyframe
			case <-t.C:
			}
			f := h.video.Frames[i%len(h.video.Frames)]
			pts := uint64(time.Since(start) / time.Microsecond)
			h.agent.OnVideo(simCodec(h.video.Codec), f.Key, pts, f.Data)
			i++
		}
	}()
}

func (h *simHost) stopVideo() {
	h.vmu.Lock()
	defer h.vmu.Unlock()
	if h.vstop != nil {
		close(h.vstop)
		h.vstop, h.vrestart = nil, nil
	}
}

func (h *simHost) startAudio() {
	if len(h.audio) == 0 {
		return
	}
	h.stopAudio()
	stop := make(chan struct{})
	h.amu.Lock()
	h.astop = stop
	h.amu.Unlock()
	go func() {
		t := time.NewTicker(20 * time.Millisecond)
		defer t.Stop()
		var pts uint64
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			case <-t.C:
			}
			h.agent.OnAudio(pts, h.audio[i%len(h.audio)])
			pts += 20000
		}
	}()
}

func (h *simHost) stopAudio() {
	h.amu.Lock()
	defer h.amu.Unlock()
	if h.astop != nil {
		close(h.astop)
		h.astop = nil
	}
}

func (h *simHost) readCommands(f *os.File) {
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 2<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		cmd, arg, _ := strings.Cut(line, " ")
		arg = strings.TrimSpace(arg)
		var c map[string]any
		switch cmd {
		case "approve", "deny":
			c = map[string]any{"cmd": cmd, "requestId": arg}
		case "kill", "resume", "disconnect", "new-setup-code", "quit", "reset-trust-store":
			c = map[string]any{"cmd": cmd}
		case "clipboard":
			c = map[string]any{"cmd": "clipboard", "text": arg}
		case "revoke":
			c = map[string]any{"cmd": "revoke", "devicePub": arg}
		case "log":
			n, _ := strconv.Atoi(arg)
			c = map[string]any{"cmd": "log-read", "limit": n}
		default:
			h.logger.Printf("unknown command %q", cmd)
			continue
		}
		h.agent.OnCommand(mustJSON(c))
		if cmd == "quit" {
			return
		}
	}
	// stdin closed: keep running until a signal (useful under test harnesses
	// that do not attach stdin).
}
