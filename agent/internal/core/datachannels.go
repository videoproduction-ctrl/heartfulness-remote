package core

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"slices"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/pion/webrtc/v4"

	"github.com/videoproduction-ctrl/heartfulness-remote/agent/internal/accesslog"
	"github.com/videoproduction-ctrl/heartfulness-remote/agent/internal/files"
	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
)

// Data-channel limits.
const (
	MaxClipBytes      = 1 << 20
	maxControlMessage = maxDCMessage
	maxUploads        = 4
	maxDownloads      = 2
	fileLowWater      = 256 << 10
	fileHighWater     = 1 << 20
	uploadIdle        = 60 * time.Second
	uploadEndWait     = 30 * time.Second
	maxLsResultBytes  = 200 << 10
)

// Control messages (PROTOCOL.md §8.1).
type ctlIn struct {
	T       string          `json:"t"`
	ID      json.RawMessage `json:"id"`
	Mode    string          `json:"mode"`
	MaxKbps int             `json:"maxKbps"`
	TS      json.RawMessage `json:"ts"`
	Text    *string         `json:"text"`
	ReqID   json.RawMessage `json:"reqId"`
	Path    *string         `json:"path"`
	Name    string          `json:"name"`
	Size    int64           `json:"size"`
	Dir     string          `json:"dir"`
	SHA256  string          `json:"sha256"`
}

type features struct {
	Audio     bool `json:"audio"`
	Clipboard bool `json:"clipboard"`
	Files     bool `json:"files"`
}

type helloMsg struct {
	T             string    `json:"t"`
	HostName      string    `json:"hostName"`
	Version       string    `json:"version"`
	Displays      []Display `json:"displays"`
	ActiveDisplay int64     `json:"activeDisplay"`
	Codec         string    `json:"codec"`
	Features      features  `json:"features"`
}

type pongMsg struct {
	T  string          `json:"t"`
	ID json.RawMessage `json:"id,omitempty"`
	TS json.RawMessage `json:"ts,omitempty"`
}

type clipMsg struct {
	T    string `json:"t"`
	Text string `json:"text"`
}

type noticeMsg struct {
	T     string `json:"t"`
	Level string `json:"level"`
	Text  string `json:"text"`
}

type byeMsg struct {
	T      string `json:"t"`
	Reason string `json:"reason"`
}

type lsResultMsg struct {
	T         string            `json:"t"`
	ReqID     json.RawMessage   `json:"reqId"`
	Path      string            `json:"path"`
	Entries   []files.ListEntry `json:"entries"`
	Truncated bool              `json:"truncated,omitempty"`
	Error     string            `json:"error,omitempty"`
}

type fileMsg struct {
	T      string          `json:"t"`
	ID     string          `json:"id,omitempty"`
	Name   string          `json:"name,omitempty"`
	Size   *int64          `json:"size,omitempty"`
	Dir    string          `json:"dir,omitempty"`
	ReqID  json.RawMessage `json:"reqId,omitempty"`
	SHA256 string          `json:"sha256,omitempty"`
	Reason string          `json:"reason,omitempty"`
}

type upload struct {
	up       *files.Upload
	name     string
	lastData time.Time
	endSHA   string
	endAt    time.Time
}

type download struct {
	cancel func()
}

func (s *Session) onDataChannel(dc *webrtc.DataChannel) {
	if s.closed.Load() {
		_ = dc.Close()
		return
	}
	s.dmu.Lock()
	defer s.dmu.Unlock()
	switch dc.Label() {
	case "control":
		if s.control != nil {
			_ = dc.Close()
			return
		}
		s.control = dc
		dc.OnOpen(s.sendHello)
		dc.OnMessage(s.onControl)
	case "input":
		if s.input != nil {
			_ = dc.Close()
			return
		}
		s.input = dc
		dc.OnMessage(func(m webrtc.DataChannelMessage) { s.onInput(m, false) })
	case "pointer":
		if s.pointer != nil {
			_ = dc.Close()
			return
		}
		s.pointer = dc
		dc.OnMessage(func(m webrtc.DataChannelMessage) { s.onInput(m, true) })
	case "file":
		if s.file != nil {
			_ = dc.Close()
			return
		}
		s.file = dc
		dc.SetBufferedAmountLowThreshold(fileLowWater)
		dc.OnBufferedAmountLow(func() {
			select {
			case s.fileLow <- struct{}{}:
			default:
			}
		})
		dc.OnMessage(s.onFileChunk)
	default:
		_ = dc.Close()
	}
}

func (s *Session) sendCtl(v any) error {
	s.dmu.Lock()
	ctl := s.control
	s.dmu.Unlock()
	if ctl == nil || s.closed.Load() {
		return errors.New("control channel not open")
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return ctl.SendText(string(b))
}

func (s *Session) sendHello() {
	s.dmu.Lock()
	displays := slices.Clone(s.displays)
	s.dmu.Unlock()
	if displays == nil {
		displays = []Display{}
	}
	_ = s.sendCtl(helloMsg{
		T: "hello", HostName: s.a.cfg.HostName, Version: Version,
		Displays: displays, ActiveDisplay: s.activeDisplay.Load(), Codec: s.codec.id.String(),
		Features: features{Audio: s.audioOn, Clipboard: true, Files: true},
	})
}

func (s *Session) setDisplays(list []Display, active int64) {
	s.dmu.Lock()
	s.displays = slices.Clone(list)
	s.dmu.Unlock()
	if !slices.ContainsFunc(list, func(d Display) bool { return d.ID == s.activeDisplay.Load() }) {
		s.activeDisplay.Store(active)
		if s.live.Load() {
			s.a.io.EmitEncoder(EncoderCmd{Cmd: "display", ID: active})
		}
	}
	s.sendHello()
}

func (s *Session) sendClipboard(text string) {
	if len(text) > MaxClipBytes || !utf8.ValidString(text) {
		_ = s.sendCtl(noticeMsg{T: "notice", Level: "warn", Text: "The Mac clipboard is too large to send."})
		return
	}
	if err := s.sendCtl(clipMsg{T: "clip", Text: text}); err != nil {
		_ = s.sendCtl(noticeMsg{T: "notice", Level: "warn", Text: "The Mac clipboard is too large for this device."})
	}
}

func (s *Session) onInput(m webrtc.DataChannelMessage, pointer bool) {
	if !m.IsString || s.closed.Load() || !s.live.Load() {
		return
	}
	now := s.a.now()
	out, release, ok := normalizeInput(m.Data, pointer, s.activeDisplay.Load())
	if !ok {
		return
	}
	b := s.inputBucket
	if pointer {
		b = s.pointerBucket
	}
	if !release && !b.allow(now) {
		return // flood: drop presses/moves, never releases
	}
	s.lastInput.Store(now.UnixNano())
	s.a.io.EmitInput(out)
}

func (s *Session) onControl(m webrtc.DataChannelMessage) {
	if !m.IsString || s.closed.Load() || len(m.Data) > maxControlMessage {
		return
	}
	var c ctlIn
	if err := json.Unmarshal(m.Data, &c); err != nil {
		return
	}
	if len(c.ReqID) > 128 || len(c.ID) > 128 || len(c.TS) > 64 {
		return
	}
	switch c.T {
	case "select-display":
		var id int64
		if json.Unmarshal(c.ID, &id) != nil {
			return
		}
		s.dmu.Lock()
		ok := slices.ContainsFunc(s.displays, func(d Display) bool { return d.ID == id })
		s.dmu.Unlock()
		if ok && s.activeDisplay.Swap(id) != id {
			s.a.io.EmitEncoder(EncoderCmd{Cmd: "display", ID: id})
			s.a.post(func() { s.a.activeDisplay = id })
		}
	case "quality":
		if c.Mode != "auto" && c.Mode != "sharp" && c.Mode != "smooth" {
			return
		}
		s.bmu.Lock()
		s.mode = c.Mode
		if c.MaxKbps > 0 {
			s.clientMax = max(c.MaxKbps, MinKbps)
		} else {
			s.clientMax = 0
		}
		s.bmu.Unlock()
		if s.live.Load() {
			s.updateBitrate()
		}
	case "keyframe":
		s.requestKeyframe()
	case "ping":
		_ = s.sendCtl(pongMsg{T: "pong", ID: c.ID, TS: c.TS})
	case "pong":
	case "clip":
		if c.Text == nil || len(*c.Text) > MaxClipBytes || !utf8.ValidString(*c.Text) {
			return
		}
		s.a.io.EmitClipboard(*c.Text)
	case "ls":
		go s.handleLs(c)
	case "get":
		s.handleGet(c)
	case "file-start":
		s.handleUploadStart(c)
	case "file-end":
		s.handleUploadEnd(c)
	case "file-cancel":
		s.handleCancel(c)
	}
}

func transferID(raw json.RawMessage) ([16]byte, string, bool) {
	var id [16]byte
	var str string
	if json.Unmarshal(raw, &str) != nil {
		return id, "", false
	}
	b, err := proto.UnB64Len(str, 16)
	if err != nil {
		return id, "", false
	}
	copy(id[:], b)
	return id, str, true
}

// userError maps file-system errors to messages safe to show the client.
func userError(err error) string {
	switch {
	case errors.Is(err, files.ErrOutsideRoot):
		return "outside-home"
	case errors.Is(err, files.ErrNotRegular):
		return "not-a-file"
	case errors.Is(err, fs.ErrNotExist):
		return "not-found"
	case errors.Is(err, fs.ErrPermission):
		return "permission-denied"
	case errors.Is(err, files.ErrBadPath):
		return "invalid-path"
	}
	return "error"
}

func (s *Session) handleLs(c ctlIn) {
	path := ""
	if c.Path != nil {
		path = *c.Path
	}
	res := lsResultMsg{T: "ls-result", ReqID: c.ReqID, Path: path, Entries: []files.ListEntry{}}
	entries, truncated, err := files.List(s.a.homeDir, path)
	if err != nil {
		res.Error = userError(err)
	} else {
		res.Entries, res.Truncated = entries, truncated
		for {
			b, _ := json.Marshal(res)
			if len(b) <= maxLsResultBytes || len(res.Entries) == 0 {
				break
			}
			res.Entries = res.Entries[:len(res.Entries)/2]
			res.Truncated = true
		}
	}
	_ = s.sendCtl(res)
}

// ----------------------------------------------------------------- uploads

func (s *Session) handleUploadStart(c ctlIn) {
	id, idStr, ok := transferID(c.ID)
	if !ok || c.Dir != "up" {
		return
	}
	reject := func(reason string) { _ = s.sendCtl(fileMsg{T: "file-reject", ID: idStr, Reason: reason}) }
	if len(c.Name) > 1024 || c.Size < 0 || c.Size > files.MaxUploadSize {
		reject("invalid")
		return
	}
	s.dmu.Lock()
	_, dup := s.uploads[id]
	n := len(s.uploads)
	s.dmu.Unlock()
	if dup {
		reject("duplicate-id")
		return
	}
	if n >= maxUploads {
		reject("busy")
		return
	}
	up, err := files.NewUpload(s.a.dlDir, c.Name, c.Size)
	if err != nil {
		reject(err.Error())
		return
	}
	s.dmu.Lock()
	if s.closed.Load() {
		s.dmu.Unlock()
		up.Abort()
		return
	}
	s.uploads[id] = &upload{up: up, name: c.Name, lastData: s.a.now()}
	s.dmu.Unlock()
	_ = s.sendCtl(fileMsg{T: "file-accept", ID: idStr})
	if c.Size == 0 {
		s.maybeFinish(id)
	}
}

func (s *Session) onFileChunk(m webrtc.DataChannelMessage) {
	if m.IsString || s.closed.Load() || len(m.Data) < 16 {
		return
	}
	var id [16]byte
	copy(id[:], m.Data[:16])
	chunk := m.Data[16:]
	s.dmu.Lock()
	u, ok := s.uploads[id]
	s.dmu.Unlock()
	if !ok {
		return
	}
	idStr := proto.B64(id[:])
	if len(chunk) > files.ChunkSize {
		s.failUpload(id, idStr, "chunk-too-large")
		return
	}
	if err := u.up.Write(chunk); err != nil {
		s.failUpload(id, idStr, "write-failed")
		return
	}
	s.dmu.Lock()
	u.lastData = s.a.now()
	s.dmu.Unlock()
	s.maybeFinish(id)
}

func (s *Session) handleUploadEnd(c ctlIn) {
	id, _, ok := transferID(c.ID)
	if !ok {
		return
	}
	s.dmu.Lock()
	u, ok := s.uploads[id]
	if ok {
		u.endSHA = c.SHA256
		u.endAt = s.a.now()
	}
	s.dmu.Unlock()
	if ok {
		s.maybeFinish(id)
	}
}

// maybeFinish completes an upload once file-end arrived and all bytes are
// in (the control and file channels are independently ordered).
func (s *Session) maybeFinish(id [16]byte) {
	s.dmu.Lock()
	u, ok := s.uploads[id]
	if !ok || u.endSHA == "" || u.up.Received() != u.up.Size() {
		s.dmu.Unlock()
		return
	}
	delete(s.uploads, id)
	s.dmu.Unlock()
	idStr := proto.B64(id[:])
	name, err := u.up.Finish(u.endSHA)
	if err != nil {
		_ = s.sendCtl(fileMsg{T: "file-error", ID: idStr, Reason: err.Error()})
		return
	}
	_ = s.sendCtl(fileMsg{T: "file-saved", ID: idStr, Name: name})
	s.a.appendLog(accesslog.Entry{Event: accesslog.EvFileReceived, Device: s.dev.Name,
		DeviceFP: proto.Fingerprint(s.devPub), File: name, Size: u.up.Size()})
	s.a.io.EmitEvent(Event{Event: "file-received", Device: ptr(s.deviceInfo()), Detail: name})
}

func (s *Session) failUpload(id [16]byte, idStr, reason string) {
	s.dmu.Lock()
	u, ok := s.uploads[id]
	delete(s.uploads, id)
	s.dmu.Unlock()
	if ok {
		u.up.Abort()
		_ = s.sendCtl(fileMsg{T: "file-error", ID: idStr, Reason: reason})
	}
}

func (s *Session) handleCancel(c ctlIn) {
	id, _, ok := transferID(c.ID)
	if !ok {
		return
	}
	s.dmu.Lock()
	u, isUp := s.uploads[id]
	delete(s.uploads, id)
	d, isDown := s.downloads[id]
	delete(s.downloads, id)
	s.dmu.Unlock()
	if isUp {
		u.up.Abort()
	}
	if isDown {
		d.cancel()
	}
}

// checkTransfers expires stalled uploads (loop tick).
func (s *Session) checkTransfers(now time.Time) {
	type exp struct {
		id     [16]byte
		reason string
	}
	var expired []exp
	s.dmu.Lock()
	for id, u := range s.uploads {
		switch {
		case u.endSHA != "" && now.Sub(u.endAt) > uploadEndWait:
			expired = append(expired, exp{id, "incomplete"})
		case now.Sub(u.lastData) > uploadIdle:
			expired = append(expired, exp{id, "timeout"})
		}
	}
	s.dmu.Unlock()
	for _, e := range expired {
		s.failUpload(e.id, proto.B64(e.id[:]), e.reason)
	}
}

// --------------------------------------------------------------- downloads

func (s *Session) handleGet(c ctlIn) {
	if c.Path == nil {
		return
	}
	fail := func(reason string) {
		_ = s.sendCtl(fileMsg{T: "file-error", ReqID: c.ReqID, Reason: reason})
	}
	s.dmu.Lock()
	n := len(s.downloads)
	fileDC := s.file
	s.dmu.Unlock()
	if fileDC == nil {
		fail("no-file-channel")
		return
	}
	if n >= maxDownloads {
		fail("busy")
		return
	}
	f, fi, err := files.OpenForDownload(s.a.homeDir, *c.Path)
	if err != nil {
		fail(userError(err))
		return
	}
	var id [16]byte
	copy(id[:], randBytes(16))
	idStr := proto.B64(id[:])
	stop := make(chan struct{})
	var once sync.Once
	cancel := func() { once.Do(func() { close(stop) }) }
	s.dmu.Lock()
	if s.closed.Load() {
		s.dmu.Unlock()
		_ = f.Close()
		return
	}
	s.downloads[id] = &download{cancel: cancel}
	s.dmu.Unlock()
	size := fi.Size()
	name := filepath.Base(fi.Name())
	if err := s.sendCtl(fileMsg{T: "file-start", ID: idStr, Name: name, Size: &size, Dir: "down", ReqID: c.ReqID}); err != nil {
		_ = f.Close()
		return
	}
	go s.sendFile(fileDC, f, id, idStr, name, size, stop)
}

func (s *Session) sendFile(dc *webrtc.DataChannel, f io.ReadCloser, id [16]byte, idStr, name string, size int64, stop chan struct{}) {
	defer f.Close()
	defer func() {
		s.dmu.Lock()
		delete(s.downloads, id)
		s.dmu.Unlock()
	}()
	h := sha256.New()
	buf := make([]byte, 16+files.ChunkSize)
	copy(buf, id[:])
	var total int64
	for {
		for dc.BufferedAmount() > fileHighWater {
			select {
			case <-stop:
				return
			case <-s.fileLow:
			case <-time.After(time.Second):
			}
			if s.closed.Load() {
				return
			}
		}
		select {
		case <-stop:
			return
		default:
		}
		n, err := f.Read(buf[16:])
		if n > 0 {
			total += int64(n)
			if total > size {
				_ = s.sendCtl(fileMsg{T: "file-error", ID: idStr, Reason: "file-changed"})
				return
			}
			h.Write(buf[16 : 16+n])
			if err := dc.Send(buf[:16+n]); err != nil {
				return
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			_ = s.sendCtl(fileMsg{T: "file-error", ID: idStr, Reason: "read-failed"})
			return
		}
	}
	if total != size {
		_ = s.sendCtl(fileMsg{T: "file-error", ID: idStr, Reason: "file-changed"})
		return
	}
	_ = s.sendCtl(fileMsg{T: "file-end", ID: idStr, SHA256: proto.B64(h.Sum(nil))})
	s.a.appendLog(accesslog.Entry{Event: accesslog.EvFileSent, Device: s.dev.Name,
		DeviceFP: proto.Fingerprint(s.devPub), File: name, Size: size})
}
