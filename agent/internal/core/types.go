// Package core is the host agent: trust decisions, pairing, setup/claim,
// sessions (pion WebRTC), data channels, file transfer, idle timeout, kill
// switch and the access log. The "Mac side" (Swift app, or the simulator) is
// abstracted behind HostIO.
package core

import (
	"context"
	"encoding/json"
)

// Version of the agent (overridable with -ldflags "-X …core.Version=…").
var Version = "0.1.0"

// HostIO is the Mac side. All Emit* methods must be safe for concurrent use
// and must not block for long.
type HostIO interface {
	// Sign asks the Mac to sign data (a TBS transcript) with the host key.
	// The agent verifies every returned signature before using it.
	Sign(ctx context.Context, data []byte) ([]byte, error)
	EmitState(State)
	EmitInput(msg json.RawMessage)
	EmitEncoder(EncoderCmd)
	EmitAudioCtl(cmd string)
	EmitClipboard(text string)
	EmitEvent(Event)
	EmitLog(LogResult)
}

// Settings mirror CONFIG.settings / COMMAND settings.
type Settings struct {
	AllowBrowserClients bool   `json:"allowBrowserClients"`
	RelayOnly           bool   `json:"relayOnly"`
	IdleTimeoutMin      int    `json:"idleTimeoutMin"`
	MaxKbps             int    `json:"maxKbps"`
	Codec               string `json:"codec"` // auto | h264 | h265
}

// Config is the CONFIG frame.
type Config struct {
	ServerURL      string   `json:"serverURL"`
	HostPub        string   `json:"hostPub"`
	HostName       string   `json:"hostName"`
	DataDir        string   `json:"dataDir"`
	StorageKey     string   `json:"storageKey"`
	Settings       Settings `json:"settings"`
	HEVCAvailable  bool     `json:"hevcAvailable"`
	AudioAvailable bool     `json:"audioAvailable"`
}

// Display describes one Mac display (COMMAND displays / control hello).
type Display struct {
	ID      int64   `json:"id"` // CGDirectDisplayID
	Name    string  `json:"name"`
	Width   int     `json:"width"`
	Height  int     `json:"height"`
	Scale   float64 `json:"scale"`
	Primary bool    `json:"primary"`
}

// DeviceInfo identifies a device in STATE and EVENT.
type DeviceInfo struct {
	Pub         string `json:"pub"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// SessionState is STATE.session.
type SessionState struct {
	Device    DeviceInfo `json:"device"`
	Since     int64      `json:"since"`
	Transport string     `json:"transport"`
	RTTMs     int        `json:"rttMs"`
	Codec     string     `json:"codec,omitempty"`
}

// PendingState is one STATE.pending entry (a revealed pairing request).
type PendingState struct {
	RequestID string `json:"requestId"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	SAS       string `json:"sas"`
	ExpiresAt int64  `json:"expiresAt"`
}

// DeviceState is one STATE.devices entry.
type DeviceState struct {
	Pub         string `json:"pub"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	AddedAt     int64  `json:"addedAt"`
	LastUsed    int64  `json:"lastUsed"`
	Fingerprint string `json:"fingerprint"`
}

// State is the STATE frame.
//
// SetupURL is set only while the server is online and unclaimed (§4).
// JoinURL/JoinCode are set only while the server is online, claimed, and this
// Mac is not in the owner's account yet (§10.2). Both appear only once the
// server has received the matching claimCommit, so a code shown always works.
// MacID (9 digits, no spaces) and Joined are always present.
type State struct {
	Server      string         `json:"server"`
	ServerError string         `json:"serverError,omitempty"`
	Claimed     bool           `json:"claimed"`
	Joined      bool           `json:"joined"`
	MacID       string         `json:"macId"`
	SetupURL    string         `json:"setupURL,omitempty"`
	JoinURL     string         `json:"joinURL,omitempty"`
	JoinCode    string         `json:"joinCode,omitempty"`
	Killed      bool           `json:"killed"`
	Session     *SessionState  `json:"session"`
	Pending     []PendingState `json:"pending"`
	Devices     []DeviceState  `json:"devices"`
}

// EncoderCmd is the ENCODER frame.
type EncoderCmd struct {
	Cmd     string `json:"cmd"`               // start | stop | keyframe | bitrate | display
	Codec   string `json:"codec,omitempty"`   // h264 | h265 (vp8 in simulator)
	Profile string `json:"profile,omitempty"` // high | baseline | main
	FPS     int    `json:"fps,omitempty"`
	Kbps    int    `json:"kbps,omitempty"`
	Display int64  `json:"display,omitempty"`
	ID      int64  `json:"id,omitempty"` // for cmd=display
}

// Event is the EVENT frame.
type Event struct {
	Event  string      `json:"event"`
	Device *DeviceInfo `json:"device,omitempty"`
	Detail string      `json:"detail,omitempty"`
}

// LogResult is the LOG frame.
type LogResult struct {
	Entries  any    `json:"entries"`
	Verified bool   `json:"verified"`
	Error    string `json:"error,omitempty"`
}

// Command is a decoded COMMAND frame.
type Command struct {
	Cmd       string          `json:"cmd"`
	RequestID string          `json:"requestId,omitempty"`
	DevicePub string          `json:"devicePub,omitempty"`
	Text      string          `json:"text,omitempty"`
	List      []Display       `json:"list,omitempty"`
	Active    int64           `json:"active,omitempty"`
	Limit     int             `json:"limit,omitempty"`
	Settings  json.RawMessage `json:"settings,omitempty"`
	Raw       json.RawMessage `json:"-"`
}

// Video codec identifiers (VIDEO frame byte).
type Codec byte

// Codec ids.
const (
	CodecH264 Codec = 1
	CodecH265 Codec = 2
	CodecVP8  Codec = 3 // simulator only
)

func (c Codec) String() string {
	switch c {
	case CodecH264:
		return "h264"
	case CodecH265:
		return "h265"
	case CodecVP8:
		return "vp8"
	}
	return "unknown"
}
