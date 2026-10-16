package core

import (
	"bytes"
	"encoding/json"
	"strconv"

	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
)

// flexInt decodes a JSON number or a decimal string (timestamps).
type flexInt int64

func (f *flexInt) UnmarshalJSON(b []byte) error {
	b = bytes.Trim(b, `"`)
	if len(b) == 0 || string(b) == "null" {
		*f = 0
		return nil
	}
	v, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil {
		return err
	}
	*f = flexInt(v)
	return nil
}

// inMsg is the union of all server → host messages we consume.
type inMsg struct {
	Type        string          `json:"type"`
	RequestID   string          `json:"requestId"`
	DevicePub   string          `json:"devicePub"`
	Name        string          `json:"name"`
	Kind        string          `json:"kind"`
	Commit      string          `json:"commit"`
	ND          string          `json:"nd"`
	ApproverPub string          `json:"approverPub"`
	Sig         string          `json:"sig"`
	SetupMac    string          `json:"setupMac"`
	TargetPub   string          `json:"targetPub"`
	TS          flexInt         `json:"ts"`
	Action      string          `json:"action"`
	SessionID   string          `json:"sessionId"`
	ClientNonce string          `json:"clientNonce"`
	RelayOnly   bool            `json:"relayOnly"`
	SDP         string          `json:"sdp"`
	Candidate   json.RawMessage `json:"candidate"`
	Reason      string          `json:"reason"`
	IceServers  json.RawMessage `json:"iceServers"`
	Claimed     bool            `json:"claimed"`
	// Joined is nil for servers older than HR1.1 (one Mac per server: a
	// claimed server then always means "this Mac is the owner's").
	Joined *bool  `json:"joined"`
	MacID  string `json:"macId"`
	// HostPub is carried by messages the server routes to a Mac (§10.3);
	// when present it must be this Mac's key.
	HostPub string `json:"hostPub"`
	Origin  string `json:"origin"`
	Code    string `json:"code"`
}

type hostAuthMsg struct {
	Type        string `json:"type"`
	HostPub     string `json:"hostPub"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Sig         string `json:"sig"`
	ClaimCommit string `json:"claimCommit,omitempty"`
}

type trustSyncMsg struct {
	Type        string             `json:"type"`
	Certs       []proto.Cert       `json:"certs"`
	Revocations []proto.Revocation `json:"revocations"`
}

type hostStatusMsg struct {
	Type              string `json:"type"`
	State             string `json:"state"`
	SessionDeviceName string `json:"sessionDeviceName,omitempty"`
}

type pairChallengeMsg struct {
	Type      string `json:"type"`
	RequestID string `json:"requestId"`
	HostPub   string `json:"hostPub"`
	NA        string `json:"na"`
	Sig       string `json:"sig"`
}

type pairResultMsg struct {
	Type      string      `json:"type"`
	RequestID string      `json:"requestId"`
	Approved  bool        `json:"approved"`
	Cert      *proto.Cert `json:"cert,omitempty"`
	Reason    string      `json:"reason,omitempty"`
}

// deviceApprovedMsg answers setup-device (§4 claim and §10.2 join). HostMac =
// HMAC(Ka, TBS("HR1/join-confirm", hostPub, devicePub)) proves to the device
// that this key belongs to the Mac that showed the code.
type deviceApprovedMsg struct {
	Type    string     `json:"type"`
	Cert    proto.Cert `json:"cert"`
	HostMac string     `json:"hostMac"`
}

type deviceRevokedMsg struct {
	Type       string           `json:"type"`
	Revocation proto.Revocation `json:"revocation"`
}

type sessionAcceptMsg struct {
	Type      string `json:"type"`
	SessionID string `json:"sessionId"`
	HostNonce string `json:"hostNonce"`
}

type sessionRejectMsg struct {
	Type      string `json:"type"`
	SessionID string `json:"sessionId"`
	Reason    string `json:"reason"`
}

type answerMsg struct {
	Type      string `json:"type"`
	SessionID string `json:"sessionId"`
	SDP       string `json:"sdp"`
	Sig       string `json:"sig"`
}

type iceMsg struct {
	Type      string `json:"type"`
	SessionID string `json:"sessionId"`
	Candidate any    `json:"candidate"` // RTCIceCandidateInit or null
}

type sessionEndMsg struct {
	Type      string `json:"type"`
	SessionID string `json:"sessionId"`
	Reason    string `json:"reason"`
}
