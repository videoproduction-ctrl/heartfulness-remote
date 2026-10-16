// Package proto implements the shared, normative pieces of the HR1 protocol
// (docs/PROTOCOL.md): transcript encoding, labels, SAS, setup key derivation
// and SDP fingerprint checks. It only composes Go standard-library crypto.
package proto

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Signature and derivation labels (PROTOCOL.md §3).
const (
	LabelHostAuth      = "HR1/host-auth"
	LabelClientAuth    = "HR1/client-auth"
	LabelPairChallenge = "HR1/pair-challenge"
	LabelPairApprove   = "HR1/pair-approve"
	LabelCert          = "HR1/cert"
	LabelRevoked       = "HR1/revoked"
	LabelRevokeRequest = "HR1/revoke-request"
	LabelKillRequest   = "HR1/kill-request"
	LabelOffer         = "HR1/offer"
	LabelAnswer        = "HR1/answer"
	LabelPairCommit    = "HR1/pair-commit"
	LabelSAS           = "HR1/sas"
	LabelSetup         = "HR1/setup"
	InfoClaim          = "HR1/claim"
	InfoSetupAuth      = "HR1/setup-auth"
)

// Sizes of random values.
const (
	NonceSize     = 32
	IDSize        = 16
	MaxClockSkew  = 300 * time.Second
	PubKeySize    = ed25519.PublicKeySize
	SignatureSize = ed25519.SignatureSize
)

var b64 = base64.RawURLEncoding

// B64 encodes bytes as base64url without padding.
func B64(b []byte) string { return b64.EncodeToString(b) }

// UnB64 decodes base64url without padding. It rejects padded input.
func UnB64(s string) ([]byte, error) { return b64.DecodeString(s) }

// UnB64Len decodes and checks the decoded length.
func UnB64Len(s string, n int) ([]byte, error) {
	b, err := UnB64(s)
	if err != nil {
		return nil, err
	}
	if len(b) != n {
		return nil, fmt.Errorf("expected %d bytes, got %d", n, len(b))
	}
	return b, nil
}

// TBS builds the transcript: UTF8(label) || 0x00 || Σ(u32be(len(f)) || f).
func TBS(label string, fields ...[]byte) []byte {
	n := len(label) + 1
	for _, f := range fields {
		n += 4 + len(f)
	}
	out := make([]byte, 0, n)
	out = append(out, label...)
	out = append(out, 0)
	var l [4]byte
	for _, f := range fields {
		binary.BigEndian.PutUint32(l[:], uint32(len(f)))
		out = append(out, l[:]...)
		out = append(out, f...)
	}
	return out
}

// Int encodes an integer field as decimal ASCII.
func Int(v int64) []byte { return []byte(strconv.FormatInt(v, 10)) }

// Str encodes a text field as UTF-8.
func Str(s string) []byte { return []byte(s) }

// Hash returns SHA-256(b).
func Hash(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// Verify checks an Ed25519 signature over TBS(label, fields...).
func Verify(pub []byte, sig []byte, label string, fields ...[]byte) bool {
	if len(pub) != PubKeySize || len(sig) != SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), TBS(label, fields...), sig)
}

// Sign signs TBS(label, fields...) with priv (used by tests, the server never signs).
func Sign(priv ed25519.PrivateKey, label string, fields ...[]byte) []byte {
	return ed25519.Sign(priv, TBS(label, fields...))
}

// PairCommit = H(TBS("HR1/pair-commit", devicePub, nd)).
func PairCommit(devicePub, nd []byte) []byte {
	return Hash(TBS(LabelPairCommit, devicePub, nd))
}

// SAS returns the 6-digit short authentication string (no space).
func SAS(hostPub, devicePub, nd, na []byte) string {
	h := Hash(TBS(LabelSAS, hostPub, devicePub, nd, na))
	v := binary.BigEndian.Uint32(h[:4]) % 1_000_000
	return fmt.Sprintf("%06d", v)
}

// FormatSAS renders "123456" as "123 456".
func FormatSAS(s string) string {
	if len(s) != 6 {
		return s
	}
	return s[:3] + " " + s[3:]
}

// SetupKeys derives (Kc, Ka) from the one-time setup secret T.
func SetupKeys(t []byte) (kc, ka []byte, err error) {
	kc, err = hkdf.Key(sha256.New, t, nil, InfoClaim, 32)
	if err != nil {
		return nil, nil, err
	}
	ka, err = hkdf.Key(sha256.New, t, nil, InfoSetupAuth, 32)
	if err != nil {
		return nil, nil, err
	}
	return kc, ka, nil
}

// ClaimCommit = H(Kc).
func ClaimCommit(kc []byte) []byte { return Hash(kc) }

// SetupMAC = HMAC-SHA256(Ka, TBS("HR1/setup", hostPub, devicePub, name, kind)).
func SetupMAC(ka, hostPub, devicePub []byte, name, kind string) []byte {
	m := hmac.New(sha256.New, ka)
	m.Write(TBS(LabelSetup, hostPub, devicePub, Str(name), Str(kind)))
	return m.Sum(nil)
}

// CheckSetupMAC verifies a setup MAC in constant time.
func CheckSetupMAC(ka, hostPub, devicePub []byte, name, kind string, mac []byte) bool {
	return hmac.Equal(SetupMAC(ka, hostPub, devicePub, name, kind), mac)
}

// Fingerprint renders a key fingerprint for humans: base32(H(pub)[0:10]) in groups of 4.
func Fingerprint(pub []byte) string {
	s := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(Hash(pub)[:10]))
	var parts []string
	for i := 0; i < len(s); i += 4 {
		parts = append(parts, s[i:min(i+4, len(s))])
	}
	return strings.Join(parts, "-")
}

// ErrFingerprint is returned when an SDP does not carry exactly one sha-256 fingerprint.
var ErrFingerprint = errors.New("sdp must contain exactly one distinct sha-256 fingerprint")

// SDPFingerprint extracts the single DTLS sha-256 fingerprint of an SDP.
// It rejects SDPs without one, with several distinct ones, or with other hash
// algorithms only (PROTOCOL.md §7.3).
func SDPFingerprint(sdp string) (string, error) {
	var found string
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, "a=fingerprint:") {
			continue
		}
		rest := strings.TrimPrefix(line, "a=fingerprint:")
		alg, val, ok := strings.Cut(rest, " ")
		if !ok || !strings.EqualFold(alg, "sha-256") {
			return "", ErrFingerprint
		}
		val = strings.ToUpper(strings.TrimSpace(val))
		if found != "" && found != val {
			return "", ErrFingerprint
		}
		found = val
	}
	if found == "" {
		return "", ErrFingerprint
	}
	return found, nil
}

// FreshTimestamp reports whether unix seconds ts is within MaxClockSkew of now.
func FreshTimestamp(ts int64, now time.Time) bool {
	d := now.Sub(time.Unix(ts, 0))
	if d < 0 {
		d = -d
	}
	return d <= MaxClockSkew
}

// Multi-Mac (PROTOCOL.md §10).
const (
	LabelMacID       = "HR1/mac-id"
	LabelJoinConfirm = "HR1/join-confirm"
	// JoinSecretSize is the size of T for joining an additional Mac (80 bits).
	JoinSecretSize = 10
)

// MacID returns the 9-digit display ID of a host key (no spaces).
func MacID(hostPub []byte) string {
	h := Hash(TBS(LabelMacID, hostPub))
	return fmt.Sprintf("%09d", binary.BigEndian.Uint32(h[:4])%1_000_000_000)
}

// FormatMacID renders "482913557" as "482 913 557".
func FormatMacID(s string) string {
	if len(s) != 9 {
		return s
	}
	return s[:3] + " " + s[3:6] + " " + s[6:]
}

// HostConfirmMAC = HMAC-SHA256(Ka, TBS("HR1/join-confirm", hostPub, devicePub)).
func HostConfirmMAC(ka, hostPub, devicePub []byte) []byte {
	m := hmac.New(sha256.New, ka)
	m.Write(TBS(LabelJoinConfirm, hostPub, devicePub))
	return m.Sum(nil)
}

// CheckHostConfirmMAC verifies a host confirmation MAC in constant time.
func CheckHostConfirmMAC(ka, hostPub, devicePub, mac []byte) bool {
	return hmac.Equal(HostConfirmMAC(ka, hostPub, devicePub), mac)
}

var joinB32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// JoinCode renders a 10-byte join secret as "K7QP-3MZD-WX2R-9TFA".
func JoinCode(t []byte) string {
	s := joinB32.EncodeToString(t)
	var parts []string
	for i := 0; i < len(s); i += 4 {
		parts = append(parts, s[i:min(i+4, len(s))])
	}
	return strings.Join(parts, "-")
}

// ParseJoinCode normalises a typed join code (case, spaces, dashes, 0→O,
// 1→I, 8→B) and decodes it to the 10-byte join secret.
func ParseJoinCode(code string) ([]byte, error) {
	var b strings.Builder
	for _, r := range strings.ToUpper(code) {
		switch {
		case r == ' ' || r == '-' || r == '\t':
			continue
		case r == '0':
			b.WriteRune('O')
		case r == '1':
			b.WriteRune('I')
		case r == '8':
			b.WriteRune('B')
		default:
			b.WriteRune(r)
		}
	}
	t, err := joinB32.DecodeString(b.String())
	if err != nil {
		return nil, err
	}
	if len(t) != JoinSecretSize {
		return nil, fmt.Errorf("join code must encode %d bytes", JoinSecretSize)
	}
	return t, nil
}
