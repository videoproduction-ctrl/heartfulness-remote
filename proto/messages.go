package proto

import (
	"crypto/ed25519"
	"errors"
)

// Cert is a host-signed statement that a device key is trusted (PROTOCOL.md §7.1).
type Cert struct {
	HostPub   string `json:"hostPub"`
	DevicePub string `json:"devicePub"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	IssuedAt  int64  `json:"issuedAt"`
	Sig       string `json:"sig"`
}

// Revocation is a host-signed statement that a device key is no longer trusted.
type Revocation struct {
	HostPub   string `json:"hostPub"`
	DevicePub string `json:"devicePub"`
	RevokedAt int64  `json:"revokedAt"`
	Sig       string `json:"sig"`
}

var errBadSig = errors.New("bad signature")

func (c Cert) fields() ([][]byte, error) {
	hp, err := UnB64Len(c.HostPub, PubKeySize)
	if err != nil {
		return nil, err
	}
	dp, err := UnB64Len(c.DevicePub, PubKeySize)
	if err != nil {
		return nil, err
	}
	return [][]byte{hp, dp, Str(c.Name), Str(c.Kind), Int(c.IssuedAt)}, nil
}

// Verify checks the cert against the expected host key.
func (c Cert) Verify(hostPub []byte) error {
	f, err := c.fields()
	if err != nil {
		return err
	}
	if string(f[0]) != string(hostPub) {
		return errors.New("cert issued by a different host")
	}
	sig, err := UnB64Len(c.Sig, SignatureSize)
	if err != nil {
		return err
	}
	if !Verify(hostPub, sig, LabelCert, f...) {
		return errBadSig
	}
	return nil
}

// SignCert fills c.Sig using priv (tests and simulators only).
func SignCert(priv ed25519.PrivateKey, c Cert) Cert {
	f, err := c.fields()
	if err != nil {
		panic(err)
	}
	c.Sig = B64(Sign(priv, LabelCert, f...))
	return c
}

// Verify checks the revocation against the expected host key.
func (r Revocation) Verify(hostPub []byte) error {
	hp, err := UnB64Len(r.HostPub, PubKeySize)
	if err != nil {
		return err
	}
	if string(hp) != string(hostPub) {
		return errors.New("revocation issued by a different host")
	}
	dp, err := UnB64Len(r.DevicePub, PubKeySize)
	if err != nil {
		return err
	}
	sig, err := UnB64Len(r.Sig, SignatureSize)
	if err != nil {
		return err
	}
	if !Verify(hostPub, sig, LabelRevoked, hp, dp, Int(r.RevokedAt)) {
		return errBadSig
	}
	return nil
}

// Message is the generic signaling envelope. Routed messages are decoded into
// map form by the server and forwarded with server-filled fields overwritten.
type Message map[string]any

// Type returns the message type or "".
func (m Message) Type() string {
	s, _ := m["type"].(string)
	return s
}

// String returns a string field or "".
func (m Message) String(k string) string {
	s, _ := m[k].(string)
	return s
}
