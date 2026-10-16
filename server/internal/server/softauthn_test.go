package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// softAuthn is a minimal software WebAuthn platform authenticator for tests:
// ES256 key, "none" attestation, resident credential, user verification.
type softAuthn struct {
	key        *ecdsa.PrivateKey
	credID     []byte
	userHandle []byte
	counter    uint32
}

var b64u = base64.RawURLEncoding

func newSoftAuthn(t *testing.T) *softAuthn {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &softAuthn{key: k, credID: id}
}

type pkOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rpId"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		UserVerification string `json:"userVerification"`
	} `json:"publicKey"`
}

func parseOptions(t *testing.T, raw json.RawMessage) pkOptions {
	t.Helper()
	var o pkOptions
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatalf("options: %v (%s)", err, raw)
	}
	if o.PublicKey.Challenge == "" {
		t.Fatalf("options without challenge: %s", raw)
	}
	return o
}

func clientData(typ, challenge, origin string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": false})
	return b
}

func (a *softAuthn) coseKey() []byte {
	x := a.key.PublicKey.X.FillBytes(make([]byte, 32))
	y := a.key.PublicKey.Y.FillBytes(make([]byte, 32))
	b, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	if err != nil {
		panic(err)
	}
	return b
}

const (
	flagUP = 0x01
	flagUV = 0x04
	flagAT = 0x40
)

// create answers navigator.credentials.create() for the given options.
func (a *softAuthn) create(t *testing.T, options json.RawMessage, origin string) json.RawMessage {
	t.Helper()
	o := parseOptions(t, options)
	uh, err := b64u.DecodeString(o.PublicKey.User.ID)
	if err != nil {
		t.Fatalf("user id: %v", err)
	}
	a.userHandle = uh
	rpHash := sha256.Sum256([]byte(o.PublicKey.RP.ID))
	auth := append([]byte(nil), rpHash[:]...)
	auth = append(auth, flagUP|flagUV|flagAT)
	auth = binary.BigEndian.AppendUint32(auth, a.counter)
	auth = append(auth, make([]byte, 16)...) // AAGUID
	auth = binary.BigEndian.AppendUint16(auth, uint16(len(a.credID)))
	auth = append(auth, a.credID...)
	auth = append(auth, a.coseKey()...)
	att, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": auth})
	if err != nil {
		t.Fatal(err)
	}
	cd := clientData("webauthn.create", o.PublicKey.Challenge, origin)
	out, _ := json.Marshal(map[string]any{
		"id": b64u.EncodeToString(a.credID), "rawId": b64u.EncodeToString(a.credID), "type": "public-key",
		"authenticatorAttachment": "platform",
		"clientExtensionResults":  map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64u.EncodeToString(cd),
			"attestationObject": b64u.EncodeToString(att),
			"transports":        []string{"internal"},
		},
	})
	return out
}

// get answers navigator.credentials.get(). badSig corrupts the signature.
func (a *softAuthn) get(t *testing.T, options json.RawMessage, origin string, badSig bool) json.RawMessage {
	t.Helper()
	o := parseOptions(t, options)
	a.counter++
	rpHash := sha256.Sum256([]byte(o.PublicKey.RPID))
	auth := append([]byte(nil), rpHash[:]...)
	auth = append(auth, flagUP|flagUV)
	auth = binary.BigEndian.AppendUint32(auth, a.counter)
	cd := clientData("webauthn.get", o.PublicKey.Challenge, origin)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte(nil), auth...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if badSig {
		other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		sig, _ = ecdsa.SignASN1(rand.Reader, other, digest[:])
	}
	out, _ := json.Marshal(map[string]any{
		"id": b64u.EncodeToString(a.credID), "rawId": b64u.EncodeToString(a.credID), "type": "public-key",
		"authenticatorAttachment": "platform",
		"clientExtensionResults":  map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64u.EncodeToString(cd),
			"authenticatorData": b64u.EncodeToString(auth),
			"signature":         b64u.EncodeToString(sig),
			"userHandle":        b64u.EncodeToString(a.userHandle),
		},
	})
	return out
}
