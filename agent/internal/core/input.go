package core

import (
	"encoding/json"
	"math"
	"regexp"
	"sync"
	"time"
	"unicode/utf8"
)

// Input limits (PROTOCOL.md §8.2).
const (
	MaxInputMessage = 20 << 10 // a txt message of 4096 chars fits comfortably
	MaxTextChars    = 4096
	MaxWheel        = 10000.0
)

var keyCodeRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,31}$`)

type rawInput struct {
	T  string   `json:"t"`
	X  *float64 `json:"x"`
	Y  *float64 `json:"y"`
	B  *int     `json:"b"`
	D  *bool    `json:"d"`
	DX *float64 `json:"dx"`
	DY *float64 `json:"dy"`
	C  string   `json:"c"`
	S  *string  `json:"s"`
}

// Normalised INPUT payloads (only validated fields are forwarded to Swift).
type inMove struct {
	T       string  `json:"t"`
	X       float64 `json:"x"`
	Y       float64 `json:"y"`
	Display int64   `json:"display"`
}

type inButton struct {
	T       string  `json:"t"`
	B       int     `json:"b"`
	D       bool    `json:"d"`
	X       float64 `json:"x"`
	Y       float64 `json:"y"`
	Display int64   `json:"display"`
}

type inWheel struct {
	T       string  `json:"t"`
	DX      float64 `json:"dx"`
	DY      float64 `json:"dy"`
	X       float64 `json:"x"`
	Y       float64 `json:"y"`
	Display int64   `json:"display"`
}

type inKey struct {
	T       string `json:"t"`
	C       string `json:"c"`
	D       bool   `json:"d"`
	Display int64  `json:"display"`
}

type inText struct {
	T       string `json:"t"`
	S       string `json:"s"`
	Display int64  `json:"display"`
}

type inReset struct {
	T       string `json:"t"`
	Display int64  `json:"display"`
}

func clamp01(p *float64) (float64, bool) {
	if p == nil || math.IsNaN(*p) || math.IsInf(*p, 0) {
		return 0, false
	}
	return math.Min(1, math.Max(0, *p)), true
}

func clampWheel(p *float64) (float64, bool) {
	if p == nil {
		return 0, true
	}
	if math.IsNaN(*p) || math.IsInf(*p, 0) {
		return 0, false
	}
	return math.Min(MaxWheel, math.Max(-MaxWheel, *p)), true
}

// normalizeInput validates one input/pointer message. pointerChannel
// restricts the channel to "m" messages (and "m" to it). It returns the
// normalised INPUT JSON, whether the message releases something (never
// dropped by flood control), and ok=false for malformed input.
func normalizeInput(data []byte, pointerChannel bool, display int64) (out []byte, release bool, ok bool) {
	if len(data) == 0 || len(data) > MaxInputMessage {
		return nil, false, false
	}
	var m rawInput
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, false, false
	}
	if pointerChannel != (m.T == "m") {
		return nil, false, false
	}
	var v any
	switch m.T {
	case "m":
		x, ok1 := clamp01(m.X)
		y, ok2 := clamp01(m.Y)
		if !ok1 || !ok2 {
			return nil, false, false
		}
		v = inMove{T: "m", X: x, Y: y, Display: display}
	case "b":
		x, ok1 := clamp01(m.X)
		y, ok2 := clamp01(m.Y)
		if !ok1 || !ok2 || m.B == nil || *m.B < 0 || *m.B > 4 || m.D == nil {
			return nil, false, false
		}
		v = inButton{T: "b", B: *m.B, D: *m.D, X: x, Y: y, Display: display}
		release = !*m.D
	case "w":
		x, ok1 := clamp01(m.X)
		y, ok2 := clamp01(m.Y)
		dx, ok3 := clampWheel(m.DX)
		dy, ok4 := clampWheel(m.DY)
		if !ok1 || !ok2 || !ok3 || !ok4 {
			return nil, false, false
		}
		v = inWheel{T: "w", DX: dx, DY: dy, X: x, Y: y, Display: display}
	case "k":
		if !keyCodeRe.MatchString(m.C) || m.D == nil {
			return nil, false, false
		}
		v = inKey{T: "k", C: m.C, D: *m.D, Display: display}
		release = !*m.D
	case "txt":
		if m.S == nil || *m.S == "" || !utf8.ValidString(*m.S) || utf8.RuneCountInString(*m.S) > MaxTextChars {
			return nil, false, false
		}
		v = inText{T: "txt", S: *m.S, Display: display}
	case "reset":
		v = inReset{T: "reset", Display: display}
		release = true
	default:
		return nil, false, false
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, false, false
	}
	return b, release, true
}

// tokenBucket is a simple rate limiter for input floods.
type tokenBucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newTokenBucket(rate, burst float64) *tokenBucket {
	return &tokenBucket{rate: rate, burst: burst, tokens: burst}
}

func (b *tokenBucket) allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.last.IsZero() {
		b.tokens = math.Min(b.burst, b.tokens+now.Sub(b.last).Seconds()*b.rate)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
