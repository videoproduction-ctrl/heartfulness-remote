// Package ipc implements the binary stdin/stdout framing between the Mac app
// (Swift) and hr-agent (PROTOCOL.md §9):
//
//	frame = u32be(len) ‖ u8 type ‖ payload      (len counts type + payload)
//
// Frames larger than MaxFrame are rejected without reading their payload; the
// stream is then unusable and the caller must terminate.
package ipc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

// MaxFrame is the largest allowed value of the length prefix (type + payload).
const MaxFrame = 16 << 20

// Swift → agent frame types.
const (
	TConfig     byte = 0x01
	TSignResult byte = 0x02
	TVideo      byte = 0x03
	TAudio      byte = 0x04
	TCommand    byte = 0x05
)

// Agent → Swift frame types.
const (
	TSignRequest  byte = 0x81
	TState        byte = 0x82
	TInput        byte = 0x83
	TEncoder      byte = 0x84
	TAudioCtl     byte = 0x85
	TClipboardSet byte = 0x86
	TEvent        byte = 0x87
	TLog          byte = 0x88
)

// Video codec ids used in VIDEO frames. 3 (VP8) is accepted only by the
// simulator build path (hostsim); the Mac app never sends it.
const (
	CodecH264 byte = 1
	CodecH265 byte = 2
	CodecVP8  byte = 3
)

// VideoFlagKeyframe is bit 0 of the VIDEO flags byte.
const VideoFlagKeyframe byte = 0x01

var (
	// ErrFrameTooLarge is returned when a length prefix exceeds MaxFrame.
	ErrFrameTooLarge = errors.New("ipc: frame too large")
	// ErrEmptyFrame is returned for a zero length prefix (no type byte).
	ErrEmptyFrame = errors.New("ipc: empty frame")
	// ErrShortPayload is returned when a VIDEO/AUDIO payload is truncated.
	ErrShortPayload = errors.New("ipc: payload too short")
)

// Frame is one decoded IPC frame.
type Frame struct {
	Type    byte
	Payload []byte
}

// ReadFrame reads exactly one frame. Short reads are handled (io.ReadFull);
// a stream that ends in the middle of a frame yields io.ErrUnexpectedEOF and a
// stream that ends between frames yields io.EOF.
func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return Frame{}, ErrEmptyFrame
	}
	if n > MaxFrame {
		return Frame{}, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return Frame{}, err
	}
	return Frame{Type: buf[0], Payload: buf[1:]}, nil
}

// Writer serialises frames onto an io.Writer; safe for concurrent use.
type Writer struct {
	mu sync.Mutex
	w  io.Writer
}

// NewWriter wraps w.
func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

// WriteFrame writes one frame with a single Write call.
func (w *Writer) WriteFrame(typ byte, payload []byte) error {
	if len(payload)+1 > MaxFrame {
		return ErrFrameTooLarge
	}
	buf := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(buf, uint32(len(payload)+1))
	buf[4] = typ
	copy(buf[5:], payload)
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err := w.w.Write(buf)
	return err
}

// Video is a decoded VIDEO payload.
type Video struct {
	Codec    byte
	Keyframe bool
	PTS      uint64 // microseconds
	Data     []byte // Annex-B access unit (or a VP8 frame in simulator mode)
}

// ParseVideo decodes u8 codec ‖ u8 flags ‖ u64be pts_us ‖ data.
func ParseVideo(p []byte) (Video, error) {
	if len(p) < 10 {
		return Video{}, ErrShortPayload
	}
	return Video{
		Codec:    p[0],
		Keyframe: p[1]&VideoFlagKeyframe != 0,
		PTS:      binary.BigEndian.Uint64(p[2:10]),
		Data:     p[10:],
	}, nil
}

// EncodeVideo is the inverse of ParseVideo (tests, simulator, reference for Swift).
func EncodeVideo(v Video) []byte {
	out := make([]byte, 10+len(v.Data))
	out[0] = v.Codec
	if v.Keyframe {
		out[1] = VideoFlagKeyframe
	}
	binary.BigEndian.PutUint64(out[2:10], v.PTS)
	copy(out[10:], v.Data)
	return out
}

// ParseAudio decodes u64be pts_us ‖ opus packet.
func ParseAudio(p []byte) (pts uint64, opus []byte, err error) {
	if len(p) < 8 {
		return 0, nil, ErrShortPayload
	}
	return binary.BigEndian.Uint64(p[:8]), p[8:], nil
}

// EncodeAudio is the inverse of ParseAudio.
func EncodeAudio(pts uint64, opus []byte) []byte {
	out := make([]byte, 8+len(opus))
	binary.BigEndian.PutUint64(out[:8], pts)
	copy(out[8:], opus)
	return out
}
