// Package mediafile loads the simulator/test media files (VP8 IVF, H.264
// Annex-B, Opus Ogg) into frames and packets.
package mediafile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pion/webrtc/v4/pkg/media/h264reader"
	"github.com/pion/webrtc/v4/pkg/media/ivfreader"
	"github.com/pion/webrtc/v4/pkg/media/oggreader"
)

// Frame is one encoded video frame / access unit.
type Frame struct {
	Key  bool
	Data []byte
}

// Codec names.
const (
	VP8  = "vp8"
	H264 = "h264"
)

// Video is a decoded video file.
type Video struct {
	Codec  string // VP8 or H264
	Frames []Frame
}

// LoadVideo reads an .ivf (VP8) or .h264 (Annex-B) file.
func LoadVideo(path string) (*Video, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".ivf":
		return loadIVF(b)
	case ".h264", ".264":
		frames, err := SplitH264(b)
		if err != nil {
			return nil, err
		}
		return &Video{Codec: H264, Frames: frames}, nil
	}
	return nil, errors.New("unsupported video file (use .ivf or .h264)")
}

func loadIVF(b []byte) (*Video, error) {
	r, hdr, err := ivfreader.NewWith(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	if string(hdr.FourCC[:]) != "VP80" {
		return nil, fmt.Errorf("IVF codec %q (need VP80)", string(hdr.FourCC[:]))
	}
	src := &Video{Codec: VP8}
	for {
		frame, _, err := r.ParseNextFrame()
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(frame) == 0 {
			continue
		}
		// VP8 frame tag: bit 0 of byte 0 is 0 for key frames.
		src.Frames = append(src.Frames, Frame{Key: frame[0]&0x01 == 0, Data: frame})
	}
	if len(src.Frames) == 0 || !src.Frames[0].Key {
		return nil, errors.New("IVF must start with a key frame")
	}
	return src, nil
}

// SplitH264 groups an Annex-B stream into access units (one per picture),
// each re-emitted with 4-byte start codes. A new access unit starts at a
// slice whose first_mb_in_slice is 0, or at an AUD/SPS/PPS/SEI that follows
// a slice (H.264 §7.4.1.2.3).
func SplitH264(b []byte) ([]Frame, error) {
	r, err := h264reader.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	var out []Frame
	var cur []byte
	key, hasVCL := false, false
	flush := func() {
		if hasVCL {
			out = append(out, Frame{Key: key, Data: cur})
		}
		cur, key, hasVCL = nil, false, false
	}
	for {
		nal, err := r.NextNAL()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch nal.UnitType {
		case h264reader.NalUnitTypeCodedSliceIdr, h264reader.NalUnitTypeCodedSliceNonIdr:
			// first_mb_in_slice is ue(v); its first bit is 1 iff it is 0.
			if hasVCL && len(nal.Data) > 1 && nal.Data[1]&0x80 != 0 {
				flush()
			}
			hasVCL = true
			if nal.UnitType == h264reader.NalUnitTypeCodedSliceIdr {
				key = true
			}
		case h264reader.NalUnitTypeAUD, h264reader.NalUnitTypeSPS, h264reader.NalUnitTypePPS, h264reader.NalUnitTypeSEI:
			if hasVCL {
				flush()
			}
		}
		cur = append(cur, 0, 0, 0, 1)
		cur = append(cur, nal.Data...)
	}
	flush()
	if len(out) == 0 || !out[0].Key {
		return nil, errors.New("H.264 stream must start with an IDR frame")
	}
	return out, nil
}

// LoadOpus returns the Opus packets of an Ogg file written with one packet
// per page (ffmpeg -page_duration 20000).
func LoadOpus(path string) ([][]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r, _, err := oggreader.NewWith(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for {
		page, _, err := r.ParseNextPage()
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if bytes.HasPrefix(page, []byte("OpusTags")) || bytes.HasPrefix(page, []byte("OpusHead")) || len(page) == 0 {
			continue
		}
		out = append(out, page)
	}
	if len(out) == 0 {
		return nil, errors.New("no Opus packets found")
	}
	return out, nil
}
