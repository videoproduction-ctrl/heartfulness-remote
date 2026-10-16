package main

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

	"github.com/videoproduction-ctrl/heartfulness-remote/agent/internal/core"
)

type videoFrame struct {
	key  bool
	data []byte
}

type videoSource struct {
	codec  core.Codec
	frames []videoFrame
}

func loadVideo(path string) (*videoSource, error) {
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
		return &videoSource{codec: core.CodecH264, frames: frames}, nil
	}
	return nil, errors.New("unsupported video file (use .ivf or .h264)")
}

func loadIVF(b []byte) (*videoSource, error) {
	r, hdr, err := ivfreader.NewWith(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	if string(hdr.FourCC[:]) != "VP80" {
		return nil, fmt.Errorf("IVF codec %q (need VP80)", string(hdr.FourCC[:]))
	}
	src := &videoSource{codec: core.CodecVP8}
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
		src.frames = append(src.frames, videoFrame{key: frame[0]&0x01 == 0, data: frame})
	}
	if len(src.frames) == 0 || !src.frames[0].key {
		return nil, errors.New("IVF must start with a key frame")
	}
	return src, nil
}

// SplitH264 groups an Annex-B stream into access units, one per coded slice
// (the test files use one slice per frame), each re-emitted with 4-byte start
// codes. Parameter sets and SEI are attached to the following slice.
func SplitH264(b []byte) ([]videoFrame, error) {
	r, err := h264reader.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	var out []videoFrame
	var cur []byte
	key := false
	for {
		nal, err := r.NextNAL()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		cur = append(cur, 0, 0, 0, 1)
		cur = append(cur, nal.Data...)
		switch nal.UnitType {
		case h264reader.NalUnitTypeCodedSliceIdr:
			key = true
			fallthrough
		case h264reader.NalUnitTypeCodedSliceNonIdr:
			out = append(out, videoFrame{key: key, data: cur})
			cur, key = nil, false
		}
	}
	if len(out) == 0 || !out[0].key {
		return nil, errors.New("H.264 stream must start with an IDR frame")
	}
	return out, nil
}

// loadOpus returns the Opus packets of an Ogg file written with one packet
// per page (ffmpeg -page_duration 20000).
func loadOpus(path string) ([][]byte, error) {
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
