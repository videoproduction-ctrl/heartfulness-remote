package mediafile

import (
	"bytes"
	"testing"
)

func TestLoadTestMedia(t *testing.T) {
	for _, tc := range []struct {
		path  string
		codec string
	}{{"../../testdata/test.h264", H264}, {"../../testdata/test.ivf", VP8}} {
		v, err := LoadVideo(tc.path)
		if err != nil {
			t.Fatalf("%s: %v", tc.path, err)
		}
		if v.Codec != tc.codec || len(v.Frames) != 120 {
			t.Fatalf("%s: codec %s, %d frames", tc.path, v.Codec, len(v.Frames))
		}
		keys := 0
		for i, f := range v.Frames {
			if f.Key {
				keys++
				if i%30 != 0 {
					t.Errorf("%s: keyframe at %d", tc.path, i)
				}
			}
		}
		if keys != 4 {
			t.Errorf("%s: %d keyframes (want one per second)", tc.path, keys)
		}
		if tc.codec == H264 {
			// Access units are Annex-B with SPS/PPS before every IDR.
			f := v.Frames[0].Data
			if !bytes.HasPrefix(f, []byte{0, 0, 0, 1}) || f[4]&0x1f != 7 {
				t.Errorf("first AU does not start with an SPS: % x", f[:8])
			}
		}
	}
	pk, err := LoadOpus("../../testdata/test.ogg")
	if err != nil || len(pk) < 150 {
		t.Fatalf("opus: %d packets, %v", len(pk), err)
	}
	if _, err := LoadVideo("../../testdata/test.ogg"); err == nil {
		t.Fatal("ogg accepted as video")
	}
}

func TestSplitH264RejectsNonIDRStart(t *testing.T) {
	// A lone non-IDR slice.
	if _, err := SplitH264([]byte{0, 0, 0, 1, 0x41, 0x9a, 0x00}); err == nil {
		t.Fatal("stream without IDR accepted")
	}
}
