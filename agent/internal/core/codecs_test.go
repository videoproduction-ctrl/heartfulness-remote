package core

import (
	"strings"
	"testing"
)

func offerWith(lines ...string) string {
	return "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=rtpmap:111 opus/48000/2\r\n" +
		"m=video 9 UDP/TLS/RTP/SAVPF 96 97 98 99 100\r\n" + strings.Join(lines, "\r\n") + "\r\n"
}

func TestChooseVideoCodec(t *testing.T) {
	chrome := offerWith(
		"a=rtpmap:96 VP8/90000",
		"a=rtpmap:97 H264/90000",
		"a=fmtp:97 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=64001f",
		"a=rtpmap:98 H264/90000",
		"a=fmtp:98 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
		"a=rtpmap:99 H264/90000",
		"a=fmtp:99 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=64001f",
		"a=rtpmap:100 H265/90000",
		"a=fmtp:100 level-id=180;profile-id=1;tier-flag=0;tx-mode=SRST",
	)
	c, err := chooseVideoCodec(chrome, []Codec{CodecH265, CodecH264})
	if err != nil || c.id != CodecH265 || !strings.Contains(c.cap.SDPFmtpLine, "level-id=180") {
		t.Fatalf("h265: %+v %v", c, err)
	}
	c, err = chooseVideoCodec(chrome, []Codec{CodecH264})
	if err != nil || c.id != CodecH264 || c.profile != "high" || c.cap.SDPFmtpLine != fmtpH264High {
		t.Fatalf("h264 high: %+v %v", c, err)
	}
	baseOnly := offerWith("a=rtpmap:98 H264/90000", "a=fmtp:98 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f")
	c, err = chooseVideoCodec(baseOnly, []Codec{CodecH265, CodecH264})
	if err != nil || c.profile != "baseline" || c.cap.SDPFmtpLine != fmtpH264Baseline {
		t.Fatalf("baseline: %+v %v", c, err)
	}
	safari := offerWith("a=rtpmap:98 H264/90000", "a=fmtp:98 packetization-mode=1;profile-level-id=640c1f")
	c, err = chooseVideoCodec(safari, []Codec{CodecH264})
	if err != nil || c.profile != "high" || !strings.HasSuffix(c.cap.SDPFmtpLine, "640c1f") {
		t.Fatalf("safari: %+v %v", c, err)
	}
	vp8Only := offerWith("a=rtpmap:96 VP8/90000")
	if _, err := chooseVideoCodec(vp8Only, []Codec{CodecH264}); err != errNoCommonCodec {
		t.Fatalf("vp8 only with h264 host: %v", err)
	}
	if c, err := chooseVideoCodec(vp8Only, []Codec{CodecVP8}); err != nil || c.id != CodecVP8 {
		t.Fatalf("vp8 sim: %v", err)
	}
	mode0 := offerWith("a=rtpmap:97 H264/90000", "a=fmtp:97 packetization-mode=0;profile-level-id=64001f")
	if _, err := chooseVideoCodec(mode0, []Codec{CodecH264}); err != errNoCommonCodec {
		t.Fatal("packetization-mode=0 accepted")
	}
}

func TestCodecsRespectSettings(t *testing.T) {
	a := &Agent{cfg: Config{HEVCAvailable: true}, settings: Settings{Codec: "auto"}}
	if got := a.codecs(); len(got) != 2 || got[0] != CodecH265 {
		t.Fatal(got)
	}
	a.settings.Codec = "h264"
	if got := a.codecs(); len(got) != 1 || got[0] != CodecH264 {
		t.Fatal(got)
	}
	a.cfg.HEVCAvailable = false
	a.settings.Codec = "h265"
	if got := a.codecs(); len(got) != 1 || got[0] != CodecH264 {
		t.Fatal(got)
	}
	// VP8 only in simulator mode.
	a.opts.Codecs = []Codec{CodecVP8, CodecH264}
	if got := a.codecs(); len(got) != 1 || got[0] != CodecH264 {
		t.Fatal(got)
	}
	a.opts.Simulator = true
	if got := a.codecs(); len(got) != 2 {
		t.Fatal(got)
	}
}
