package core

import (
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v4"
)

// Fixed codec descriptions (PROTOCOL.md §8; agent brief).
const (
	fmtpH264High     = "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=64001f"
	fmtpH264Baseline = "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f"
	fmtpOpus         = "minptime=10;useinbandfec=1;stereo=1;sprop-stereo=1"
)

var errNoCommonCodec = errors.New("no common video codec")

type offeredCodec struct {
	pt     uint8
	name   string // upper-case encoding name
	clock  uint32
	params map[string]string
}

// codecChoice is the negotiated video codec for one session.
type codecChoice struct {
	id      Codec
	cap     webrtc.RTPCodecCapability
	profile string // high | baseline | main | "" (vp8)
}

// parseOfferedVideo lists the video codecs of the first video m-section.
func parseOfferedVideo(offer string) ([]offeredCodec, error) {
	var sd sdp.SessionDescription
	if err := sd.UnmarshalString(offer); err != nil {
		return nil, err
	}
	for _, md := range sd.MediaDescriptions {
		if md.MediaName.Media != "video" {
			continue
		}
		byPT := map[uint8]*offeredCodec{}
		var order []uint8
		for _, a := range md.Attributes {
			switch a.Key {
			case "rtpmap":
				ptS, rest, ok := strings.Cut(a.Value, " ")
				if !ok {
					continue
				}
				pt, err := strconv.ParseUint(ptS, 10, 8)
				if err != nil {
					continue
				}
				parts := strings.Split(rest, "/")
				c := &offeredCodec{pt: uint8(pt), name: strings.ToUpper(parts[0]), params: map[string]string{}}
				if len(parts) > 1 {
					clk, _ := strconv.ParseUint(parts[1], 10, 32)
					c.clock = uint32(clk)
				}
				if old, ok := byPT[c.pt]; ok {
					c.params = old.params
				} else {
					order = append(order, c.pt)
				}
				byPT[c.pt] = c
			case "fmtp":
				ptS, rest, ok := strings.Cut(a.Value, " ")
				if !ok {
					continue
				}
				pt, err := strconv.ParseUint(ptS, 10, 8)
				if err != nil {
					continue
				}
				c, ok := byPT[uint8(pt)]
				if !ok {
					c = &offeredCodec{pt: uint8(pt), params: map[string]string{}}
					byPT[uint8(pt)] = c
					order = append(order, c.pt)
				}
				for _, kv := range strings.Split(rest, ";") {
					k, v, _ := strings.Cut(strings.TrimSpace(kv), "=")
					if k != "" {
						c.params[strings.ToLower(k)] = v
					}
				}
			}
		}
		out := make([]offeredCodec, 0, len(order))
		for _, pt := range order {
			if c := byPT[pt]; c.name != "" {
				out = append(out, *c)
			}
		}
		return out, nil
	}
	return nil, errors.New("offer has no video section")
}

// chooseVideoCodec picks the best codec the host can produce (can, in
// preference order) that the client offered.
func chooseVideoCodec(offer string, can []Codec) (codecChoice, error) {
	offered, err := parseOfferedVideo(offer)
	if err != nil {
		return codecChoice{}, err
	}
	for _, want := range can {
		switch want {
		case CodecH265:
			for _, c := range offered {
				if c.name != "H265" || c.clock != 90000 {
					continue
				}
				if p := c.params["profile-id"]; p != "" && p != "1" {
					continue
				}
				if t := c.params["tier-flag"]; t != "" && t != "0" {
					continue
				}
				if m := c.params["tx-mode"]; m != "" && !strings.EqualFold(m, "SRST") {
					continue
				}
				level := c.params["level-id"]
				if _, err := strconv.Atoi(level); err != nil {
					level = "93"
				}
				return codecChoice{id: CodecH265, profile: "main", cap: webrtc.RTPCodecCapability{
					MimeType: webrtc.MimeTypeH265, ClockRate: 90000,
					SDPFmtpLine: "level-id=" + level + ";profile-id=1;tier-flag=0;tx-mode=SRST",
				}}, nil
			}
		case CodecH264:
			// High first, then constrained baseline / baseline.
			if c, ok := findH264(offered, 0x64); ok {
				return h264Choice(c, "high", fmtpH264High), nil
			}
			if c, ok := findH264(offered, 0x42); ok {
				return h264Choice(c, "baseline", fmtpH264Baseline), nil
			}
		case CodecVP8:
			for _, c := range offered {
				if c.name == "VP8" && c.clock == 90000 {
					return codecChoice{id: CodecVP8, cap: webrtc.RTPCodecCapability{
						MimeType: webrtc.MimeTypeVP8, ClockRate: 90000,
					}}, nil
				}
			}
		}
	}
	return codecChoice{}, errNoCommonCodec
}

// findH264 returns the offered H.264 format with packetization-mode=1 and the
// given profile_idc, preferring the canonical constraint flags (0x00 for
// High, 0xe0 for constrained baseline).
func findH264(offered []offeredCodec, profileIdc byte) (offeredCodec, bool) {
	var best offeredCodec
	found := false
	for _, c := range offered {
		if c.name != "H264" || c.clock != 90000 || c.params["packetization-mode"] != "1" {
			continue
		}
		pli, err := hex.DecodeString(c.params["profile-level-id"])
		if err != nil || len(pli) != 3 || pli[0] != profileIdc {
			continue
		}
		canonical := (profileIdc == 0x64 && pli[1] == 0x00) || (profileIdc == 0x42 && pli[1] == 0xe0)
		if !found || canonical {
			best, found = c, true
			if canonical {
				break
			}
		}
	}
	return best, found
}

func h264Choice(c offeredCodec, profile, canonicalFmtp string) codecChoice {
	fmtp := canonicalFmtp
	// pion matches profile_idc + constraint flags exactly; mirror the
	// client's when they differ from ours (e.g. Safari's 640c1f).
	want := strings.ToLower(c.params["profile-level-id"])
	if !strings.HasSuffix(canonicalFmtp, want) {
		fmtp = "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=" + want
	}
	return codecChoice{id: CodecH264, profile: profile, cap: webrtc.RTPCodecCapability{
		MimeType: webrtc.MimeTypeH264, ClockRate: 90000, SDPFmtpLine: fmtp,
	}}
}
