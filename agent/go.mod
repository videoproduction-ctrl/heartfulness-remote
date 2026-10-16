module github.com/videoproduction-ctrl/heartfulness-remote/agent

go 1.26.0

toolchain go1.27.2

require (
	github.com/coder/websocket v1.8.15
	github.com/pion/ice/v4 v4.4.7
	github.com/pion/interceptor v0.1.49
	github.com/pion/rtcp v1.2.19
	github.com/pion/rtp v1.10.5
	github.com/pion/sdp/v3 v3.0.20
	github.com/pion/turn/v5 v5.1.2
	github.com/pion/webrtc/v4 v4.2.23
	github.com/videoproduction-ctrl/heartfulness-remote/proto v0.0.0
)

require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/pion/datachannel v1.6.3 // indirect
	github.com/pion/dtls/v3 v3.1.12 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/mdns/v2 v2.2.2 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/sctp v1.12.0 // indirect
	github.com/pion/srtp/v3 v3.1.3 // indirect
	github.com/pion/stun/v4 v4.0.1 // indirect
	github.com/pion/transport/v5 v5.1.1 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/time v0.16.0 // indirect
)

replace github.com/videoproduction-ctrl/heartfulness-remote/proto => ../proto
