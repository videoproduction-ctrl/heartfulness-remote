module github.com/videoproduction-ctrl/heartfulness-remote/server

go 1.26.0

toolchain go1.27.2

require (
	github.com/coder/websocket v1.8.15
	github.com/fxamacker/cbor/v2 v2.9.0
	github.com/go-webauthn/webauthn v0.15.0
	github.com/videoproduction-ctrl/heartfulness-remote/proto v0.0.0
	golang.org/x/time v0.14.0
)

require (
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/go-webauthn/x v0.1.26 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.0 // indirect
	github.com/google/go-tpm v0.9.6 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.43.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
)

replace github.com/videoproduction-ctrl/heartfulness-remote/proto => ../proto
