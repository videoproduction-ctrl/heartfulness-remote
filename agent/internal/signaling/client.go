// Package signaling is the host's outbound WebSocket client for /ws/host
// (PROTOCOL.md §7.1). It never listens; it dials out, authenticates with a
// host signature supplied by the Handler, reconnects with exponential backoff
// (1 s → 60 s, jittered) and pings the server every 20 s.
package signaling

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
)

// Limits and timings.
const (
	MaxMessage     = 256 << 10
	PingInterval   = 20 * time.Second
	PingTimeout    = 15 * time.Second
	WriteTimeout   = 10 * time.Second
	HandshakeLimit = 15 * time.Second
	MinBackoff     = 1 * time.Second
	MaxBackoff     = 60 * time.Second
)

// Status values reported to the handler.
const (
	StatusOffline    = "offline"
	StatusConnecting = "connecting"
	StatusOnline     = "online"
	StatusError      = "error"
)

// Handler is implemented by the agent core.
type Handler interface {
	// HostAuth builds the signed host-auth message for the server nonce.
	HostAuth(ctx context.Context, origin string, nonce []byte) (any, error)
	// OnReady is called with the raw host-ready message.
	OnReady(s Sender, raw []byte)
	// OnMessage is called for every other server message (serially).
	OnMessage(typ string, raw []byte)
	// OnStatus reports connection state changes; code is set for "error".
	OnStatus(status, code string)
}

// Sender sends one JSON message to the server.
type Sender interface {
	Send(msg any) error
}

// Endpoints derives the origin (signed in host-auth) and the WebSocket URL
// from the configured server URL. Plain http/ws is accepted only for loopback
// hosts unless allowInsecure is set (development on a LAN).
func Endpoints(serverURL string, allowInsecure bool) (origin, wsURL string, err error) {
	u, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil || u.Host == "" {
		return "", "", fmt.Errorf("invalid server URL")
	}
	if u.User != nil {
		return "", "", fmt.Errorf("server URL must not contain credentials")
	}
	host := strings.ToLower(u.Host)
	var scheme, wsScheme string
	switch strings.ToLower(u.Scheme) {
	case "https", "wss":
		scheme, wsScheme = "https", "wss"
		host = strings.TrimSuffix(host, ":443")
	case "http", "ws":
		scheme, wsScheme = "http", "ws"
		host = strings.TrimSuffix(host, ":80")
		if !allowInsecure && !isLoopback(u.Hostname()) {
			return "", "", fmt.Errorf("refusing unencrypted server URL for a non-loopback host")
		}
	default:
		return "", "", fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}
	origin = scheme + "://" + host
	return origin, wsScheme + "://" + host + "/ws/host", nil
}

func isLoopback(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// Client maintains the connection.
type Client struct {
	Origin  string
	WSURL   string
	Handler Handler
	Version string
	Logf    func(format string, a ...any)

	// Overridable for tests.
	MinBackoff time.Duration
	MaxBackoff time.Duration

	mu        sync.Mutex
	conn      *websocket.Conn
	reconnect chan struct{}
	attempt   int
}

// New creates a client.
func New(origin, wsURL string, h Handler, version string) *Client {
	return &Client{
		Origin: origin, WSURL: wsURL, Handler: h, Version: version,
		MinBackoff: MinBackoff, MaxBackoff: MaxBackoff,
		reconnect: make(chan struct{}, 1),
		Logf:      func(string, ...any) {},
	}
}

// Send writes a JSON message on the current connection.
func (c *Client) Send(msg any) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if len(b) > MaxMessage {
		return errors.New("signaling message too large")
	}
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return errors.New("not connected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), WriteTimeout)
	defer cancel()
	return conn.Write(ctx, websocket.MessageText, b)
}

// Reconnect drops the current connection (if any) and reconnects at once.
func (c *Client) Reconnect() {
	c.mu.Lock()
	c.attempt = 0
	conn := c.conn
	c.mu.Unlock()
	select {
	case c.reconnect <- struct{}{}:
	default:
	}
	if conn != nil {
		_ = conn.Close(websocket.StatusNormalClosure, "reconnect")
	}
}

// Run connects and reconnects until ctx is cancelled.
func (c *Client) Run(ctx context.Context) {
	for ctx.Err() == nil {
		c.Handler.OnStatus(StatusConnecting, "")
		code, err := c.session(ctx)
		if ctx.Err() != nil {
			break
		}
		if code != "" {
			c.Handler.OnStatus(StatusError, code)
		} else {
			c.Handler.OnStatus(StatusOffline, "")
		}
		if err != nil {
			c.Logf("signaling: %v", err)
		}
		c.mu.Lock()
		d := c.backoff(c.attempt)
		c.attempt++
		c.mu.Unlock()
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
		case <-c.reconnect:
			t.Stop()
		case <-t.C:
		}
	}
	c.Handler.OnStatus(StatusOffline, "")
}

// backoff returns a jittered exponential delay: base·2^n capped, then a
// uniformly random value in [d/2, d].
func (c *Client) backoff(n int) time.Duration {
	d := c.MinBackoff
	for i := 0; i < n && d < c.MaxBackoff; i++ {
		d *= 2
	}
	d = min(d, c.MaxBackoff)
	half := d / 2
	return half + time.Duration(rand.Int64N(int64(half)+1))
}

func (c *Client) httpClient() *http.Client {
	tr := &http.Transport{
		// Honours HTTPS_PROXY/HTTP_PROXY/NO_PROXY only when they are set
		// (never for loopback).
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: HandshakeLimit,
		ForceAttemptHTTP2:   false,
	}
	return &http.Client{Transport: tr}
}

type challengeMsg struct {
	Type  string `json:"type"`
	Nonce string `json:"nonce"`
	Code  string `json:"code"`
}

// session runs one connection; it returns a server error code if the server
// sent {type:"error", code}.
func (c *Client) session(ctx context.Context) (string, error) {
	dctx, cancel := context.WithTimeout(ctx, HandshakeLimit)
	defer cancel()
	conn, _, err := websocket.Dial(dctx, c.WSURL, &websocket.DialOptions{
		HTTPClient: c.httpClient(),
		HTTPHeader: http.Header{"User-Agent": []string{"hr-agent/" + c.Version}},
	})
	if err != nil {
		return "", fmt.Errorf("dial: %w", err)
	}
	defer conn.CloseNow()
	conn.SetReadLimit(MaxMessage)

	// 1. challenge
	_, raw, err := conn.Read(dctx)
	if err != nil {
		return "", fmt.Errorf("read challenge: %w", err)
	}
	var ch challengeMsg
	if err := json.Unmarshal(raw, &ch); err != nil {
		return "", errors.New("bad challenge")
	}
	if ch.Type == "error" {
		return codeOr(ch.Code), nil
	}
	if ch.Type != "challenge" {
		return "", fmt.Errorf("expected challenge, got %q", ch.Type)
	}
	nonce, err := proto.UnB64Len(ch.Nonce, proto.NonceSize)
	if err != nil {
		return "", errors.New("bad challenge nonce")
	}
	// 2. host-auth
	auth, err := c.Handler.HostAuth(dctx, c.Origin, nonce)
	if err != nil {
		return "", fmt.Errorf("host-auth: %w", err)
	}
	b, _ := json.Marshal(auth)
	if err := conn.Write(dctx, websocket.MessageText, b); err != nil {
		return "", err
	}
	// 3. host-ready or error
	_, raw, err = conn.Read(dctx)
	if err != nil {
		return "", fmt.Errorf("read host-ready: %w", err)
	}
	var rd challengeMsg
	if err := json.Unmarshal(raw, &rd); err != nil {
		return "", errors.New("bad host-ready")
	}
	if rd.Type == "error" {
		return codeOr(rd.Code), nil
	}
	if rd.Type != "host-ready" {
		return "", fmt.Errorf("expected host-ready, got %q", rd.Type)
	}

	sctx, scancel := context.WithCancel(ctx)
	defer scancel()
	c.mu.Lock()
	c.conn = conn
	c.attempt = 0
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		if c.conn == conn {
			c.conn = nil
		}
		c.mu.Unlock()
	}()
	c.Handler.OnStatus(StatusOnline, "")
	c.Handler.OnReady(c, raw)

	go func() {
		t := time.NewTicker(PingInterval)
		defer t.Stop()
		for {
			select {
			case <-sctx.Done():
				return
			case <-t.C:
				pctx, pcancel := context.WithTimeout(sctx, PingTimeout)
				err := conn.Ping(pctx)
				pcancel()
				if err != nil && sctx.Err() == nil {
					c.Logf("signaling: ping failed: %v", err)
					conn.CloseNow()
					return
				}
			}
		}
	}()

	for {
		_, raw, err := conn.Read(sctx)
		if err != nil {
			if ctx.Err() != nil {
				_ = conn.Close(websocket.StatusGoingAway, "shutdown")
			}
			return "", err
		}
		var m struct {
			Type string `json:"type"`
			Code string `json:"code"`
		}
		if err := json.Unmarshal(raw, &m); err != nil || m.Type == "" {
			continue
		}
		// Errors after host-ready are passed to the handler; the connection
		// stays unless the server closes it.
		c.Handler.OnMessage(m.Type, raw)
	}
}

func codeOr(code string) string {
	if code == "" {
		return "server-error"
	}
	if len(code) > 64 {
		code = code[:64]
	}
	return code
}
