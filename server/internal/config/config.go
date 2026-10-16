// Package config loads and validates the server configuration from the
// environment (HR_* variables). Validation is strict: a misconfigured server
// refuses to start rather than running with weakened security.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
)

// TauriOrigins are the only cross-origin callers allowed (bearer auth, no credentials).
var TauriOrigins = []string{"tauri://localhost", "http://tauri.localhost", "https://tauri.localhost"}

// Config is the validated server configuration.
type Config struct {
	Origin         string // e.g. https://heartfulness-remote.dedyn.io (no trailing slash)
	RPID           string // WebAuthn relying party ID (host of Origin by default)
	Listen         string
	DataDir        string
	TurnSecret     string // coturn static-auth-secret; empty only in dev
	TurnHost       string
	TurnPort       int
	TrustedProxies []netip.Prefix
	HostPubAllow   [][]byte // optional allow-list of host keys (32 bytes each); empty = any
	WebDir         string // optional on-disk web client (instead of the embedded copy)
	Dev            bool
}

// Secure reports whether the origin is https (secure cookies, HSTS).
func (c *Config) Secure() bool { return strings.HasPrefix(c.Origin, "https://") }

// CookieName is the session cookie name: __Host- prefixed over https.
func (c *Config) CookieName() string {
	if c.Secure() {
		return "__Host-hr_session"
	}
	return "hr_session"
}

// HostAllowed reports whether a host key may connect: any key when the
// HR_HOST_PUBKEY allow-list is empty, otherwise only listed keys.
func (c *Config) HostAllowed(pub []byte) bool {
	if len(c.HostPubAllow) == 0 {
		return true
	}
	for _, k := range c.HostPubAllow {
		if string(k) == string(pub) {
			return true
		}
	}
	return false
}

// IsTauriOrigin reports whether o is one of the Tauri app origins.
func IsTauriOrigin(o string) bool {
	for _, t := range TauriOrigins {
		if o == t {
			return true
		}
	}
	return false
}

// FromEnv loads the configuration from the process environment.
func FromEnv() (*Config, error) { return Load(os.Getenv) }

// Load builds a Config from getenv and validates it.
func Load(getenv func(string) string) (*Config, error) {
	var errs []error
	c := &Config{
		Listen:  strings.TrimSpace(getenv("HR_LISTEN")),
		DataDir: strings.TrimSpace(getenv("HR_DATA_DIR")),
		WebDir:  strings.TrimSpace(getenv("HR_WEB_DIR")),
	}
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.DataDir == "" {
		c.DataDir = "/data"
	}
	dev, err := parseBool(getenv("HR_DEV"))
	if err != nil {
		errs = append(errs, fmt.Errorf("HR_DEV: %w", err))
	}
	c.Dev = dev

	origin, host, err := parseOrigin(getenv("HR_ORIGIN"))
	if err != nil {
		errs = append(errs, fmt.Errorf("HR_ORIGIN: %w", err))
	}
	c.Origin = origin

	c.RPID = strings.ToLower(strings.TrimSpace(getenv("HR_RP_ID")))
	if c.RPID == "" {
		c.RPID = host
	}
	if host != "" && !rpIDMatches(c.RPID, host) {
		errs = append(errs, fmt.Errorf("HR_RP_ID %q must equal the origin host %q or be a parent domain of it", c.RPID, host))
	}

	c.TurnSecret = getenv("HR_TURN_SECRET")
	switch {
	case c.TurnSecret == "" && !c.Dev:
		errs = append(errs, errors.New("HR_TURN_SECRET is required (set HR_DEV=1 for local development without TURN)"))
	case c.TurnSecret != "" && len(c.TurnSecret) < 16 && !c.Dev:
		errs = append(errs, errors.New("HR_TURN_SECRET is too short (use at least 16 characters, e.g. openssl rand -hex 32)"))
	}

	c.TurnHost = strings.TrimSpace(getenv("HR_TURN_HOST"))
	if c.TurnHost == "" {
		c.TurnHost = c.RPID
	}
	if strings.ContainsAny(c.TurnHost, "/?#@ ") {
		errs = append(errs, fmt.Errorf("HR_TURN_HOST %q must be a bare host name or IP", c.TurnHost))
	}
	c.TurnPort = 3478
	if p := strings.TrimSpace(getenv("HR_TURN_PORT")); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			errs = append(errs, fmt.Errorf("HR_TURN_PORT %q is not a valid port", p))
		} else {
			c.TurnPort = n
		}
	}

	if tp := strings.TrimSpace(getenv("HR_TRUSTED_PROXIES")); tp != "" {
		prefixes, err := ParsePrefixes(tp)
		if err != nil {
			errs = append(errs, fmt.Errorf("HR_TRUSTED_PROXIES: %w", err))
		}
		c.TrustedProxies = prefixes
	}

	if hp := strings.TrimSpace(getenv("HR_HOST_PUBKEY")); hp != "" {
		keys, err := parseHostKeys(hp)
		if err != nil {
			errs = append(errs, fmt.Errorf("HR_HOST_PUBKEY must be a comma-separated list of base64url Ed25519 public keys: %w", err))
		}
		c.HostPubAllow = keys
	}

	if c.WebDir != "" {
		st, err := os.Stat(c.WebDir)
		if err != nil || !st.IsDir() {
			errs = append(errs, fmt.Errorf("HR_WEB_DIR %q is not a directory", c.WebDir))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return c, nil
}

func parseBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "0", "false", "no", "off":
		return false, nil
	case "1", "true", "yes", "on":
		return true, nil
	}
	return false, fmt.Errorf("invalid boolean %q", s)
}

// parseOrigin validates and canonicalizes an origin: lowercase scheme and host,
// default port removed, no path/query/fragment/userinfo. Returns the hostname.
func parseOrigin(raw string) (origin, host string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", errors.New("is required (e.g. https://heartfulness-remote.dedyn.io)")
	}
	u, err := url.Parse(strings.TrimSuffix(raw, "/"))
	if err != nil {
		return "", "", err
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return "", "", fmt.Errorf("%q must be a bare origin like https://example.org", raw)
	}
	scheme := strings.ToLower(u.Scheme)
	host = strings.ToLower(u.Hostname())
	if host == "" {
		return "", "", fmt.Errorf("%q has no host", raw)
	}
	port := u.Port()
	switch scheme {
	case "https":
		if port == "443" {
			port = ""
		}
	case "http":
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return "", "", fmt.Errorf("%q must use https (plain http is only allowed for localhost)", raw)
		}
		if port == "80" {
			port = ""
		}
	default:
		return "", "", fmt.Errorf("%q must start with https://", raw)
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", "", fmt.Errorf("%q has an invalid port", raw)
		}
	}
	hostPort := host
	if strings.Contains(host, ":") {
		hostPort = "[" + host + "]"
	}
	if port != "" {
		hostPort = net.JoinHostPort(host, port)
	}
	return scheme + "://" + hostPort, host, nil
}

// rpIDMatches implements the WebAuthn rule: the RP ID must be the origin's
// effective domain or a registrable suffix of it.
func rpIDMatches(rpID, host string) bool {
	if rpID == host {
		return true
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	return strings.HasSuffix(host, "."+rpID) && strings.Contains(rpID, ".")
}

// parseHostKeys parses a comma (or space) separated list of b64 host keys.
func parseHostKeys(s string) ([][]byte, error) {
	var out [][]byte
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		b, err := proto.UnB64Len(f, proto.PubKeySize)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", f, err)
		}
		out = append(out, b)
	}
	if len(out) == 0 {
		return nil, errors.New("no keys")
	}
	return out, nil
}

// ParsePrefixes parses a comma/space separated list of CIDRs or bare IPs.
func ParsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		if strings.Contains(f, "/") {
			p, err := netip.ParsePrefix(f)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q", f)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("invalid IP %q", f)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}
