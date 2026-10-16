package config

import (
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func base() map[string]string {
	return map[string]string{
		"HR_ORIGIN":      "https://heartfulness-remote.dedyn.io",
		"HR_TURN_SECRET": "0123456789abcdef0123456789abcdef",
	}
}

func TestDefaults(t *testing.T) {
	c, err := Load(env(base()))
	if err != nil {
		t.Fatal(err)
	}
	if c.Origin != "https://heartfulness-remote.dedyn.io" || c.RPID != "heartfulness-remote.dedyn.io" {
		t.Fatalf("origin/rpid: %q %q", c.Origin, c.RPID)
	}
	if c.Listen != ":8080" || c.DataDir != "/data" || c.TurnHost != c.RPID || c.TurnPort != 3478 {
		t.Fatalf("defaults: %+v", c)
	}
	if !c.Secure() || c.CookieName() != "__Host-hr_session" || c.Dev {
		t.Fatal("https origin must use secure __Host- cookie")
	}
}

func TestOriginValidation(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"https://Example.ORG/", "https://example.org", true},
		{"https://example.org:443", "https://example.org", true},
		{"https://example.org:8443", "https://example.org:8443", true},
		{"http://localhost:8080", "http://localhost:8080", true},
		{"http://127.0.0.1:9000", "http://127.0.0.1:9000", true},
		{"http://example.org", "", false},
		{"https://example.org/app", "", false},
		{"https://example.org?x=1", "", false},
		{"https://user@example.org", "", false},
		{"ftp://example.org", "", false},
		{"example.org", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		m := base()
		m["HR_ORIGIN"] = tc.in
		c, err := Load(env(m))
		if tc.ok != (err == nil) {
			t.Errorf("%q: ok=%v err=%v", tc.in, tc.ok, err)
			continue
		}
		if tc.ok && c.Origin != tc.want {
			t.Errorf("%q: got %q want %q", tc.in, c.Origin, tc.want)
		}
	}
}

func TestDevLocalhost(t *testing.T) {
	c, err := Load(env(map[string]string{"HR_ORIGIN": "http://localhost:8080", "HR_DEV": "1"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Secure() || c.CookieName() != "hr_session" || !c.Dev || c.TurnSecret != "" {
		t.Fatalf("dev config: %+v", c)
	}
}

func TestTurnSecretRequired(t *testing.T) {
	m := base()
	delete(m, "HR_TURN_SECRET")
	if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "HR_TURN_SECRET") {
		t.Fatalf("missing secret accepted: %v", err)
	}
	m["HR_TURN_SECRET"] = "short"
	if _, err := Load(env(m)); err == nil {
		t.Fatal("short secret accepted")
	}
	m["HR_DEV"] = "yes"
	if _, err := Load(env(m)); err != nil {
		t.Fatalf("dev mode should relax the TURN secret: %v", err)
	}
	m["HR_DEV"] = "maybe"
	if _, err := Load(env(m)); err == nil {
		t.Fatal("invalid HR_DEV accepted")
	}
}

func TestRPID(t *testing.T) {
	m := base()
	m["HR_ORIGIN"] = "https://remote.example.org"
	m["HR_RP_ID"] = "example.org"
	if c, err := Load(env(m)); err != nil || c.RPID != "example.org" || c.TurnHost != "example.org" {
		t.Fatalf("parent RP ID rejected: %v", err)
	}
	m["HR_RP_ID"] = "evil.org"
	if _, err := Load(env(m)); err == nil {
		t.Fatal("unrelated RP ID accepted")
	}
	m["HR_RP_ID"] = "org"
	if _, err := Load(env(m)); err == nil {
		t.Fatal("TLD RP ID accepted")
	}
}

func TestTrustedProxiesAndPins(t *testing.T) {
	m := base()
	m["HR_TRUSTED_PROXIES"] = "172.30.77.0/24, 10.0.0.1 fd00::/8"
	m["HR_HOST_PUBKEY"] = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	m["HR_TURN_PORT"] = "3479"
	m["HR_TURN_HOST"] = "turn.example.org"
	c, err := Load(env(m))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.TrustedProxies) != 3 || c.TrustedProxies[1].Bits() != 32 || len(c.HostPubAllow) != 1 || len(c.HostPubAllow[0]) != 32 || c.TurnPort != 3479 || c.TurnHost != "turn.example.org" {
		t.Fatalf("parsed: %+v", c)
	}
	if !c.HostAllowed(c.HostPubAllow[0]) || c.HostAllowed(make([]byte, 32)) {
		t.Fatal("single-key allow-list")
	}
	// HR_HOST_PUBKEY is a comma-separated allow-list (PROTOCOL.md §10.2).
	m["HR_HOST_PUBKEY"] = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if c, err = Load(env(m)); err != nil || len(c.HostPubAllow) != 2 || !c.HostAllowed(make([]byte, 32)) {
		t.Fatalf("allow-list: %v %+v", err, c)
	}
	m["HR_HOST_PUBKEY"] = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo,AAAA"
	if _, err := Load(env(m)); err == nil {
		t.Fatal("allow-list with an invalid key accepted")
	}
	m["HR_HOST_PUBKEY"] = ""
	if c, err = Load(env(m)); err != nil || len(c.HostPubAllow) != 0 || !c.HostAllowed(make([]byte, 32)) {
		t.Fatalf("empty allow-list must allow any key: %v", err)
	}
	for k, v := range map[string]string{
		"HR_TRUSTED_PROXIES": "not-an-ip",
		"HR_HOST_PUBKEY":     "AAAA",
		"HR_TURN_PORT":       "70000",
		"HR_TURN_HOST":       "turn.example.org/x",
		"HR_WEB_DIR":         "/definitely/not/here",
	} {
		mm := base()
		mm[k] = v
		if _, err := Load(env(mm)); err == nil {
			t.Errorf("%s=%q accepted", k, v)
		}
	}
}

func TestTauriOrigins(t *testing.T) {
	for _, o := range []string{"tauri://localhost", "http://tauri.localhost", "https://tauri.localhost"} {
		if !IsTauriOrigin(o) {
			t.Fatal(o)
		}
	}
	if IsTauriOrigin("https://tauri.localhost.evil.org") || IsTauriOrigin("") {
		t.Fatal("non-Tauri origin accepted")
	}
}
