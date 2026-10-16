// Command heartfulness-server is the Heartfulness Remote signaling server.
//
//	heartfulness-server [serve]        run the server (default)
//	heartfulness-server status         show claim state, the Macs (ID, fingerprint, key) and counts (no secrets)
//	heartfulness-server reset --confirm
//	                                   forget the owner, passkeys, Macs, devices and sessions
//	heartfulness-server healthcheck    exit 0 if the local server answers /healthz
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
	"github.com/videoproduction-ctrl/heartfulness-remote/server/internal/config"
	"github.com/videoproduction-ctrl/heartfulness-remote/server/internal/server"
	"github.com/videoproduction-ctrl/heartfulness-remote/server/internal/store"
	"github.com/videoproduction-ctrl/heartfulness-remote/server/internal/webassets"
)

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve()
	case "status":
		err = status(os.Stdout)
	case "reset":
		err = reset(os.Stdout, args)
	case "healthcheck":
		err = healthcheck()
	case "-h", "--help", "help":
		usage(os.Stdout)
		return
	default:
		usage(os.Stderr)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `Usage: heartfulness-server [command]

Commands:
  serve            Run the server (default).
  status           Show whether the server is claimed, its Macs (Mac ID, key
                   fingerprint, host key) and device counts. Prints no secrets.
  reset --confirm  Forget the owner, passkeys, all Macs, all devices and
                   sessions. Stop the server first. Use this to recover if the
                   wrong Mac claimed the server or all passkeys are lost.
  healthcheck      Exit 0 if the local server answers /healthz.

Configuration (environment): HR_ORIGIN (required), HR_RP_ID, HR_LISTEN (:8080),
HR_DATA_DIR (/data), HR_TURN_SECRET (required unless HR_DEV=1), HR_TURN_HOST,
HR_TURN_PORT (3478), HR_TRUSTED_PROXIES, HR_HOST_PUBKEY (comma-separated
allow-list of Mac host keys; empty = any), HR_WEB_DIR, HR_DEV.
`)
}

func serve() error {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := config.FromEnv()
	if err != nil {
		return fmt.Errorf("configuration:\n%w", err)
	}
	release, err := store.Lock(cfg.DataDir)
	if err != nil {
		return err
	}
	defer release()
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	srv, err := server.New(cfg, st, server.Options{Logger: log, WebFS: webassets.FS()})
	if err != nil {
		return err
	}
	if cfg.Dev {
		log.Warn("development mode (HR_DEV=1)")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return srv.Run(ctx)
}

func dataDir() string {
	if d := strings.TrimSpace(os.Getenv("HR_DATA_DIR")); d != "" {
		return d
	}
	return "/data"
}

func status(w io.Writer) error {
	dir := dataDir()
	st, err := store.ReadFile(dir + "/state.json")
	if err != nil {
		return err
	}
	now := time.Now()
	yes := map[bool]string{true: "yes", false: "no"}
	fmt.Fprintf(w, "Claimed:          %s\n", yes[st.Claimed()])
	fmt.Fprintf(w, "Macs:             %d (at most %d)\n", len(st.Hosts), store.MaxHosts)
	for i, h := range st.Hosts {
		fp, macID := "(invalid key)", h.MacID
		if pub, err := proto.UnB64Len(h.Pub, proto.PubKeySize); err == nil {
			fp, macID = proto.Fingerprint(pub), proto.MacID(pub)
		}
		fmt.Fprintf(w, "Mac %d:            %s\n", i+1, h.Name)
		fmt.Fprintf(w, "  Mac ID:         %s\n", proto.FormatMacID(macID))
		fmt.Fprintf(w, "  Fingerprint:    %s\n", fp)
		fmt.Fprintf(w, "  Host key:       %s   (for HR_HOST_PUBKEY)\n", h.Pub)
		fmt.Fprintf(w, "  Added:          %s\n", h.ClaimedAt.UTC().Format(time.RFC3339))
	}
	passkeys := 0
	if st.Owner != nil {
		passkeys = len(st.Owner.Passkeys)
	}
	counts := map[string]int{}
	for pub, d := range st.Devices {
		switch {
		case st.ApprovedOnAny(pub):
			counts[store.StatusApproved]++
		case hasStatus(d, store.StatusPending):
			counts[store.StatusPending]++
		default:
			counts[store.StatusRevoked]++
		}
	}
	sessions := 0
	for _, s := range st.Sessions {
		if s.Valid(now) {
			sessions++
		}
	}
	fmt.Fprintf(w, "Passkeys:         %d\n", passkeys)
	fmt.Fprintf(w, "Devices:          %d approved on a Mac, %d pending, %d revoked\n",
		counts[store.StatusApproved], counts[store.StatusPending], counts[store.StatusRevoked])
	fmt.Fprintf(w, "Active sessions:  %d\n", sessions)
	fmt.Fprintf(w, "Audit events:     %d (kept 7 days)\n", len(st.Events))
	return nil
}

func hasStatus(d *store.Device, status string) bool {
	for _, a := range d.Approvals {
		if a.Status == status {
			return true
		}
	}
	return false
}

func reset(w io.Writer, args []string) error {
	confirmed := false
	for _, a := range args {
		if a == "--confirm" {
			confirmed = true
		}
	}
	if !confirmed {
		return errors.New("this forgets the owner, passkeys, all Macs and all devices; run again with --confirm")
	}
	dir := dataDir()
	release, err := store.Lock(dir)
	if errors.Is(err, store.ErrLocked) {
		return errors.New("the server is running; stop it first (docker compose stop server), then run reset again")
	}
	if err != nil {
		return err
	}
	defer release()
	st, err := store.ReadFile(dir + "/state.json")
	if err != nil {
		return err
	}
	st.Reset(time.Now())
	if err := store.WriteFile(dir, st); err != nil {
		return err
	}
	fmt.Fprintln(w, "Reset complete. Start the server; each Mac will show a new setup QR code. Set up one Mac, then add the others.")
	return nil
}

func healthcheck() error {
	addr := os.Getenv("HR_LISTEN")
	if addr == "" {
		addr = ":8080"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz returned %d", resp.StatusCode)
	}
	return nil
}
