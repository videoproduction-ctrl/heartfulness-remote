// Command heartfulness-server is the Heartfulness Remote signaling server.
//
//	heartfulness-server [serve]        run the server (default)
//	heartfulness-server status         show claim state, host fingerprint and counts (no secrets)
//	heartfulness-server reset --confirm
//	                                   forget the owner, passkeys, host, devices and sessions
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
  status           Show whether the server is claimed, the Mac's key fingerprint
                   and device counts. Prints no secrets.
  reset --confirm  Forget the owner, passkeys, the Mac binding, all devices and
                   sessions. Stop the server first. Use this to recover if the
                   wrong Mac claimed the server or all passkeys are lost.
  healthcheck      Exit 0 if the local server answers /healthz.

Configuration (environment): HR_ORIGIN (required), HR_RP_ID, HR_LISTEN (:8080),
HR_DATA_DIR (/data), HR_TURN_SECRET (required unless HR_DEV=1), HR_TURN_HOST,
HR_TURN_PORT (3478), HR_TRUSTED_PROXIES, HR_HOST_PUBKEY, HR_WEB_DIR, HR_DEV.
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
	if st.Host != nil {
		fp := "(invalid key)"
		if pub, err := proto.UnB64Len(st.Host.Pub, proto.PubKeySize); err == nil {
			fp = proto.Fingerprint(pub)
		}
		fmt.Fprintf(w, "Mac:              %s\n", st.Host.Name)
		fmt.Fprintf(w, "Mac fingerprint:  %s\n", fp)
		fmt.Fprintf(w, "Claimed at:       %s\n", st.Host.ClaimedAt.UTC().Format(time.RFC3339))
	}
	passkeys := 0
	if st.Owner != nil {
		passkeys = len(st.Owner.Passkeys)
	}
	counts := map[string]int{}
	for _, d := range st.Devices {
		counts[d.Status]++
	}
	sessions := 0
	for _, s := range st.Sessions {
		if s.Valid(now) {
			sessions++
		}
	}
	fmt.Fprintf(w, "Passkeys:         %d\n", passkeys)
	fmt.Fprintf(w, "Devices:          %d approved, %d pending, %d revoked\n",
		counts[store.StatusApproved], counts[store.StatusPending], counts[store.StatusRevoked])
	fmt.Fprintf(w, "Active sessions:  %d\n", sessions)
	fmt.Fprintf(w, "Audit events:     %d (kept 7 days)\n", len(st.Events))
	return nil
}

func reset(w io.Writer, args []string) error {
	confirmed := false
	for _, a := range args {
		if a == "--confirm" {
			confirmed = true
		}
	}
	if !confirmed {
		return errors.New("this forgets the owner, passkeys, the Mac and all devices; run again with --confirm")
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
	fmt.Fprintln(w, "Reset complete. Start the server; the Mac will show a new setup QR code.")
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
