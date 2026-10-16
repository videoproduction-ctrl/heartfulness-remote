// Command hr-agent is the host networking helper bundled inside
// "Heartfulness Remote.app". The Swift app launches it and talks to it only
// over stdin/stdout using the framing of PROTOCOL.md §9. The agent never
// opens a listening TCP socket; it dials the signaling server and runs
// WebRTC (pion). Diagnostics go to stderr and never contain secrets.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/videoproduction-ctrl/heartfulness-remote/agent/internal/core"
	"github.com/videoproduction-ctrl/heartfulness-remote/agent/internal/ipc"
)

func main() {
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Fprintln(os.Stderr, "hr-agent", core.Version)
		return
	}
	// stdout is the IPC channel: keep the real file for frames and point
	// os.Stdout at stderr so no library can ever corrupt the stream.
	ipcOut := os.Stdout
	os.Stdout = os.Stderr
	logger := log.New(os.Stderr, "hr-agent: ", log.LstdFlags|log.Lmsgprefix)
	log.SetOutput(os.Stderr)

	code := run(os.Stdin, ipcOut, logger)
	os.Exit(code)
}

func run(stdin io.Reader, stdout io.Writer, logger *log.Logger) int {
	in := bufio.NewReaderSize(stdin, 1<<20)
	host := newIPCHost(ipc.NewWriter(stdout), logger)

	// The first frame must be CONFIG.
	f, err := ipc.ReadFrame(in)
	if err != nil {
		logger.Printf("waiting for CONFIG: %v", err)
		return 2
	}
	if f.Type != ipc.TConfig {
		logger.Printf("first frame must be CONFIG (got 0x%02x)", f.Type)
		return 2
	}
	var cfg core.Config
	if err := json.Unmarshal(f.Payload, &cfg); err != nil {
		logger.Printf("CONFIG: malformed JSON")
		return 2
	}
	agent := core.New(host, core.Options{
		Logf:          logger.Printf,
		AllowInsecure: os.Getenv("HR_ALLOW_INSECURE") == "1",
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := agent.Start(ctx, cfg); err != nil {
		logger.Printf("start: %v", err)
		return 2
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		agent.Stop()
	}()

	go func() {
		for {
			f, err := ipc.ReadFrame(in)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					logger.Printf("ipc: %v", err)
				}
				// The app went away (or the stream is corrupt): stop.
				agent.Stop()
				return
			}
			dispatch(agent, host, f, logger)
		}
	}()
	<-agent.Done()
	host.close()
	return 0
}

func dispatch(agent *core.Agent, host *ipcHost, f ipc.Frame, logger *log.Logger) {
	switch f.Type {
	case ipc.TVideo:
		v, err := ipc.ParseVideo(f.Payload)
		if err == nil {
			agent.OnVideo(core.Codec(v.Codec), v.Keyframe, v.PTS, v.Data)
		}
	case ipc.TAudio:
		pts, opus, err := ipc.ParseAudio(f.Payload)
		if err == nil {
			agent.OnAudio(pts, opus)
		}
	case ipc.TSignResult:
		host.onSignResult(f.Payload)
	case ipc.TCommand:
		agent.OnCommand(f.Payload)
	case ipc.TConfig:
		var cfg core.Config
		if json.Unmarshal(f.Payload, &cfg) == nil {
			agent.OnConfig(cfg)
		}
	default:
		logger.Printf("ipc: unknown frame type 0x%02x ignored", f.Type)
	}
}
