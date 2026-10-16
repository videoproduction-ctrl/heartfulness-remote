package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"sync"

	"github.com/videoproduction-ctrl/heartfulness-remote/agent/internal/core"
	"github.com/videoproduction-ctrl/heartfulness-remote/agent/internal/ipc"
	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
)

// ipcHost implements core.HostIO over the stdin/stdout framing.
type ipcHost struct {
	w      *ipc.Writer
	logger *log.Logger

	mu      sync.Mutex
	nextID  uint64
	pending map[uint64]chan []byte
	closed  bool
}

func newIPCHost(w *ipc.Writer, logger *log.Logger) *ipcHost {
	return &ipcHost{w: w, logger: logger, pending: map[uint64]chan []byte{}}
}

func (h *ipcHost) send(t byte, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	if err := h.w.WriteFrame(t, b); err != nil {
		h.logger.Printf("ipc write: %v", err)
	}
}

type signRequest struct {
	ID   uint64 `json:"id"`
	Data string `json:"data"`
}

type signResult struct {
	ID  uint64 `json:"id"`
	Sig string `json:"sig"`
}

// Sign sends SIGN_REQUEST and waits for the matching SIGN_RESULT. The core
// verifies the signature against hostPub before using it.
func (h *ipcHost) Sign(ctx context.Context, data []byte) ([]byte, error) {
	ch := make(chan []byte, 1)
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, errors.New("ipc closed")
	}
	h.nextID++
	id := h.nextID
	h.pending[id] = ch
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.pending, id)
		h.mu.Unlock()
	}()
	h.send(ipc.TSignRequest, signRequest{ID: id, Data: proto.B64(data)})
	select {
	case sig := <-ch:
		if sig == nil {
			return nil, errors.New("signing refused")
		}
		return sig, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (h *ipcHost) onSignResult(payload []byte) {
	var r signResult
	if json.Unmarshal(payload, &r) != nil {
		return
	}
	sig, err := proto.UnB64(r.Sig)
	if err != nil {
		sig = nil
	}
	h.mu.Lock()
	ch := h.pending[r.ID]
	h.mu.Unlock()
	if ch != nil {
		select {
		case ch <- sig:
		default:
		}
	}
}

func (h *ipcHost) close() {
	h.mu.Lock()
	h.closed = true
	h.mu.Unlock()
}

func (h *ipcHost) EmitState(s core.State)        { h.send(ipc.TState, s) }
func (h *ipcHost) EmitEncoder(c core.EncoderCmd) { h.send(ipc.TEncoder, c) }
func (h *ipcHost) EmitEvent(e core.Event)        { h.send(ipc.TEvent, e) }
func (h *ipcHost) EmitLog(l core.LogResult)      { h.send(ipc.TLog, l) }

func (h *ipcHost) EmitInput(msg json.RawMessage) {
	if err := h.w.WriteFrame(ipc.TInput, msg); err != nil {
		h.logger.Printf("ipc write: %v", err)
	}
}

func (h *ipcHost) EmitAudioCtl(cmd string) {
	h.send(ipc.TAudioCtl, struct {
		Cmd string `json:"cmd"`
	}{cmd})
}

func (h *ipcHost) EmitClipboard(text string) {
	h.send(ipc.TClipboardSet, struct {
		Text string `json:"text"`
	}{text})
}
