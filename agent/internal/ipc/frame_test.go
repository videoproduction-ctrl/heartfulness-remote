package ipc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"testing"
	"testing/iotest"
)

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	frames := []Frame{
		{TConfig, []byte(`{"serverURL":"https://x"}`)},
		{TVideo, EncodeVideo(Video{Codec: CodecH264, Keyframe: true, PTS: 123456789, Data: []byte{0, 0, 0, 1, 0x65, 1, 2}})},
		{TAudio, EncodeAudio(42, []byte{0xfc, 1, 2})},
		{TState, nil}, // type-only frame
	}
	for _, f := range frames {
		if err := w.WriteFrame(f.Type, f.Payload); err != nil {
			t.Fatal(err)
		}
	}
	for i, want := range frames {
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if got.Type != want.Type || !bytes.Equal(got.Payload, want.Payload) {
			t.Fatalf("frame %d: got %x/%x want %x/%x", i, got.Type, got.Payload, want.Type, want.Payload)
		}
	}
	if _, err := ReadFrame(&buf); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF at end, got %v", err)
	}
}

func TestVideoAudioPayloads(t *testing.T) {
	v, err := ParseVideo(EncodeVideo(Video{Codec: CodecH265, Keyframe: true, PTS: 1 << 40, Data: []byte("au")}))
	if err != nil || v.Codec != CodecH265 || !v.Keyframe || v.PTS != 1<<40 || string(v.Data) != "au" {
		t.Fatalf("video %+v %v", v, err)
	}
	v, _ = ParseVideo(EncodeVideo(Video{Codec: CodecH264, Data: []byte("x")}))
	if v.Keyframe {
		t.Fatal("keyframe flag")
	}
	if _, err := ParseVideo(make([]byte, 9)); !errors.Is(err, ErrShortPayload) {
		t.Fatal("short video accepted")
	}
	pts, op, err := ParseAudio(EncodeAudio(20000, []byte{1, 2, 3}))
	if err != nil || pts != 20000 || !bytes.Equal(op, []byte{1, 2, 3}) {
		t.Fatal("audio")
	}
	if _, _, err := ParseAudio(make([]byte, 7)); !errors.Is(err, ErrShortPayload) {
		t.Fatal("short audio accepted")
	}
}

func TestOversizeRejected(t *testing.T) {
	var hdr [5]byte
	binary.BigEndian.PutUint32(hdr[:], MaxFrame+1)
	hdr[4] = TVideo
	// The reader must reject from the prefix alone, without reading or
	// allocating the payload.
	r := io.MultiReader(bytes.NewReader(hdr[:]), iotest.ErrReader(errors.New("payload must not be read")))
	if _, err := ReadFrame(r); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("want ErrFrameTooLarge, got %v", err)
	}
	if err := NewWriter(io.Discard).WriteFrame(TVideo, make([]byte, MaxFrame)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("writer accepted oversize frame: %v", err)
	}
	// Exactly MaxFrame (type + payload) is allowed.
	var buf bytes.Buffer
	if err := NewWriter(&buf).WriteFrame(TVideo, make([]byte, MaxFrame-1)); err != nil {
		t.Fatal(err)
	}
	if f, err := ReadFrame(&buf); err != nil || len(f.Payload) != MaxFrame-1 {
		t.Fatalf("max frame: %v", err)
	}
}

func TestEmptyFrame(t *testing.T) {
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 0, 0, 0})); !errors.Is(err, ErrEmptyFrame) {
		t.Fatalf("got %v", err)
	}
}

func TestPartialReads(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	payload := bytes.Repeat([]byte("abcdefgh"), 1000)
	_ = w.WriteFrame(TCommand, payload)
	_ = w.WriteFrame(TSignResult, []byte(`{"id":1}`))
	for name, r := range map[string]io.Reader{
		"one-byte": iotest.OneByteReader(bytes.NewReader(buf.Bytes())),
		"half":     iotest.HalfReader(bytes.NewReader(buf.Bytes())),
		"data-err": iotest.DataErrReader(bytes.NewReader(buf.Bytes())),
	} {
		f, err := ReadFrame(r)
		if err != nil || f.Type != TCommand || !bytes.Equal(f.Payload, payload) {
			t.Fatalf("%s: first frame: %v", name, err)
		}
		f, err = ReadFrame(r)
		if err != nil || f.Type != TSignResult {
			t.Fatalf("%s: second frame: %v", name, err)
		}
	}
	// Stream cut in the middle of a frame.
	cut := buf.Bytes()[:100]
	if _, err := ReadFrame(bytes.NewReader(cut)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated frame: %v", err)
	}
	// Cut inside the length prefix.
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 0})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated prefix: %v", err)
	}
}

func TestConcurrentWritesDoNotInterleave(t *testing.T) {
	var buf bytes.Buffer
	var mu sync.Mutex
	w := NewWriter(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return buf.Write(p)
	}))
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				_ = w.WriteFrame(TInput, bytes.Repeat([]byte{byte(i)}, 300))
			}
		}()
	}
	wg.Wait()
	for n := 0; n < 1000; n++ {
		f, err := ReadFrame(&buf)
		if err != nil || len(f.Payload) != 300 || !bytes.Equal(f.Payload, bytes.Repeat(f.Payload[:1], 300)) {
			t.Fatalf("frame %d corrupted: %v", n, err)
		}
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
