package core

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNormalizeInput(t *testing.T) {
	ok := []struct {
		in      string
		pointer bool
		want    string
		release bool
	}{
		{`{"t":"m","x":0.5,"y":0.25}`, true, `{"t":"m","x":0.5,"y":0.25,"display":7}`, false},
		{`{"t":"m","x":-3,"y":9}`, true, `{"t":"m","x":0,"y":1,"display":7}`, false},
		{`{"t":"b","b":0,"d":true,"x":0.1,"y":0.2}`, false, `{"t":"b","b":0,"d":true,"x":0.1,"y":0.2,"display":7}`, false},
		{`{"t":"b","b":2,"d":false,"x":0.1,"y":0.2}`, false, `{"t":"b","b":2,"d":false,"x":0.1,"y":0.2,"display":7}`, true},
		{`{"t":"w","dx":1e9,"dy":-3,"x":0.5,"y":0.5}`, false, `{"t":"w","dx":10000,"dy":-3,"x":0.5,"y":0.5,"display":7}`, false},
		{`{"t":"k","c":"KeyA","d":true,"extra":"dropped"}`, false, `{"t":"k","c":"KeyA","d":true,"display":7}`, false},
		{`{"t":"k","c":"ShiftLeft","d":false}`, false, `{"t":"k","c":"ShiftLeft","d":false,"display":7}`, true},
		{`{"t":"txt","s":"héllo 👋"}`, false, `{"t":"txt","s":"héllo 👋","display":7}`, false},
		{`{"t":"reset"}`, false, `{"t":"reset","display":7}`, true},
	}
	for _, c := range ok {
		out, rel, good := normalizeInput([]byte(c.in), c.pointer, 7)
		if !good || string(out) != c.want || rel != c.release {
			t.Errorf("%s → %s (%v, rel %v)", c.in, out, good, rel)
		}
	}
	bad := []struct {
		in      string
		pointer bool
	}{
		{`{"t":"m","x":0.5,"y":0.5}`, false}, // move on input channel
		{`{"t":"k","c":"KeyA","d":true}`, true},
		{`{"t":"m","x":"a","y":0}`, true},
		{`{"t":"m","y":0}`, true},
		{`{"t":"b","b":5,"d":true,"x":0,"y":0}`, false},
		{`{"t":"b","b":-1,"d":true,"x":0,"y":0}`, false},
		{`{"t":"b","b":0,"x":0,"y":0}`, false},
		{`{"t":"b","b":1.5,"d":true,"x":0,"y":0}`, false},
		{`{"t":"k","c":"Key A","d":true}`, false},
		{`{"t":"k","c":"","d":true}`, false},
		{`{"t":"k","c":"KeyA"}`, false},
		{`{"t":"txt","s":""}`, false},
		{`{"t":"txt"}`, false},
		{`{"t":"exec","cmd":"rm -rf /"}`, false},
		{`not json`, false},
		{``, false},
	}
	for _, c := range bad {
		if out, _, good := normalizeInput([]byte(c.in), c.pointer, 7); good {
			t.Errorf("accepted %s → %s", c.in, out)
		}
	}
	// txt limit: 4096 characters (not bytes).
	okTxt, _ := json.Marshal(map[string]string{"t": "txt", "s": strings.Repeat("é", MaxTextChars)})
	if _, _, good := normalizeInput(okTxt, false, 1); !good {
		t.Error("4096-char text rejected")
	}
	long, _ := json.Marshal(map[string]string{"t": "txt", "s": strings.Repeat("a", MaxTextChars+1)})
	if _, _, good := normalizeInput(long, false, 1); good {
		t.Error("txt > 4096 accepted")
	}
	if _, _, good := normalizeInput([]byte(`{"t":"txt","s":"`+strings.Repeat("a", MaxInputMessage)+`"}`), false, 1); good {
		t.Error("oversize message accepted")
	}
}

func TestTokenBucket(t *testing.T) {
	b := newTokenBucket(10, 5)
	now := time.Now()
	n := 0
	for range 100 {
		if b.allow(now) {
			n++
		}
	}
	if n != 5 {
		t.Fatalf("burst %d", n)
	}
	if !b.allow(now.Add(150 * time.Millisecond)) {
		t.Fatal("refill")
	}
}
