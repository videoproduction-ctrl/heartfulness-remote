// Command genvectors writes testdata/vectors.json: deterministic HR1 test
// vectors that every implementation (Go, TypeScript, Rust) checks against.
//
//	go run ./proto/cmd/genvectors > testdata/vectors.json
package main

import (
	"encoding/json"
	"os"

	"github.com/videoproduction-ctrl/heartfulness-remote/proto"
)

func main() {
	v := proto.Vectors()
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
}
