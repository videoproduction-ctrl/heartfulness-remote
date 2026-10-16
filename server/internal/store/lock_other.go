//go:build !unix

package store

import "errors"

// ErrLocked means another process (the running server) holds the data dir.
var ErrLocked = errors.New("the data directory is in use by a running server")

// Lock is a no-op on platforms without flock (the server targets Linux).
func Lock(dir string) (release func(), err error) { return func() {}, nil }
