//go:build !unix

package files

import "os"

func openNoFollow(p string) (*os.File, error) { return os.Open(p) }

func freeBytes(string) (uint64, bool) { return 0, false }
