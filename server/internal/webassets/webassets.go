// Package webassets embeds the built web client (web/dist). The repository
// only contains a placeholder index.html; the Docker build copies the real
// web/dist here before compiling.
package webassets

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var embedded embed.FS

// FS returns the embedded web client rooted at dist/.
func FS() fs.FS {
	sub, err := fs.Sub(embedded, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}
