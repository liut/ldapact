//go:build dev

package ldapact

import (
	"io/fs"
	"os"
)

// Assets returns the on-disk static directory for live reload during
// development.
func Assets() fs.FS {
	return os.DirFS("static")
}

// Templates returns the on-disk template directory for live reload during
// development.
func Templates() fs.FS {
	return os.DirFS("templates")
}
