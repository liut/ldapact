//go:build !dev

// Package ldapact exposes the embedded static and XML template assets
// (KTD 16, R17). The dev build (tag "dev") swaps these for live directories.
package ldapact

import (
	"embed"
	"io/fs"
)

//go:embed all:static all:templates
var assetsFS embed.FS

// Assets returns the static web assets (css/js/htmx) as an fs.FS.
func Assets() fs.FS {
	sub, err := fs.Sub(assetsFS, "static")
	if err != nil {
		panic("embedded static assets missing: " + err.Error())
	}
	return sub
}

// Templates returns the embedded XML template corpus.
func Templates() fs.FS {
	sub, err := fs.Sub(assetsFS, "templates")
	if err != nil {
		panic("embedded templates missing: " + err.Error())
	}
	return sub
}
