// Package web provides the Go-side HTML rendering surface (R17): named
// html/template files parsed from an embedded FS, a FuncMap registry, and
// partial render helpers for HTMX swaps. The XML template engine lives in
// pkg/tplengine (U6) and is deliberately separate.
package web

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
)

//go:embed templates
var templatesFS embed.FS

// MustParse parses all HTML templates and panics with the failing template
// name on error (startup contract: a parse failure must abort loudly).
func MustParse(funcs template.FuncMap) *template.Template {
	return mustParseFS(templatesFS, funcs)
}

func mustParseFS(fsys fs.FS, funcs template.FuncMap) *template.Template {
	t, err := parseFS(fsys, funcs)
	if err != nil {
		panic(fmt.Sprintf("web: parse HTML templates: %v", err))
	}
	return t
}

// Parse parses all *.html templates under pkg/web/templates. extra merges
// additional FuncMap entries (U6 registers its macro registry here).
func Parse(extra template.FuncMap) (*template.Template, error) {
	return parseFS(templatesFS, extra)
}

func parseFS(fsys fs.FS, extra template.FuncMap) (*template.Template, error) {
	t := template.New("root").Funcs(FuncMap())
	if len(extra) > 0 {
		t = t.Funcs(extra)
	}
	return t.ParseFS(fsys, "templates/*.html")
}
