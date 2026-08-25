package web

import (
	"fmt"
	"html/template"
	"io"
)

// Renderer executes named templates, either full pages or HTMX fragments.
// Templates are parsed once at startup and cached for the process lifetime.
type Renderer struct {
	tmpl *template.Template
}

// New wraps a parsed template set.
func New(tmpl *template.Template) *Renderer {
	return &Renderer{tmpl: tmpl}
}

// Fragment executes the named partial for an HTMX swap (missing names and
// execution errors are returned, not panicked).
func (r *Renderer) Fragment(w io.Writer, name string, data any) error {
	if r.tmpl == nil || r.tmpl.Lookup(name) == nil {
		return fmt.Errorf("web: template %q not found", name)
	}
	if err := r.tmpl.ExecuteTemplate(w, name, data); err != nil {
		return fmt.Errorf("web: execute template %q: %w", name, err)
	}
	return nil
}

// Page executes a full page template (same mechanics as Fragment; named for
// readability at call sites).
func (r *Renderer) Page(w io.Writer, name string, data any) error {
	return r.Fragment(w, name, data)
}
