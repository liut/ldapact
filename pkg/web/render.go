package web

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
)

// layoutData is injected into layout.html: Body holds the already-escaped
// output of a content template.
type layoutData struct {
	Title string
	Body  template.HTML
}

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

// Page renders a full page: it executes the named content template into a
// buffer, then wraps it in layout.html. Wrapping after escaping avoids
// double-escaping while keeping the shell DRY.
func (r *Renderer) Page(w io.Writer, title, contentName string, data any) error {
	var buf bytes.Buffer
	if err := r.Fragment(&buf, contentName, data); err != nil {
		return err
	}
	return r.tmpl.ExecuteTemplate(w, "layout.html", layoutData{
		Title: title,
		Body:  template.HTML(buf.String()),
	})
}
