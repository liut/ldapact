package web

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestParseAllTemplates(t *testing.T) {
	tmpl, err := Parse(nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, name := range []string{"layout.html", "tree-row.html", "status-region.html", "error-box.html"} {
		if tmpl.Lookup(name) == nil {
			t.Errorf("template %q missing", name)
		}
	}
}

func TestMustParsePanicsWithTemplateName(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("want panic")
		}
		msg, ok := r.(string)
		if !ok || !strings.Contains(msg, "parse HTML templates") {
			t.Errorf("panic = %v", r)
		}
	}()
	badFS := fstest.MapFS{
		"templates/broken.html": &fstest.MapFile{Data: []byte("{{define \"x\"}}unclosed")},
	}
	mustParseFS(badFS, nil)
}
